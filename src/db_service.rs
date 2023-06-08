pub use crate::db::NewDatabase;
pub use crate::db_content::{AllTags, Entry, EntryType, FieldDataType, Group};
pub use crate::error;
pub use crate::error::{Error, Result};
pub use crate::form_data::*;
pub use crate::password_generator::{AnalyzedPassword, PasswordGenerationOptions, PasswordScore};
pub use crate::util::string_to_simple_hash;

use crate::db::{self, write_kdbx_file, write_kdbx_file_with_backup_file, KdbxFile};
use crate::db_content::{standard_types_ordered_by_id, AttachmentHashValue, KeepassFile};
use crate::password_generator;
use crate::searcher;
use crate::util;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::File;
use std::io::{BufReader, Read, Seek, Write, Cursor};
use std::path::Path;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use chrono::NaiveDateTime;
use log::{debug, info};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug)]
pub enum SaveStatus {
    Success,
    Failed(String),
    Message(String),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SaveAllResponse {
    pub db_key: String,
    pub save_status: SaveStatus,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KdbxContextStatus {
    pub last_read_time: NaiveDateTime,
    pub last_write_time: NaiveDateTime,
    pub save_pending: bool,
}

pub fn kdbx_context_statuses(db_key: &str) -> Result<KdbxContextStatus> {
    call_kdbx_context_action(db_key, |ctx: &KdbxContext| {
        Ok(KdbxContextStatus {
            last_read_time: ctx.last_read_time.clone(),
            last_write_time: ctx.last_write_time.clone(),
            save_pending: ctx.save_pending,
        })
    })
}

pub struct KdbxContext {
    pub(crate) kdbx_file: KdbxFile,
    /// The time of the most recent reading of the database
    pub(crate) last_read_time: NaiveDateTime, // Need to use NaiveDateTime::signed_duration_since to get duration from this
    ///  The time of the most recent writing to the database
    pub(crate) last_write_time: NaiveDateTime,
    pub(crate) save_pending: bool,
}

// Need to implement Default explicitly as there is no default support in NaiveDateTime
impl Default for KdbxContext {
    fn default() -> Self {
        Self {
            kdbx_file: KdbxFile::default(),
            last_read_time: util::now_utc(),
            last_write_time: util::now_utc(),
            save_pending: false,
        }
    }
}

// Here we're using an Arc to share memory among threads, and the data - HashMap<String, KdbxContext> - inside
// the Arc is protected with a mutex.
type MainStore = Arc<Mutex<HashMap<String, KdbxContext>>>;

fn main_store() -> &'static MainStore {
    static MAIN_STORE: Lazy<MainStore> = Lazy::new(Default::default);
    &MAIN_STORE
}

/// A macro to do a db query and then update the last read time for tracking
macro_rules! main_content_action {
    ($db_key:expr,$closure_fn:expr) => {{
        let r = call_main_content_action($db_key, $closure_fn);
        // Update the read time
        call_kdbx_context_mut_action($db_key, |ctx: &mut KdbxContext| {
            ctx.last_read_time = util::now_utc();
            Ok(())
        })?;
        r
    }};
    ($db_key:expr,$closure_fn:expr ,no_times) => {
        // No read time update is done when the caller passes 'no_times' at the end
        call_main_content_action($db_key, $closure_fn)
    };
}

/// A macro to call a db modification and then update the last write time for tracking  
macro_rules! main_content_mut_action {
    ($db_key:expr,$closure_fn:expr) => {{
        let r = call_main_content_mut_action($db_key, $closure_fn);
        // Update the write time
        call_kdbx_context_mut_action($db_key, |ctx: &mut KdbxContext| {
            ctx.last_write_time = util::now_utc();
            ctx.save_pending = true;
            Ok(())
        })?;
        r
    }};
    ($db_key:expr,$closure_fn:expr, no_times) => {
        // No write time update is done when the caller passes 'no_times' at the end
        call_main_content_mut_action($db_key, $closure_fn)
    };
}

/// A macro to call a db reading and then update the last read time for tracking
macro_rules! kdbx_context_action {
    ($db_key:expr,$closure_fn:expr) => {{
        let r = call_kdbx_context_action($db_key, $closure_fn);
        // Update the read time
        call_kdbx_context_mut_action($db_key, |ctx: &mut KdbxContext| {
            ctx.last_read_time = util::now_utc();
            Ok(())
        })?;
        r
    }};
    ($db_key:expr,$closure_fn:expr ,no_times) => {
        // No read time update is done when the caller passes 'no_times' at the end
        call_kdbx_context_action($db_key, $closure_fn)
    };
}

macro_rules! kdbx_context_mut_action {
    ($db_key:expr,$closure_fn:expr) => {{
        let r = call_kdbx_context_mut_action($db_key, $closure_fn);
        // Update the write time
        call_kdbx_context_mut_action($db_key, |ctx: &mut KdbxContext| {
            ctx.last_write_time = util::now_utc();
            ctx.save_pending = true;
            Ok(())
        })?;
        r
    }};
    ($db_key:expr,$closure_fn:expr ,no_times) => {
        // No read time update is done when the caller passes 'no_times' at the end
        call_kdbx_context_action($db_key, $closure_fn)
    };
}

// Calls the action closure with the complete context for a specific db
fn call_kdbx_context_action<T, F>(db_key: &str, action: F) -> Result<T>
where
    F: Fn(&KdbxContext) -> Result<T>,
{
    let store = main_store().lock().unwrap();
    // Gets the stored KdbxContext for the key "db_key"
    match store.get(db_key) {
        Some(kdbx_context) => action(kdbx_context),
        None => Err(Error::DbKeyNotFound),
    }
}

// Calls the mut action closure with the complete context for a specific db
fn call_kdbx_context_mut_action<T, F>(db_key: &str, mut action: F) -> Result<T>
where
    F: FnMut(&mut KdbxContext) -> Result<T>,
{
    let mut store = main_store().lock().unwrap();
    //Gets the stored KdbxContext for the key "db_key"
    match store.get_mut(db_key) {
        Some(kdbx_context) => action(kdbx_context),
        None => Err(Error::DbKeyNotFound),
    }
}

// Calls the action closure with the db content for a specific db
fn call_main_content_action<T, F>(db_key: &str, action: F) -> Result<T>
where
    F: Fn(&KeepassFile) -> Result<T>,
{
    let store = main_store().lock().unwrap();
    // First we need to get the context and then get the stored KdbxFile for the key "db_key"
    match store.get(db_key) {
        Some(kdbx_context) => match &kdbx_context.kdbx_file.keepass_main_content {
            // Call the closure with the keepassFile content.
            // We cannot return ref to Entry or Group or Meta from the action.
            // This is because the return ref cannot outlive the borrowed ref (store -> kbdx_file -> k)
            // The borrowed ref 'store' will be dropped at the end of this
            // So we need to clone if we want to return the content to the caller
            Some(k) => action(&k),
            None => Err(error::Error::NotFound(
                "Keepass main content in not found".into(),
            )),
        },
        None => Err(error::Error::DbKeyNotFound),
    }
}

// Calls the mut action closure with the db content for a specific db
fn call_main_content_mut_action<T, F>(db_key: &str, action: F) -> Result<T>
where
    F: Fn(&mut KeepassFile) -> Result<T>,
{
    let mut store = main_store().lock().unwrap();
    // First we need to get the mut context and then get the stored mut KdbxFile for the key "db_key"
    match store.get_mut(db_key) {
        Some(kdbx_context) => match &mut kdbx_context.kdbx_file.keepass_main_content {
            // Call the closure with the keepassFile content.
            // We cannot return ref to Entry or Group or Meta from the action.
            // This is because the return ref cannot outlive the borrowed ref (store -> kbdx_file -> k)
            // The borrowed ref 'store' will be dropped at the end of this
            // So we need to clone if we want to return the content to the caller
            Some(k) => action(k),
            None => Err(Error::NotFound("Keepass main content in not found".into())),
        },
        None => Err(Error::DbKeyNotFound),
    }
}

/// Opens and reads a valid KDBX file.
/// Returns KdbxLoaded with db key which is required to access such loaded db content from the cache
pub fn load_kdbx(
    db_file_name: &str,
    password: &str,
    key_file_name: Option<&str>,
) -> Result<KdbxLoaded> {
    let mut db_file_reader = db::open_db_file(db_file_name)?;
    read_kdbx(&mut db_file_reader, db_file_name, password, key_file_name)
}

// Gets a ref to the main keepass content
macro_rules! to_keepassfile {
    ($kdbx_file:expr) => {
        // Need to get Option<&KeepassFile> from Option<KeepassFile> using as_ref
        $kdbx_file
            .keepass_main_content
            .as_ref()
            .ok_or("No main content")?
    };
}

// Used for both desktop and mobile
// db_file_name is full uri and used as db_key in all subsequent calls
pub fn read_kdbx<R: Read + Seek>(
    reader: &mut R,
    db_file_name: &str,
    password: &str,
    key_file_name: Option<&str>,
) -> Result<KdbxLoaded> {
    let kdbx_file = db::read_db_from_reader(reader, db_file_name, password, key_file_name)?;

    let kp = to_keepassfile!(kdbx_file);

    let kdbx_loaded = KdbxLoaded {
        db_key: db_file_name.into(),
        database_name: kp.meta.database_name.clone(),
    };

    let mut kdbx_context = KdbxContext::default();
    kdbx_context.kdbx_file = kdbx_file;

    // Arc<T> automatically dereferences to T (via the Deref trait),
    // so you can call T’s methods on a value of type Arc<T>
    let mut store = main_store().lock().unwrap();
    // Each database has a unique uri (File Path) and accordingly only one db with that name can be opened at a time
    // The 'db_file_name' is the full uri and used as a unique db_key throughout all db specific calls
    store.insert(db_file_name.into(), kdbx_context);
    info!("Reading KDBX file {} is completed", db_file_name);
    Ok(kdbx_loaded)
}

pub fn all_kdbx_cache_keys() -> Result<Vec<String>> {
    let store = main_store().lock().unwrap();
    let mut vec = vec![];
    for k in store.keys() {
        vec.push(k.clone());
    }
    Ok(vec)
}

// TODO: Refactor create_kdbx (used mainly for desktop app) and create_and_write_to_writer to use common functionalties
/// Called to create a new KDBX database and perists the file
/// Returns KdbxLoaded with dbkey to locate this KDBX database in cache
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows",))]
pub fn create_kdbx(new_db: NewDatabase) -> Result<KdbxLoaded> {
    if let Some(kf) = &new_db.key_file_name {
        if !kf.trim().is_empty() & !Path::new(kf).exists() {
            return Err(Error::NotFound(format!(
                "The key file {} is not valid one",
                kf
            )));
        }
    }
    let kdbx_file = new_db.create()?;
    let kp = to_keepassfile!(kdbx_file);
    let kdbx_loaded = KdbxLoaded {
        db_key: new_db.database_file_name.clone(),
        database_name: kp.meta.database_name.clone(),
    };

    // IMPORTANT:
    // We need to call the following inserting of db to the shared cache in a {} block
    // so that the Mutex guard is unlocked when this block's scope ends and the save_kdbx_with_backup fn
    // can be called.
    // If this is not done, save_kdbx_with_backup will deadlock the thread as it will be waiting for
    // the same main_store lock to be released
    {
        // Add the newly created db to cache for UI use
        let mut kdbx_context = KdbxContext::default();
        kdbx_context.kdbx_file = kdbx_file;

        let mut store = main_store().lock().unwrap();
        store.insert(new_db.database_file_name.clone(), kdbx_context);
    }
    // Mutex guard is now released

    // Save the newly created db to the file system for persistence
    // See above block comment. The drop(main_store()) is not working; Also there is no method 'unlock' in Mutex yet;
    save_kdbx_with_backup(&new_db.database_file_name, None, true)?;
    Ok(kdbx_loaded)
}

// Mobile
/// Creates a new db and writes into the supplied writer as kdbx db
pub fn create_and_write_to_writer<W: Read + Write + Seek>(
    writer: &mut W,
    new_db: NewDatabase,
) -> Result<KdbxLoaded> {
    if let Some(kf) = &new_db.key_file_name {
        if !kf.trim().is_empty() & !Path::new(kf).exists() {
            return Err(Error::NotFound(format!(
                "The key file {} is not valid one",
                kf
            )));
        }
    }
    let kdbx_file = new_db.create()?;
    let kp = to_keepassfile!(kdbx_file);
    let kdbx_loaded = KdbxLoaded {
        db_key: new_db.database_file_name.clone(),
        database_name: kp.meta.database_name.clone(),
    };

    // IMPORTANT:
    // We need to call the following inserting of db to the shared cache in {} block
    // so that the Mutex guard is unlocked so that outside this block, the save_kdbx fn
    // can be called. If this is not done, save_kdbx will deadlock the thread as it will be waiting for
    // main_store lock to be released
    {
        // Add the newly created db to cache for UI use
        let mut kdbx_context = KdbxContext::default();
        kdbx_context.kdbx_file = kdbx_file;

        let mut store = main_store().lock().unwrap();
        store.insert(new_db.database_file_name.clone(), kdbx_context);
    }
    let mut buf = Cursor::new(Vec::<u8>::new());
    // Mutex guard is now released
    // Save the newly created db to the file system for persistence
    // See above block comment. The drop(main_store()) is not working;Also there is no method 'unclock' in Mutex yet;
    save_kdbx_to_writer(&mut buf , &new_db.database_file_name)?; //new_db.database_file_name is the db_key
    buf.rewind()?;
    debug!("Setting the checksum for the new database");
    calculate_db_file_checksum(&new_db.database_file_name, &mut buf)?;
    buf.rewind()?;  //do we require this
    std::io::copy(&mut buf, writer)?;
    debug!("New db data is copied from buf to file");

    //Ok(new_db.database_file_name.clone())
    Ok(kdbx_loaded)
}

/// Removes the previously opened KDBX file from cache
pub fn close_kdbx(db_key: &str) -> Result<()> {
    let mut store = main_store().lock().unwrap();

    // UI side save is handled for any changes.
    // As an additional check, on the backendside, we may need to verify that all changes are persisted and
    // ask the user to save or not if there are any unsaved changes

    store.remove(db_key);
    Ok(())
}

/// Called to save the modified database with a backup in desktop
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows",))]
pub fn save_kdbx_with_backup(
    db_key: &str,
    backup_file_name: Option<&str>,
    overwrite: bool,
) -> Result<KdbxSaved> {
    let kdbx_saved = call_kdbx_context_mut_action(db_key, |ctx: &mut KdbxContext| {
        write_kdbx_file_with_backup_file(&mut ctx.kdbx_file, backup_file_name, overwrite)?;
        // All changes are now saved to file
        ctx.save_pending = false;
        Ok(KdbxSaved {
            db_key: db_key.into(),
            database_name: ctx.kdbx_file.get_database_name().into(),
        })
    })?;
    Ok(kdbx_saved)
}

// Mobile 
pub fn verify_db_file_checksum<R: Read + Seek>(db_key: &str, reader: &mut R) -> Result<()> {
    call_kdbx_context_mut_action(db_key, |ctx: &mut KdbxContext| {
        db::verify_db_file_checksum(&mut ctx.kdbx_file, reader)
    })?;
    Ok(())
}

// Mobile
pub fn calculate_db_file_checksum<R: Read + Seek>(db_key: &str, reader: &mut R) -> Result<()> {
    call_kdbx_context_mut_action(db_key, |ctx: &mut KdbxContext| {
        ctx.kdbx_file.checksum_hash = db::calculate_db_file_checksum(reader)?;
        Ok(())
    })
}

// Mobile
/// Converts all data from memory structs to kdbx database formatted data and
/// writes the final complte db content to the supplied writer. The writer may be in memory or a file
/// Returns the result of saving in KdbxSaved struct to the client
pub fn save_kdbx_to_writer<W: Read + Write + Seek>(
    writer: &mut W,
    db_key: &str,
) -> Result<KdbxSaved> {
    let kdbx_saved = call_kdbx_context_mut_action(db_key, |ctx: &mut KdbxContext| {
        db::write_db(writer, &mut ctx.kdbx_file)?;
        // All changes are now saved to file
        ctx.save_pending = false;
        debug!(
            "Saving database_name {} with db_key {}",
            ctx.kdbx_file.get_database_name(),
            &db_key
        );
        Ok(KdbxSaved {
            db_key: db_key.into(),
            database_name: ctx.kdbx_file.get_database_name().into(),
        })
    })?;
    Ok(kdbx_saved)
}

/// Called to save all modified db files in one go and also creating backups in desktop
pub fn save_all_modified_dbs_with_backups(
    db_keys_and_backups: Vec<(String, Option<String>)>,
) -> Result<Vec<SaveAllResponse>> {
    if db_keys_and_backups.is_empty() {
        return Err(Error::DataError(
            "Empty db keys list is passed. Expected at least one db key in the list",
        ));
    }
    let mut save_result = vec![];
    // We should not make any other calls that may require main_store().lock()
    // If used, that will lead to deadlock. For example, using any of 'save_kdbx*' methods
    // instead of 'write_kdbx*' methods
    let mut store = main_store().lock().unwrap();
    for (db_key, backup_file_name) in db_keys_and_backups {
        match store.get_mut(&db_key) {
            Some(ctx) => {
                if ctx.save_pending == true {
                    match write_kdbx_file_with_backup_file(
                        &mut ctx.kdbx_file,
                        backup_file_name.as_deref(),
                        false,
                    ) {
                        Ok(()) => {
                            ctx.save_pending = false;
                            save_result.push(SaveAllResponse {
                                db_key,
                                save_status: SaveStatus::Success,
                            })
                        }
                        Err(e) => save_result.push(SaveAllResponse {
                            db_key,
                            save_status: SaveStatus::Failed(format!(
                                "Writing failed with error {}",
                                e
                            )),
                        }),
                    }
                } else {
                    save_result.push(SaveAllResponse {
                        db_key,
                        save_status: SaveStatus::Message(
                            "The db file is not in modified status. No saving was done".into(),
                        ),
                    })
                }
            }
            None => save_result.push(SaveAllResponse {
                db_key,
                save_status: SaveStatus::Failed(format!("The supplied db key is not found")),
            }),
        };
    }
    Ok(save_result)
}

/// Saves to a new db file in desktop app and returns the db key in KdbxLoaded when successfully the file is saved
pub fn save_as_kdbx(db_key: &str, database_file_name: &str) -> Result<KdbxLoaded> {
    let kdbx_loaded = call_kdbx_context_mut_action(db_key, |ctx: &mut KdbxContext| {
        ctx.kdbx_file.set_database_file_name(database_file_name);
        write_kdbx_file(&mut ctx.kdbx_file, true)?;
        // All changes are now saved to file
        ctx.save_pending = false;
        Ok(KdbxLoaded {
            db_key: database_file_name.into(),
            database_name: ctx.kdbx_file.get_database_name().into(),
        })
    })?;

    // As the db_file_name is changed, we need to reset the db key to this new name
    let mut store = main_store().lock().unwrap();
    if let Some(v) = store.remove(db_key) {
        store.insert(database_file_name.into(), v);
    }
    Ok(kdbx_loaded)
}

// Mobile 
/// Called to rename the db key used and the database_file_name as we know
/// the full db file name and db_key are used interchangeabley
pub fn rename_db_key(old_db_key: &str, new_db_key: &str) -> Result<KdbxLoaded> {
    let kdbx_loaded = call_kdbx_context_mut_action(old_db_key, |ctx: &mut KdbxContext| {
        ctx.kdbx_file.set_database_file_name(new_db_key);
        Ok(KdbxLoaded {
            db_key: new_db_key.into(),
            database_name: ctx.kdbx_file.get_database_name().into(),
        })
    })?;

    let mut store = main_store().lock().unwrap();
    if let Some(v) = store.remove(old_db_key) {
        store.insert(new_db_key.into(), v);
    }

    Ok(kdbx_loaded)
}

/// Compares the entered credentials with the stored one for a quick unlock of the db
pub fn unlock_kdbx(
    db_key: &str,
    password: &str,
    key_file_name: Option<&str>,
) -> Result<KdbxLoaded> {
    kdbx_context_action!(db_key, |ctx: &KdbxContext| {
        if ctx.kdbx_file.compare_key(password, key_file_name)? {
            Ok(KdbxLoaded {
                db_key: db_key.into(),
                database_name: ctx.kdbx_file.get_database_name().into(),
            })
        } else {
            // Same error as if db file verification failure as in load_kdbx
            Err(Error::HeaderHmacHashCheckFailed)
        }
    })
}

pub fn export_main_content_as_xml(db_key: &str, xml_file_name: &str) -> Result<()> {
    main_content_action!(db_key, |k: &KeepassFile| {
        Ok(db::export_db_main_content_as_xml(k, xml_file_name)?)
    })
}

// This will call before_xml_writing and any attachemnt hash to ref conversion is done
pub fn export_as_xml(db_key: &str, xml_file_name: &str) -> Result<()> {
    kdbx_context_mut_action!(db_key, |ctx: &mut KdbxContext| {
        db::export_as_xml(&mut ctx.kdbx_file, Some(xml_file_name))
    })
}

/// Gather all unique tags that are used in all groups and entries
pub fn collect_entry_group_tags(db_key: &str) -> Result<AllTags> {
    main_content_action!(db_key, move |k: &KeepassFile| Ok(k.root.collect_tags()))
}

pub fn get_db_settings(db_key: &str) -> Result<DbSettings> {
    kdbx_context_action!(db_key, |ctx: &KdbxContext| {
        let kp = to_keepassfile!(ctx.kdbx_file);

        let db_settings = DbSettings {
            kdf: ctx.kdbx_file.get_kdf_algorithm(),
            cipher_id: ctx.kdbx_file.get_content_cipher_id(),
            password: None,
            key_file_name: ctx.kdbx_file.get_key_file_name(),
            database_file_name: ctx.kdbx_file.get_database_file_name().to_string(),
            meta: (&kp.meta).into(),
        };
        Ok(db_settings)
    })
}

pub fn set_db_settings(db_key: &str, db_settings: DbSettings) -> Result<()> {
    kdbx_context_mut_action!(db_key, |ctx: &mut KdbxContext| {
        let db_settings = db_settings.clone();
        let kp = ctx
            .kdbx_file
            .keepass_main_content
            .as_mut()
            .ok_or("No main content")?;
        kp.meta.update((&db_settings.meta).into())?;
        // Password changed
        if let Some(s) = db_settings.password {
            ctx.kdbx_file.set_password(&s);
        }
        // TODO: Check the existence of 'key_file_name' and return error before calling set_file_key
        ctx.kdbx_file
            .set_file_key(db_settings.key_file_name.as_deref())?;

        ctx.kdbx_file.set_kdf_algorithm(db_settings.kdf)?;
        ctx.kdbx_file.set_content_cipher_id(db_settings.cipher_id)?;
        Ok(())
    })
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EntrySearchResult {
    pub term: String,
    pub entry_items: Vec<EntrySummary>,
}

/// A simple term search. The term is searched in all fields of each entry and returned all matching entry ids
pub fn search_term(db_key: &str, term: &str) -> Result<EntrySearchResult> {
    main_content_action!(db_key, |k: &KeepassFile| {
        let mut search_result = EntrySearchResult {
            term: term.into(),
            entry_items: vec![],
        };

        for e in k.get_all_entries(true) {
            if searcher::term_search_all_entry_fields(term, e)? {
                let (t1, t2) = extract_entry_titles(e);
                search_result.entry_items.push(EntrySummary {
                    uuid: e.uuid.to_string(),
                    title: t1,
                    secondary_title: t2,
                    icon_id: e.icon_id,
                    history_index: None,
                });
            }
        }
        Ok(search_result)
    })
}

// Deprecated; Use entry_type_headers
pub fn entry_type_names(db_key: &str) -> Result<EntryTypeNames> {
    main_content_action!(db_key, |k: &KeepassFile| {
        k.meta
            .custom_entry_type_names_by_id()
            .sort_by(|a, b| a.1.cmp(&b.1));
        //let mut sn = standard_type_names();
        let mut sn = standard_types_ordered_by_id()
            .into_iter()
            .map(|e| e.name.clone())
            .collect::<Vec<String>>();
        //let mut sn = standard_type_uuids_names_ordered_by_id();
        sn.sort();
        let type_names = EntryTypeNames {
            custom: k
                .meta
                .custom_entry_type_names_by_id()
                .into_iter()
                .map(|(_, s)| s)
                .collect(), //entries.sort_unstable_by(|a, b| a.title.cmp(&b.title));
            //standard: sn.into_iter().map(|(_,s)| s).collect(),
            standard: sn,
        };
        Ok(type_names)
    })
}

pub fn entry_type_headers(db_key: &str) -> Result<EntryTypeHeaders> {
    main_content_action!(db_key, |k: &KeepassFile| {
        let to_headers = |v: Vec<&EntryType>| {
            v.into_iter()
                .map(|e| EntryTypeHeader {
                    uuid: e.uuid.clone(),
                    name: e.name.clone(),
                    icon_name: e.icon_name.clone(),
                })
                .collect()
        };

        let custom: Vec<EntryTypeHeader> = k.meta.with_custom_entry_type(to_headers);
        let standard = to_headers(standard_types_ordered_by_id());

        Ok(EntryTypeHeaders { custom, standard })
    })
}

pub fn insert_or_update_custom_entry_type(
    db_key: &str,
    entry_type_form_data: &EntryTypeFormData,
) -> Result<Uuid> {
    main_content_mut_action!(db_key, |k: &mut KeepassFile| {
        let et: EntryType = entry_type_form_data.into();
        let entry_type_uuid = et.uuid.clone();
        k.meta
            .insert_or_update_custom_entry_type(entry_type_form_data.into());
        Ok(entry_type_uuid)
    })
}

/// Adjusts the special groups are such as recycle bin group listed
/// in the end of the child group ids in case of root group
fn adjust_special_groups_order(k: &KeepassFile, group: &Group) -> Vec<String> {
    if k.root.root_uuid == group.uuid {
        let v: Vec<String> = group
            .group_uuids
            .iter()
            .filter(|x| !k.root.special_group_uuids().contains(x))
            .map(|x| x.to_string())
            .collect();

        [
            v,
            k.root
                .special_group_uuids()
                .iter()
                .map(|x| x.to_string())
                .collect(),
        ]
        .concat()
    } else {
        group.group_uuids.iter().map(|x| x.to_string()).collect()
    }
}

/// Create as group summary data for all groups
fn create_groups_summary_data(k: &KeepassFile) -> Result<GroupTree> {
    let mut grps: HashMap<String, GroupSummary> = HashMap::new();
    // All groups including special groups (e.g Recycle Bin Group) are collected
    // to form summary. Need to pass 'false' to include all groups
    for group in &k.root.get_all_groups(false) {
        grps.insert(
            group.uuid.to_string(),
            GroupSummary {
                uuid: group.uuid.to_string(),
                name: group.name.clone(),
                icon_id: group.icon_id,
                group_uuids: adjust_special_groups_order(k, &group),
                entry_uuids: group.entry_uuids.iter().map(|x| x.to_string()).collect(),
            },
        );
    }
    Ok(GroupTree {
        root_uuid: k.root.root_uuid,
        recycle_bin_uuid: k.root.recycle_bin_uuid,
        deleted_group_uuids: k.deleted_group_uuids(),
        groups: grps,
    })
}

pub fn groups_summary_data(db_key: &str) -> Result<GroupTree> {
    main_content_action!(db_key, create_groups_summary_data)
}

/// All categories that can be shown in the UI layer including individual groups
pub fn categories_to_show(db_key: &str) -> Result<EntryCategoryInfo> {
    let action = |k: &KeepassFile| Ok(k.into());
    main_content_action!(db_key, action)
}

pub fn mark_group_as_category(db_key: &str, group_id: &str) -> Result<()> {
    let gid = Uuid::parse_str(group_id)?;
    main_content_mut_action!(db_key, |k: &mut KeepassFile| {
        Ok(k.root.mark_group_as_category(&gid))
    })
}

/// Extracts the primary, secondary title and icon id only to show the entries in a list
/// TODO: Deprecate after changing its use in "search_term" fn
fn extract_entry_titles(entry: &Entry) -> (Option<String>, Option<String>) {
    let mut titles: (Option<String>, Option<String>) = (None, None);
    for kv in &entry.entry_field.get_key_values() {
        if kv.key == "Title" {
            titles.0 = Some(kv.value.clone());
        } else if kv.key == "UserName" {
            titles.1 = Some(kv.value.clone());
        }
    }
    titles
}

pub fn entry_summary_data(
    db_key: &str,
    entry_category: EntryCategory,
) -> Result<Vec<EntrySummary>> {
    let action = |k: &KeepassFile| {
        let mut entries = EntrySummary::entry_summary_data(entry_by_category(&k, &entry_category));
        // for now sort just by the title
        entries.sort_unstable_by(|a, b| a.title.cmp(&b.title));
        Ok(entries)
    };
    main_content_action!(db_key, action)
}

// Deprecate - See below fn comment
// A macro to query the db store for an entry or group by id
macro_rules! query_main_content_by_id {
    ($db_key:expr, $uuid:expr, $coll_name:tt) => {
        main_content_action!(
            $db_key,
            (|k: &KeepassFile| match Uuid::parse_str($uuid) {
                Ok(p_uuid) => {
                    if let Some(g) = k.root.$coll_name(&p_uuid) {
                        return Ok(g.clone());
                    } else {
                        return Err(Error::NotFound(
                            "No entry Entry/Group found for the id".into(),
                        ));
                    }
                }
                Err(e) => Err(Error::UuidCoversionFailed(e)),
            })
        )
    };
}

// Deprecate after using get_group_by_id in Mobile
pub fn query_group_by_id(db_key: &str, group_uuid: &str) -> Result<Group> {
    query_main_content_by_id!(db_key, group_uuid, group_by_id)
}

pub fn get_group_by_id(db_key: &str, group_uuid: &Uuid) -> Result<Group> {
    main_content_action!(db_key, move |k: &KeepassFile| {
        match k.root.group_by_id(group_uuid) {
            Some(g) => Ok(g.clone()),
            None => Err(Error::NotFound("No group Entry found for the id".into())),
        }
    })
}

pub fn get_entry_form_data_by_id(db_key: &str, entry_uuid: &Uuid) -> Result<EntryFormData> {
    main_content_action!(db_key, move |k: &KeepassFile| {
        match k.root.entry_by_id(entry_uuid) {
            Some(e) => Ok(e.into()),
            None => Err(Error::NotFound("No entry Entry found for the id".into())),
        }
    })
}

pub fn history_entry_by_index(
    db_key: &str,
    entry_uuid: &Uuid,
    index: i32,
) -> Result<EntryFormData> {
    main_content_action!(db_key, move |k: &KeepassFile| {
        match k.root.history_entry_by_index(entry_uuid, index) {
            Some(ref e) => Ok(e.into()),
            None => Err(Error::NotFound("No entry Entry found for the id".into())),
        }
    })
}

pub fn delete_history_entry_by_index(db_key: &str, entry_uuid: &Uuid, index: i32) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        k.root.delete_history_entry_by_index(entry_uuid, index);
        Ok(())
    })
}

pub fn delete_history_entries(db_key: &str, entry_uuid: &Uuid) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        k.root.delete_history_entries(entry_uuid);
        Ok(())
    })
}

pub fn history_entries_summary(db_key: &str, entry_uuid: &Uuid) -> Result<Vec<EntrySummary>> {
    main_content_action!(db_key, move |k: &KeepassFile| {
        match k.root.entry_by_id(entry_uuid) {
            Some(e) => Ok(EntrySummary::history_entries_summary(e)),
            None => Err(Error::NotFound("No entry Entry found for the id".into())),
        }
    })
}

pub fn update_entry_from_form_data(db_key: &str, form_data: EntryFormData) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        k.root.update_entry((&form_data).into())
    })
}

pub fn insert_entry_from_form_data(db_key: &str, form_data: EntryFormData) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        // entry.meta_share is not yet set when EntryFormData is converted to
        // an Entry. It is set in Keepass's insert_entry which in turn
        // calls k.root.insert_entry
        k.insert_entry((&form_data).into())
    })
}

pub fn update_group(db_key: &str, group: Group) -> Result<()> {
    main_content_mut_action!(db_key, |k: &mut KeepassFile| {
        Ok(k.root.update_group(group.clone()))
    })
}

pub fn insert_group(db_key: &str, group: Group) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        k.root.insert_group(group.clone())
    })
}

pub fn move_group_to_recycle_bin(db_key: &str, group_uuid: Uuid) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        k.root.move_group_to_recycle_bin(group_uuid)
    })
}

pub fn move_group(db_key: &str, group_uuid: Uuid, new_parent_id: Uuid) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        k.root.move_group(group_uuid, new_parent_id)
    })
}

pub fn remove_group_permanently(db_key: &str, group_uuid: Uuid) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        k.root.remove_group_permanently(group_uuid)
    })
}

pub fn move_entry_to_recycle_bin(db_key: &str, entry_uuid: Uuid) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        k.root.move_entry_to_recycle_bin(entry_uuid)
    })
}

pub fn move_entry(db_key: &str, entry_uuid: Uuid, new_parent_id: Uuid) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        k.root.move_entry(entry_uuid, new_parent_id)
    })
}

pub fn remove_entry_permanently(db_key: &str, entry_uuid: Uuid) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        k.root.remove_entry_permanently(entry_uuid)
    })
}

pub fn empty_trash(db_key: &str) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| { k.empty_trash() })
}

// Returns the deleted custom entry type's header to the caller
pub fn delete_custom_entry_type_by_id(
    db_key: &str,
    entry_type_uuid: &Uuid,
) -> Result<EntryTypeHeader> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        let et_opt = k.delete_custom_entry_type_by_id(entry_type_uuid)?;
        let entry_type_header = et_opt.map_or_else(
            || EntryTypeHeader::default(),
            |e| EntryTypeHeader {
                uuid: e.uuid.clone(),
                name: e.name.clone(),
                icon_name: None,
            },
        );
        Ok(entry_type_header)
    })
}

pub fn new_entry_form_data_by_id(
    db_key: &str,
    entry_type_uuid: &Uuid,
    parent_group_uuid: Option<&Uuid>,
) -> Result<EntryFormData> {
    main_content_action!(db_key, |k: &KeepassFile| {
        Ok(EntryFormData::new_form_entry_by_type_id(
            entry_type_uuid,
            k.meta.get_custom_entry_type_by_id(entry_type_uuid),
            parent_group_uuid,
        ))
    })
}

pub fn new_blank_group(mark_as_category: bool) -> Group {
    let mut group = Group::new();
    group.uuid = uuid::Uuid::new_v4();
    if mark_as_category {
        group.mark_as_category();
        //group.custom_data.mark_as_category();
    }
    group
}

pub fn new_blank_group_with_parent(
    parent_group_uuid: Uuid,
    mark_as_category: bool,
) -> Result<Group> {
    if parent_group_uuid == Uuid::default() {
        return Err(Error::Other("Valid parent group is not provided".into()));
    }
    let mut group = new_blank_group(mark_as_category);
    group.parent_group_uuid = parent_group_uuid;
    Ok(group)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AttachmentUploadInfo {
    pub name: String,
    #[serde(with = "util::from_or_to::string")]
    pub data_hash: AttachmentHashValue,
    pub data_size: usize,
}

/// Called to upload an attachment.  
/// On successful loading the file content, the attachment name and hash for the file data are returned
/// The caller need to connect these info with the an entry as this uploading of the binary data is done only to the
/// inner header structure and yet to be linked with an Entry
pub fn upload_entry_attachment(db_key: &str, file_name: &str) -> Result<AttachmentUploadInfo> {
    //Load the file from file system
    let file = File::open(file_name)?;
    let mut buf_reader = BufReader::new(file);
    let name = Path::new(file_name)
        .file_name()
        .and_then(|x| x.to_str())
        .unwrap_or("No Attachment Name");

    call_kdbx_context_mut_action(db_key, |ctx: &mut KdbxContext| {
        let mut buf = vec![];
        buf_reader.read_to_end(&mut buf)?;
        let size = buf.len();
        let data_hash = ctx.kdbx_file.upload_entry_attachment(buf);
        Ok(AttachmentUploadInfo {
            name: name.into(),
            data_hash: data_hash,
            data_size: size,
        })
    })
}

/// Saves the bytes content of an entry attachment as file to temp dir
/// The file name is based on 'name' and valid data hash handle is required to get the bytes data
pub fn save_attachment_as_temp_file(
    db_key: &str,
    name: &str,
    data_hash: &AttachmentHashValue,
) -> Result<String> {
    let mut path = env::temp_dir();
    println!("The current directory is {}", path.display());
    // The app temp dir
    path.push("okp_cache");
    if !path.exists() {
        std::fs::create_dir(path.clone())?;
    }

    // Push the file name wanted and create the file with full name
    // TODO: Generate some random file name ?
    path.push(name);
    let mut file = std::fs::File::create(path.clone())?;

    let data = call_kdbx_context_action(db_key, |ctx: &KdbxContext| {
        Ok(ctx.kdbx_file.get_bytes_content(data_hash))
    })?;

    if let Some(v) = data {
        file.write_all(&v)?;
        path.to_str()
            .ok_or_else(|| "Invalid temp file".into())
            .map(|s| s.into())
    } else {
        Err(Error::Other("No valid data found".into()))
    }
}

/// Removes all contents of the app's temp dir
pub fn remove_app_temp_dir_content() -> Result<()> {
    let mut path = env::temp_dir();
    path.push("okp_cache");
    util::remove_dir_contents(path)
}

pub fn analyzed_password(password_options: PasswordGenerationOptions) -> Result<AnalyzedPassword> {
    password_options.analyzed_password()
}

pub fn score_password(password: &str) -> PasswordScore {
    password_generator::score_password(password)
}
