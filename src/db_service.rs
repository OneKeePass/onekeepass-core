// These are sub modules from dir db_service
// db_service.rs is used instead of mod.rs in dir db_service

mod attachment;
mod io;

// Note: Moved module storage to db_service_ffi crate as it is used only in mobile apps for now

// Modules storage and callback_service are used for now only in mobile apps
//#[cfg(any( target_os = "ios",target_os = "android"))]
//pub mod callback_service;
// #[cfg(any( target_os = "ios",target_os = "android"))]
// pub mod storage;

use crate::db::KdbxFile;
use crate::db_content::{standard_types_ordered_by_id, Entry, KeepassFile, OtpData};
use crate::db_merge;
use crate::form_data;
use crate::searcher;
use crate::util;

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use chrono::NaiveDateTime;
use log::debug;
use uuid::Uuid;

//    ========  Re-exports to use in all api users ============

pub use attachment::{
    read_entry_attachment, remove_app_temp_dir_content, save_attachment_as,
    save_attachment_as_temp_file, save_attachment_to_writter, upload_entry_attachment,
    AttachmentUploadInfo,
};

// For now, as some fns are used only in desktop, need to include
// all fns from this module so that desktop and mobile compilation
// works
pub use io::*;

// pub use io::{
//     create_and_write_to_writer, create_kdbx, export_as_xml,
//     export_main_content_as_xml, generate_key_file, load_kdbx, read_and_verify_db_file, read_kdbx,
//     reload_kdbx, save_all_modified_dbs_with_backups, save_as_kdbx,
//     save_kdbx_to_writer, save_kdbx_with_backup, save_to_db_file,
// };

pub use crate::error::{self, Error, Result};

pub use crate::password_passphrase_generator::{
    AnalyzedPassword, GeneratedPassPhrase, PassphraseGenerationOptions, PasswordGenerationOptions,
    PasswordScore, WordListLoader,
};

// See lib.rs where util module is reexported as service_util
// another option is rename 'util' module as 'service_util' to avoid confilts with other crates 'util' module
pub use crate::service_util;

pub use crate::db::{
    calculate_db_file_checksum, KeyStoreOperation, KeyStoreService, KeyStoreServiceType,
    NewDatabase, SecureKeyInfo,
};

pub use crate::db_content::{
    AllTags, EntryCloneOption, EntryType, FieldDataType, Group, GroupSortCriteria, OtpSettings,
};

pub use crate::form_data::{
    CategoryDetail, CurrentOtpTokenData, DbSettings, EntryCategories, EntryCategory,
    EntryCategoryGrouping, EntryCategoryInfo, EntryFormData, EntrySummary, EntryTypeFormData,
    EntryTypeHeader, EntryTypeHeaders, EntryTypeNames, GroupSummary, GroupTree, KdbxLoaded,
    KdbxSaved,
};

pub use crate::constants::entry_keyvalue_key;

pub use crate::db_merge::MergeResult;

pub use crate::import::csv_reader::{CsvImport, CsvImportOptions, CvsHeaderInfo,CsvImportMapping};

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
pub(crate) struct KdbxContext {
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

impl KdbxContext {
    // Add the newly created KdbxFile to cache for UI use
    fn insert(kdbx_file:KdbxFile,) {
        let db_key = kdbx_file.get_database_file_name().to_string();
        let mut kdbx_context = KdbxContext::default();
        kdbx_context.kdbx_file = kdbx_file;
        let mut store = main_store().lock().unwrap();
        store.insert(db_key, kdbx_context);
    }
}

// Here we're using an Arc to share memory among threads, and the data - HashMap<String, KdbxContext> - inside
// the Arc is protected with a mutex.
// The keys of inner HashMap are from 'db_key' of each opened database
type MainStore = Arc<Mutex<HashMap<String, KdbxContext>>>;

fn main_store() -> &'static MainStore {
    static MAIN_STORE: Lazy<MainStore> = Lazy::new(Default::default);
    &MAIN_STORE
}

// Gets a ref to the main keepass content
#[macro_export]
macro_rules! to_keepassfile {
    ($kdbx_file:expr) => {
        // Need to get Option<&KeepassFile> from Option<KeepassFile> using as_ref
        $kdbx_file
            .keepass_main_content
            .as_ref()
            .ok_or("No main content")?
    };
}

#[macro_export]
macro_rules! to_keepassfile_mut {
    ($kdbx_file:expr) => {
        // Need to get Option<&KeepassFile> from Option<KeepassFile> using as_ref
        $kdbx_file
            .keepass_main_content
            .as_mut()
            .ok_or("No main content")?
    };
}

// A macro to do a db query and then update the last read time for tracking
#[macro_export]
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

// A macro to call a db modification and then update the last write time for tracking
#[macro_export]
macro_rules! main_content_mut_action {
    ($db_key:expr,$closure_fn:expr) => {{
        let r = call_main_content_mut_action($db_key, $closure_fn);
        // Update the write time
        call_kdbx_context_mut_action($db_key, |ctx: &mut KdbxContext| {
            ctx.last_write_time = crate::util::now_utc();
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
#[macro_export]
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

#[macro_export]
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
pub(crate) fn call_kdbx_context_mut_action<T, F>(db_key: &str, mut action: F) -> Result<T>
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
pub(crate) fn call_main_content_mut_action<T, F>(db_key: &str, action: F) -> Result<T>
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

pub fn all_kdbx_cache_keys() -> Result<Vec<String>> {
    let store = main_store().lock().unwrap();
    let mut vec = vec![];
    for k in store.keys() {
        vec.push(k.clone());
    }
    Ok(vec)
}

pub fn is_db_opened(db_key: &str) -> bool {
    let store = main_store().lock().unwrap();
    store.contains_key(db_key)
}

// Gets the previously calculated checksum for a db found under the db_key
pub fn db_checksum_hash(db_key: &str) -> Result<Vec<u8>> {
    call_kdbx_context_action(db_key, |ctx: &KdbxContext| {
        Ok(ctx.kdbx_file.checksum_hash().clone())
    })
}

pub fn close_all_databases() -> Result<()> {
    if let Ok(keys) = all_kdbx_cache_keys() {
        for k in keys {
            let _r = close_kdbx(&k);
        }
    }
    Ok(())
}

/// Removes the previously opened KDBX file from cache
pub fn close_kdbx(db_key: &str) -> Result<()> {
    let mut store = main_store().lock().unwrap();
    // UI side save is handled for any changes.
    // As an additional check, on the backendside, we may need to verify that all changes are persisted and
    // ask the user to save or not if there are any unsaved changes
    store.remove(db_key);
    KeyStoreOperation::delete_key(db_key)?;
    Ok(())
}

// Mobile (iOS and Android)
// Called to rename the db key used and the database_file_name as we know
// the full db file name and db_key are used interchangeably
// Used mainly in 'complete_save_as_on_error' call

// See db_service::ios::save_as_kdbx for desktop version where db_key is the
// actual file to which content is written. Here we are changing map key

// TODO: Combine these two

pub fn rename_db_key(old_db_key: &str, new_db_key: &str) -> Result<KdbxLoaded> {
    // Need to copy the encrytion key for the new name from the existing one
    KeyStoreOperation::copy_key(old_db_key, new_db_key)?;

    let kdbx_loaded = call_kdbx_context_mut_action(old_db_key, |ctx: &mut KdbxContext| {
        ctx.kdbx_file.set_database_file_name(new_db_key);

        Ok(KdbxLoaded {
            db_key: new_db_key.into(),
            database_name: ctx.kdbx_file.get_database_name().into(),
            // TODO: Check the use of 'None' values below fields in iOS and Android after this Save as call
            //       We may need to update in db-service_ffi crate before sending back to UI
            file_name: None,
            key_file_name: None,
        })
    })?;

    // As the db_file_name is changed, we need to reset the db key to this new name
    let mut store = main_store().lock().unwrap();
    if let Some(v) = store.remove(old_db_key) {
        store.insert(new_db_key.into(), v);
    }

    // Remove the old encryption key for the old db_key
    KeyStoreOperation::delete_key(old_db_key)?;

    Ok(kdbx_loaded)
}

// Called after user has successfully completed the biometeric based authentication
pub fn unlock_kdbx_on_biometric_authentication(db_key: &str) -> Result<KdbxLoaded> {
    kdbx_context_action!(db_key, |ctx: &KdbxContext| {
        Ok(KdbxLoaded {
            db_key: db_key.into(),
            database_name: ctx.kdbx_file.get_database_name().into(),
            file_name: util::file_name(db_key),
            key_file_name: ctx.kdbx_file.get_key_file_name(),
        })
    })
}

// Compares the entered credentials with the stored one for a quick unlock of the db
pub fn unlock_kdbx(
    db_key: &str,
    password: Option<&str>,
    key_file_name: Option<&str>,
) -> Result<KdbxLoaded> {
    kdbx_context_action!(db_key, |ctx: &KdbxContext| {
        if ctx.kdbx_file.compare_key(password, key_file_name)? {
            Ok(KdbxLoaded {
                db_key: db_key.into(),
                database_name: ctx.kdbx_file.get_database_name().into(),
                file_name: util::file_name(db_key),
                key_file_name: ctx.kdbx_file.get_key_file_name(),
            })
        } else {
            // Same error as if db file verification failure happening in load_kdbx
            Err(Error::HeaderHmacHashCheckFailed)
        }
    })
}

// Gather all unique tags that are used in all groups and entries
pub fn collect_entry_group_tags(db_key: &str) -> Result<AllTags> {
    main_content_action!(db_key, move |k: &KeepassFile| Ok(k.root.collect_tags()))
}

pub fn get_db_settings(db_key: &str) -> Result<DbSettings> {
    kdbx_context_action!(db_key, |ctx: &KdbxContext| {
        let kp = to_keepassfile!(ctx.kdbx_file);

        let key_file_name = ctx.kdbx_file.get_key_file_name();
        //Used only in Mobile apps
        let key_file_name_part = key_file_name.as_ref().and_then(|s| util::file_name(s));

        let (password_used, key_file_used) = ctx.kdbx_file.credentials_used_state();

        let db_settings = DbSettings {
            kdf: ctx.kdbx_file.get_kdf_algorithm(),
            cipher_id: ctx.kdbx_file.get_content_cipher_id(),
            password: None,
            key_file_name,
            password_used,
            key_file_used,
            password_changed: false,
            key_file_changed: false,
            key_file_name_part,
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

        // IMPORTANT
        // password_used,key_file_used,password_changed and key_file_changed are set from client side
        // in a consistent way statifying the following combinations
        // e.g
        // If a password is changed, then password_used = true, password_changed = true and password = Some value
        // If the password use is removed,
        //     then password_used = false , password_changed = true, password = None  ;
        //          key_file_used = true , key_file_changed = true or false ,  key_file_name = Some value
        //
        // If a key file is changed,
        //      then key_file_used = true ,key_file_changed = true, key_file_name = Some value
        //      password_used = true or false, password_changed = false
        // If the key file use is removed,
        //      then key_file_used = false, key_file_changed = true,key_file_name = None; password_used = true , password_changed = true or false

        debug!("password_used: {}, password_changed: {}, password is nil?:  {},key_file_used: {}, key_file_changed: {}, key_file_name:  {:?}",
        &db_settings.password_used,&db_settings.password_changed,db_settings.password.is_none(),
        &db_settings.key_file_used, &db_settings.key_file_changed, &db_settings.key_file_name
        );

        // Both password and key file can not be none at the same time
        // Note the existing db_settings.password = None when password_changed = false as
        // the password field in DbSetttings is None (db_settings.password = None) in 'get_db_settings' call
        // Because of this db_settings.password will have Some value only when password_used = true and password_changed = true

        // If we do not use password, then key file should be used;
        // db_settings.password_used is false when password use is removed in Settings UI
        if !db_settings.password_used && db_settings.key_file_name.is_none() {
            return Err(error::Error::InSufficientCredentials);
        }

        // Password is used and expected some value when it is changed or added
        if db_settings.password_used
            && db_settings.password_changed
            && db_settings.password.is_none()
        {
            return Err(Error::DataError("Password can not be empty"));
        }

        if !db_settings.password_used && db_settings.password.is_some() {
            return Err(Error::DataError(
                "Password is not used, but found some value",
            ));
        }

        // When key_file_used is true,
        // then key file name should have some value - either the existing one or new one
        if db_settings.key_file_used && db_settings.key_file_name.is_none() {
            return Err(Error::DataError("Key file name can not be empty"));
        }

        // password is considered only when it is changed
        let password = if db_settings.password_used && db_settings.password_changed {
            // May be this check redundant ?
            if db_settings.password.is_none() {
                return Err(Error::DataError(
                    "Password can not be empty when password file used flag is set",
                ));
            }
            db_settings.password.as_deref()
        } else {
            None
        };

        let file_key = if db_settings.key_file_used {
            // May be this check redundant ?
            if db_settings.key_file_name.is_none() {
                return Err(Error::DataError(
                    "Key file name can not be empty when key file used flag is set",
                ));
            }
            db_settings.key_file_name.as_deref()
        } else {
            None
        };

        if db_settings.password_changed && db_settings.key_file_changed {
            // Both password and key file use changed
            ctx.kdbx_file.set_credentials(db_key, password, file_key)?;
        } else if db_settings.password_changed {
            // Only password changed
            ctx.kdbx_file.set_password(password)?;
        } else if db_settings.key_file_changed {
            // Only password key file used changed
            ctx.kdbx_file.set_file_key(file_key)?;
        }

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
                    parent_group_uuid:e.parent_group_uuid(),
                    title: t1,
                    secondary_title: t2,
                    icon_id: e.icon_id,
                    history_index: None,
                    #[allow(deprecated)]
                    modified_time: Some(e.times.last_modification_time.timestamp()),
                    #[allow(deprecated)]
                    created_time: Some(e.times.creation_time.timestamp()),
                });
            }
        }
        Ok(search_result)
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

// Adjusts the special groups are such as recycle bin group listed
// in the end of the child group ids in case of root group
fn adjust_special_groups_order(k: &KeepassFile, group: &Group) -> Vec<String> {
    if k.root.root_uuid() == group.uuid {
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

// Create as group summary data for all groups
// Returns the group tree data
fn create_groups_summary_data(k: &KeepassFile) -> Result<GroupTree> {
    let mut grps: HashMap<String, GroupSummary> = HashMap::new();
    // All groups including special groups (e.g Recycle Bin Group) are collected
    // to form summary. Need to pass 'false' to include all groups
    for group in &k.root.get_all_groups(false) {
        grps.insert(
            group.get_uuid().to_string(),
            GroupSummary {
                uuid: group.get_uuid(),
                parent_group_uuid: group.parent_group_uuid(),
                name: group.name.clone(),
                icon_id: group.icon_id,
                group_uuids: adjust_special_groups_order(k, &group),
                entry_uuids: group.entry_uuids.iter().map(|x| x.to_string()).collect(),
            },
        );
    }
    Ok(GroupTree {
        root_uuid: k.root.root_uuid(),
        recycle_bin_uuid: k.root.recycle_bin_uuid(),
        auto_open_group_uuid: k.root.auto_open_group_uuid(),
        deleted_group_uuids: k.deleted_group_uuids(),
        groups: grps,
    })
}

pub fn groups_summary_data(db_key: &str) -> Result<GroupTree> {
    main_content_action!(db_key, create_groups_summary_data)
}

// Deprecate
// All categories that can be shown in the UI layer including individual groups
pub fn categories_to_show(db_key: &str) -> Result<EntryCategoryInfo> {
    let action = |k: &KeepassFile| Ok(k.into());
    main_content_action!(db_key, action)
}

// All categories that can be shown in the UI layer
pub fn combined_category_details(
    db_key: &str,
    grouping_kind: &EntryCategoryGrouping,
) -> Result<EntryCategories> {
    let action = |k: &KeepassFile| {
        Ok(form_data::combined_category_details(
            k,
            grouping_kind.clone(),
        ))
    };
    main_content_action!(db_key, action)
}

pub fn mark_group_as_category(db_key: &str, group_id: &str) -> Result<()> {
    let gid = Uuid::parse_str(group_id)?;
    main_content_mut_action!(db_key, |k: &mut KeepassFile| {
        Ok(k.root.mark_group_as_category(&gid))
    })
}

// Extracts the primary, secondary title and icon id only to show the entries in a list
// TODO: Deprecate after changing its use in "search_term" fn
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
        // let mut entries = EntrySummary::entry_summary_data(form_data::entry_by_category(&k, &entry_category));
        let mut entries = EntrySummary::entry_summary_data(&k, &entry_category);
        // for now sort just by the title
        entries.sort_unstable_by(|a, b| a.title.cmp(&b.title));
        Ok(entries)
    };
    main_content_action!(db_key, action)
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
            // Need to parse and resolve place holders found in some entry fields
            Some(e) => Ok(EntryFormData::place_holder_resolved_form_data(&k.root, e)),
            None => Err(Error::NotFound(format!(
                "No entry is found for the id {}",
                entry_uuid
            ))),
        }
    })
}

// Gets all entries found under the special group 'AutoOpen'
pub fn auto_open_group_entries(db_key: &str) -> Result<Vec<EntryFormData>> {
    main_content_action!(db_key, move |k: &KeepassFile| {
        let ao_entries: Vec<EntryFormData> = k
            .root
            .auto_open_group_entries()
            .iter()
            .map(|entry| EntryFormData::place_holder_resolved_form_data(&k.root, entry))
            .collect();

        Ok(ao_entries)
    })
}

pub fn auto_open_group_entry_uuids(db_key: &str) -> Result<Vec<Uuid>> {
    main_content_action!(db_key, move |k: &KeepassFile| {
        Ok(k.root.auto_open_group_entry_uuids())
    })
}

pub fn auto_open_group_uuid(db_key: &str) -> Result<Option<Uuid>> {
    main_content_action!(db_key, move |k: &KeepassFile| {
        Ok(k.root.auto_open_group_uuid())
    })
}

// deprecate?
// Gets the current TOPT token for an entry's opt field
pub fn entry_form_current_otp(
    db_key: &str,
    entry_uuid: &Uuid,
    otp_field_name: &str,
) -> Result<CurrentOtpTokenData> {
    main_content_action!(db_key, move |k: &KeepassFile| {
        match k.root.entry_by_id(entry_uuid) {
            Some(e) => match e.current_otp_token_data(otp_field_name) {
                Some(pd) => Ok(pd),
                None => Err(Error::UnexpectedError(format!(
                    "Current TOPT token data is not available for the field: {}",
                    otp_field_name
                ))),
            },
            None => Err(Error::NotFound(format!(
                "No entry is found for the id {}",
                entry_uuid
            ))),
        }
    })
}

// deprecate?
pub fn entry_form_current_otps(
    db_key: &str,
    entry_uuid: &Uuid,
    otp_field_names: Vec<String>,
) -> Result<HashMap<String, CurrentOtpTokenData>> {
    main_content_action!(db_key, move |k: &KeepassFile| {
        match k.root.entry_by_id(entry_uuid) {
            Some(e) => {
                let v: HashMap<String, CurrentOtpTokenData> = otp_field_names
                    .iter()
                    .filter_map(|s| match e.current_otp_token_data(s) {
                        Some(d) => Some((s.clone(), d)),
                        None => None,
                    })
                    .collect();
                Ok(v)
            }
            None => Err(Error::NotFound(format!(
                "No entry is found for the id {}",
                entry_uuid
            ))),
        }
    })
}

#[inline]
pub fn form_otp_url(otp_settings: &OtpSettings) -> Result<String> {
    otp_settings.otp_url()
}

#[inline]
pub fn is_valid_otp_url(otp_url_str: &str) -> bool {
    OtpData::from_url(otp_url_str).is_ok()
}

// Collects all entry field names and its values (not in any particular order)
pub fn entry_key_value_fields(db_key: &str, entry_uuid: &Uuid) -> Result<HashMap<String, String>> {
    main_content_action!(db_key, move |k: &KeepassFile| {
        EntryFormData::entry_key_value_fields(k, entry_uuid)
        // match k.root.entry_by_id(entry_uuid) {
        //     Some(e) => Ok(e.field_values()),
        //     None => Err(Error::NotFound("No entry Entry found for the id".into())),
        // }
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

pub fn clone_entry(
    db_key: &str,
    entry_uuid: &Uuid,
    entry_clone_option: &EntryCloneOption,
) -> Result<Uuid> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        k.root.clone_entry(entry_uuid, entry_clone_option)
    })
}

pub fn update_group(db_key: &str, group: Group) -> Result<()> {
    main_content_mut_action!(db_key, |k: &mut KeepassFile| {
        Ok(k.root.update_group(group.clone(), false))
    })
}

// Called from UI layer to insert a newly added group
pub fn insert_group(db_key: &str, group: Group) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        // Delegate to the fn in root
        k.root.insert_group(group.clone())
    })
}

pub fn sort_sub_groups(
    db_key: &str,
    group_uuid: &Uuid,
    criteria: &GroupSortCriteria,
) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        // Delegate to the fn in root
        k.root.sort_sub_groups(group_uuid, criteria)
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
    let mut group = Group::new_with_id();
    // group.uuid = uuid::Uuid::new_v4();
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
        return Err(Error::UnexpectedError(
            "Valid parent group is not provided".into(),
        ));
    }
    let mut group = new_blank_group(mark_as_category);
    group.parent_group_uuid = parent_group_uuid;
    Ok(group)
}

#[cfg(any(target_os = "macos",target_os = "windows",target_os = "linux"))]
pub fn merge_databases(
    target_db_key: &str,
    source_db_key: &str,
    password: Option<&str>,
    key_file_name: Option<&str>,
) -> Result<MergeResult> {
    if target_db_key == source_db_key {
        return Err(error::Error::UnexpectedError(format!("Both source and target are the same databases. Please select a different database to merge")));
    }

    // IMPORTANT:
    // We need to call all the calls 'main_store().lock()' to access the shared cache in a {} block
    // so that the Mutex guard is unlocked while leaving the block and can then called again in another block or fn
    // If not done this way, the deadlock will happen when we make calls to 'main_store().lock()' before unlocking the previous call

    let source_already_opened = {
        let store = main_store().lock().unwrap();
        store.contains_key(source_db_key)
    };

    log::debug!("source_already_openned is {}", source_already_opened);

    let source_loaded = if !source_already_opened {
        load_kdbx(source_db_key, password, key_file_name)?;
        log::debug!("source is opened");
        true
    } else {
        false
    };

    let merge_result = {
        let mut store = main_store().lock().unwrap();
        let [target, source] = store.get_disjoint_mut([target_db_key, source_db_key]);
        log::debug!("Got refs for source and target");

        let target_kdbx = &mut target
            .ok_or_else(|| "Target database key is not found")?
            .kdbx_file;
        let source_kdbx = &source
            .as_ref()
            .ok_or_else(|| "Source database key is not found")?
            .kdbx_file;
        let merge_result = db_merge::Merger::from_kdbx_file(source_kdbx, target_kdbx).merge()?;
        log::debug!("Dbs are merged");

        merge_result
    };

    if source_loaded {
        close_kdbx(source_db_key)?;
        log::debug!("source_db_key closed as it was opened only for merging");
    }

    Ok(merge_result)
}


#[cfg(any( target_os = "ios",target_os = "android"))]
pub fn merge_databases(target_db_key: &str,source_db_key: &str,)  -> Result<MergeResult> {
    if target_db_key == source_db_key {
        return Err(error::Error::UnexpectedError(format!("Both source and target are the same databases. Please select a different database to merge")));
    }

    let merge_result = {
        let mut store = main_store().lock().unwrap();
        let [target, source] = store.get_disjoint_mut([target_db_key, source_db_key]);
        log::debug!("Got refs for source and target");

        let target_kdbx = &mut target
            .ok_or_else(|| "Target database key is not found")?
            .kdbx_file;
        let source_kdbx = &source
            .as_ref()
            .ok_or_else(|| "Source database key is not found")?
            .kdbx_file;
        let merge_result = db_merge::Merger::from_kdbx_file(source_kdbx, target_kdbx).merge()?;
        log::debug!("Dbs are merged");

        merge_result
    };

    Ok(merge_result)
}