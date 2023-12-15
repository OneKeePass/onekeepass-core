use std::io::{Cursor, Read, Seek, Write};
use std::path::Path;

use log::debug;

use super::{
    call_kdbx_context_mut_action, main_store, KdbxContext, KdbxLoaded, KdbxSaved, NewDatabase,
    SaveAllResponse,SaveStatus,
};
use crate::db_content::KeepassFile;

use crate::db_service::call_main_content_action;

// macros 
use crate::{to_keepassfile,main_content_action, kdbx_context_mut_action};

use crate::error::{Error, Result};

use crate::db::{self,write_kdbx_file,write_kdbx_file_with_backup_file, write_kdbx_content_to_file,};
use crate::util;

// TODO: Refactor create_kdbx (used mainly for desktop app) and create_and_write_to_writer to use common functionalties
// Called to create a new KDBX database and perists the file
// Returns KdbxLoaded with dbkey to locate this KDBX database in cache
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
    let file_name = util::file_name(&new_db.database_file_name);
    let kdbx_loaded = KdbxLoaded {
        db_key: new_db.database_file_name.clone(),
        database_name: kp.meta.database_name.clone(),
        file_name,
        key_file_name: kdbx_file.get_key_file_name(),
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

// Opens and reads a valid KDBX file.
// Returns KdbxLoaded with db key which is required to access such loaded db content from the cache
pub fn load_kdbx(
    db_file_name: &str,
    password: Option<&str>,
    key_file_name: Option<&str>,
) -> Result<KdbxLoaded> {
    let mut db_file_reader = db::open_db_file(db_file_name)?;
    let file_name = util::file_name(&db_file_name);
    read_kdbx(
        &mut db_file_reader,
        db_file_name,
        password,
        key_file_name,
        file_name.as_deref(),
    )
}

// Desktop
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows",))]
pub fn reload_kdbx(db_key: &str) -> Result<KdbxLoaded> {
    call_kdbx_context_mut_action(db_key, |ctx: &mut KdbxContext| {
        // db_key is full database file uri
        let mut db_file_reader = db::open_db_file(db_key)?;
        let reloaded_kdbx_file = db::reload(&mut db_file_reader, &ctx.kdbx_file)?;
        let kp = to_keepassfile!(reloaded_kdbx_file);

        let file_name = util::file_name(db_key);
        let kdbx_loaded = KdbxLoaded {
            db_key: db_key.into(),
            database_name: kp.meta.database_name.clone(),
            file_name,
            key_file_name: ctx.kdbx_file.get_key_file_name(),
        };

        ctx.kdbx_file = reloaded_kdbx_file;

        Ok(kdbx_loaded)
    })
}

// Used for both desktop and mobile
// db_file_name is full uri and used as db_key in all subsequent calls
pub fn read_kdbx<R: Read + Seek>(
    reader: &mut R,
    db_file_name: &str,
    password: Option<&str>,
    key_file_name: Option<&str>,
    file_name: Option<&str>,
) -> Result<KdbxLoaded> {
    let kdbx_file = db::read_db_from_reader(reader, db_file_name, password, key_file_name)?;

    let kp = to_keepassfile!(kdbx_file);
    //let file_name = util::file_name(&db_file_name);
    let kdbx_loaded = KdbxLoaded {
        db_key: db_file_name.into(),
        database_name: kp.meta.database_name.clone(),
        key_file_name: key_file_name.map(|s| s.to_string()),
        file_name: file_name.map(|s| s.to_string()),
    };

    let mut kdbx_context = KdbxContext::default();
    kdbx_context.kdbx_file = kdbx_file;

    // Arc<T> automatically dereferences to T (via the Deref trait),
    // so you can call T’s methods on a value of type Arc<T>
    let mut store = main_store().lock().unwrap();
    // Each database has a unique uri (File Path) and accordingly only one db with that name can be opened at a time
    // The 'db_file_name' is the full uri and used as a unique db_key throughout all db specific calls
    store.insert(db_file_name.into(), kdbx_context);
    debug!("Reading KDBX file {} is completed", db_file_name);
    Ok(kdbx_loaded)
}

// Called to save the modified database with a backup in desktop
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

// Desktop
// Called to save all modified db files in one go and also creating backups in desktop
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

// Saves to a new db file in desktop app and returns the db key in KdbxLoaded when successfully the file is saved
pub fn save_as_kdbx(db_key: &str, database_file_name: &str) -> Result<KdbxLoaded> {
    // Need to copy the encrytion key for the new name from the existing one
    db::KeyStoreOperation::copy_key(db_key, database_file_name)?;

    let kdbx_loaded = call_kdbx_context_mut_action(db_key, |ctx: &mut KdbxContext| {
        // database_file_name is full name uri and will be used the new saved as file's db_key
        ctx.kdbx_file.set_database_file_name(database_file_name);

        write_kdbx_file(&mut ctx.kdbx_file, true)?;
        // All changes are now saved to file
        ctx.save_pending = false;
        let file_name = util::file_name(&database_file_name);
        Ok(KdbxLoaded {
            db_key: database_file_name.into(),
            database_name: ctx.kdbx_file.get_database_name().into(),
            file_name,
            key_file_name: ctx.kdbx_file.get_key_file_name(),
        })
    })?;

    // As the db_file_name is changed, we need to reset the db key to this new name
    let mut store = main_store().lock().unwrap();
    if let Some(v) = store.remove(db_key) {
        store.insert(database_file_name.into(), v);
    }

    // Remove the old encryption key for the old db_key
    db::KeyStoreOperation::delete_key(db_key)?;

    Ok(kdbx_loaded)
}

// Saves the content of a openned kdbx database content to a new file with the given full file name
// This is different from 'save_as_kdbx' which saves to a new database file and changes the db_key to that
pub fn save_to_db_file(db_key: &str, full_file_name: &str) -> Result<()> {
    call_kdbx_context_mut_action(db_key, |ctx: &mut KdbxContext| {
        write_kdbx_content_to_file(&mut ctx.kdbx_file, full_file_name)
    })
}

// Mobile
// Creates a new db and writes into the supplied writer as kdbx db
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
        // only for android 'file_name' will have some value.
        // In case of iOS, not done as full uri is temp one
        // For desktop, see create_kdbx
        file_name: new_db.file_name,
        key_file_name: new_db.key_file_name,
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
    save_kdbx_to_writer(&mut buf, &new_db.database_file_name)?; //new_db.database_file_name is the db_key
    buf.rewind()?;
    calculate_db_file_checksum(&new_db.database_file_name, &mut buf)?;
    buf.rewind()?; //do we require this
    std::io::copy(&mut buf, writer)?;

    //Ok(new_db.database_file_name.clone())
    Ok(kdbx_loaded)
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

pub fn read_and_verify_db_file(db_key: &str) -> Result<()> {
    call_kdbx_context_mut_action(db_key, |ctx: &mut KdbxContext| {
        db::read_and_verify_db_file(&mut ctx.kdbx_file)
    })
}

// Called to generate random 32 bytes key and stored in an xml file (Version 2.0)
pub fn generate_key_file(key_file_name: &str) -> Result<()> {
    db::create_key_file(key_file_name)
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

