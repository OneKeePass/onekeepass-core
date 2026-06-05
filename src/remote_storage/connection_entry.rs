use serde::Serialize;
use uuid::Uuid;

use crate::constants::{entry_keyvalue_key, entry_type_uuid};
use crate::db_content::KeepassFile;
use crate::db_service::{
    all_kdbx_cache_keys, call_kdbx_context_action, call_main_content_action, EntryFormData,
    KdbxContext,
};
use crate::error::Result;

// Locates a remote-connection entry (e.g. REMOTE_CONNECTION_SFTP /
// REMOTE_CONNECTION_WEBDAV) across the currently open kdbx databases.
// The remote-storage resolver passes the connection id (= entry uuid) and
// the expected entry-type uuid; the first open db that holds a matching
// entry wins.
pub struct RemoteConnectionEntry {
    pub db_key: String,
    pub form_data: EntryFormData,
}

// Lightweight summary of a remote-connection entry surfaced by the connection
// picker. Powers the merged picker that lists blob-stored connections together
// with kdbx-entry-stored ones.
#[derive(Debug, Serialize, Clone)]
pub struct RemoteConnectionEntrySummary {
    pub db_key: String,
    pub connection_id: Uuid,
    pub title: String,
    pub entry_type_uuid: Uuid,
    // Host:port (SFTP) or root URL (WebDAV) - displayed as secondary text
    // in the picker so the user can tell connections apart.
    pub connection_info: String,
    pub icon_id: i32,
    pub custom_icon_uuid: Option<Uuid>,
}

// Enumerates every entry across all currently open kdbx databases whose
// entry-type matches the given uuid (typically REMOTE_CONNECTION_SFTP or
// REMOTE_CONNECTION_WEBDAV). Used by the connection picker to merge
// kdbx-source connections with the legacy blob source, and by the migration
// command to identify destination dbs.
pub fn list_remote_connection_entries(entry_type_uuid: &Uuid) -> Vec<RemoteConnectionEntrySummary> {
    let target_type = *entry_type_uuid;
    let sftp_type = uuid::Builder::from_slice(entry_type_uuid::REMOTE_CONNECTION_SFTP)
        .ok()
        .map(|b| b.into_uuid());
    let webdav_type = uuid::Builder::from_slice(entry_type_uuid::REMOTE_CONNECTION_WEBDAV)
        .ok()
        .map(|b| b.into_uuid());
    let is_sftp = sftp_type == Some(target_type);
    let is_webdav = webdav_type == Some(target_type);

    let db_keys = all_kdbx_cache_keys().unwrap_or_default();
    let mut out: Vec<RemoteConnectionEntrySummary> = Vec::new();

    for db_key in db_keys {
        let key_clone = db_key.clone();
        let collected: Result<Vec<RemoteConnectionEntrySummary>> =
            call_main_content_action(&db_key, move |k: &KeepassFile| {
                let mut local: Vec<RemoteConnectionEntrySummary> = Vec::new();
                for entry in k.root.all_entries().values() {
                    if entry.entry_field.entry_type.uuid != target_type {
                        continue;
                    }
                    let title = entry
                        .entry_field
                        .find_key_value(entry_keyvalue_key::TITLE)
                        .map(|kv| kv.value.clone())
                        .unwrap_or_default();
                    let connection_info = if is_sftp {
                        let host = entry
                            .entry_field
                            .find_key_value(entry_keyvalue_key::HOST)
                            .map(|kv| kv.value.trim().to_string())
                            .unwrap_or_default();
                        let port = entry
                            .entry_field
                            .find_key_value(entry_keyvalue_key::PORT)
                            .map(|kv| kv.value.trim().to_string())
                            .unwrap_or_default();
                        if port.is_empty() {
                            host
                        } else if host.is_empty() {
                            String::new()
                        } else {
                            format!("{}:{}", host, port)
                        }
                    } else if is_webdav {
                        entry
                            .entry_field
                            .find_key_value(entry_keyvalue_key::URL)
                            .map(|kv| kv.value.trim().to_string())
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };
                    local.push(RemoteConnectionEntrySummary {
                        db_key: key_clone.clone(),
                        connection_id: entry.get_uuid(),
                        title,
                        entry_type_uuid: target_type,
                        connection_info,
                        icon_id: entry.icon_id,
                        custom_icon_uuid: entry.custom_icon_uuid,
                    });
                }
                Ok(local)
            });

        if let Ok(found) = collected {
            out.extend(found);
        }
    }

    out
}

// Returns the first binary attachment (name + raw bytes) on the given entry,
// or None if the entry has no attachments. The remote-storage resolver uses
// this to fetch the SFTP private key from a REMOTE_CONNECTION_SFTP entry,
// which by convention carries the private key as its only attachment.
pub fn entry_first_attachment(
    db_key: &str,
    entry_uuid: &Uuid,
) -> Result<Option<(String, Vec<u8>)>> {
    let target = *entry_uuid;
    let metadata: Option<(String, crate::db_content::AttachmentHashValue)> =
        call_main_content_action(db_key, move |k: &KeepassFile| {
            let info = k.root.entry_by_id(&target).and_then(|entry| {
                entry
                    .binary_key_values
                    .first()
                    .map(|bkv| (bkv.key.clone(), bkv.data_hash))
            });
            Ok(info)
        })?;

    let Some((name, data_hash)) = metadata else {
        return Ok(None);
    };

    let bytes = call_kdbx_context_action(db_key, |ctx: &KdbxContext| {
        Ok(ctx.kdbx_file.get_bytes_content(&data_hash))
    })?;

    Ok(bytes.map(|b| (name, b)))
}

pub fn find_remote_connection_entry(
    entry_uuid: &Uuid,
    entry_type_uuid: &Uuid,
) -> Option<RemoteConnectionEntry> {
    let target_entry = *entry_uuid;
    let target_type = *entry_type_uuid;

    let db_keys = match all_kdbx_cache_keys() {
        Ok(keys) => keys,
        Err(_) => return None,
    };

    for db_key in db_keys {
        // no_times: a finder shouldn't touch last_read_time on every open db
        let lookup: Result<Option<EntryFormData>> =
            call_main_content_action(&db_key, move |k: &KeepassFile| {
                if let Some(entry) = k.root.entry_by_id(&target_entry) {
                    if entry.entry_field.entry_type.uuid == target_type {
                        return Ok(Some(EntryFormData::place_holder_resolved_form_data(
                            &k.root, entry,
                        )));
                    }
                }
                Ok(None)
            });

        if let Ok(Some(form_data)) = lookup {
            return Some(RemoteConnectionEntry { db_key, form_data });
        }
    }
    None
}
