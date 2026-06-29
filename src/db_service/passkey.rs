// Passkey (WebAuthn) database operations — common across desktop and mobile.
//
// This module is compiled for **all** platforms (no `#[cfg]` gate).
// It replaces the passkey section that previously lived inside
// `db_service::browser_extension` (which is desktop-only).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::constants::entry_keyvalue_key::{
    KPEX_PASSKEY_CREDENTIAL_ID, KPEX_PASSKEY_PRIVATE_KEY_PEM, KPEX_PASSKEY_RELYING_PARTY,
    KPEX_PASSKEY_USERNAME, KPEX_PASSKEY_USER_HANDLE,
};
use crate::constants::entry_keyvalue_key::{TITLE, URL, USER_NAME};
use crate::constants::entry_type_uuid;
use crate::constants::standard_in_section_names::{LOGIN_DETAILS, PASSKEY_DETAILS};
use crate::db_content::{Group, KeepassFile};
use crate::db_service::{call_kdbx_context_mut_action, call_main_content_action, KdbxContext};
use crate::error::Error;
use crate::error::Result;
use crate::form_data::KeyValueData;
use crate::util;

// NOTE: To use these macros in this module, we need to import all fns used
// inside the macro expansion as well.
use crate::main_content_action;

// Tag applied to any entry that holds a passkey (new or updated). Lets the UI
// group/filter passkey-bearing entries.
const PASSKEY_TAG: &str = "Passkey";

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

// All data needed to sign a WebAuthn assertion.
#[derive(Debug, Serialize)]
pub struct PasskeyEntry {
    pub entry_uuid: String,
    pub credential_id_b64url: String,
    pub rp_id: String,
    pub username: String,
    pub user_handle_b64url: String,
    // PKCS#8 PEM-encoded EC P-256 private key (treated as protected).
    pub private_key_pem: String,
}

// Minimal summary shown in a passkey selection popup.
#[derive(Debug, Serialize)]
pub struct PasskeySummary {
    pub entry_uuid: String,
    pub db_key: String,
    pub credential_id_b64url: String,
    pub rp_id: String,
    pub username: String,
    pub user_handle_b64url: String,
}

// Describes where (and how) to persist a newly created passkey.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyStorageInfo {
    pub credential_id_b64url: String,
    pub private_key_pem: String,
    pub rp_id: String,
    pub rp_name: String,
    pub username: String,
    pub user_handle_b64url: String,
    pub origin: String,
    // If set, the passkey custom fields are added to this existing entry.
    pub entry_uuid: Option<Uuid>,
    // If `entry_uuid` is None, a new entry is created with this title.
    pub new_entry_name: Option<String>,
    // UUID of an existing group to place the new entry in.
    // Ignored when `entry_uuid` is Some.
    pub group_uuid: Option<Uuid>,
    // When set and `group_uuid` is None, a new sub-group with this name is
    // created under root before the entry is inserted.
    pub new_group_name: Option<String>,
}

// A group descriptor returned by [`get_db_groups`].
#[derive(Debug, Serialize)]
pub struct GroupInfo {
    pub group_uuid: String,
    pub name: String,
    pub parent_group_uuid: String,
}

// A minimal entry descriptor returned by [`get_group_entries`].
#[derive(Debug, Serialize)]
pub struct EntryBasicInfo {
    pub entry_uuid: String,
    pub title: String,
}

// Identifies the entry (and its group, type and tags) that a passkey was stored
// on, so callers can refresh/navigate the UI to the affected entry - including
// precise navigation when the UI groups entries by type or tag.
#[derive(Clone, Debug, Serialize)]
pub struct PasskeyStoreOutcome {
    pub entry_uuid: Uuid,
    pub group_uuid: Uuid,
    pub entry_type_uuid: Uuid,
    pub entry_type_name: String,
    pub tags: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

// #[cfg(test)]
use crate::db_content::{Entry, FieldDataType, KeyValue};

#[cfg(test)]
fn make_passkey_kv(key: &str, value: &str, protected: bool) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: value.to_string(),
        protected,
        data_type: FieldDataType::Text,
    }
}

#[cfg(test)]
fn write_passkey_fields(entry: &mut Entry, info: &PasskeyStorageInfo) {
    entry.entry_field.insert_key_value(make_passkey_kv(
        KPEX_PASSKEY_CREDENTIAL_ID,
        &info.credential_id_b64url,
        false,
    ));
    entry.entry_field.insert_key_value(make_passkey_kv(
        KPEX_PASSKEY_PRIVATE_KEY_PEM,
        &info.private_key_pem,
        true,
    ));
    entry.entry_field.insert_key_value(make_passkey_kv(
        KPEX_PASSKEY_RELYING_PARTY,
        &info.rp_id,
        false,
    ));
    entry.entry_field.insert_key_value(make_passkey_kv(
        KPEX_PASSKEY_USERNAME,
        &info.username,
        false,
    ));
    entry.entry_field.insert_key_value(make_passkey_kv(
        KPEX_PASSKEY_USER_HANDLE,
        &info.user_handle_b64url,
        false,
    ));
}

fn passkey_kvds(info: &PasskeyStorageInfo) -> Vec<KeyValueData> {
    vec![
        KeyValueData::new_simple(KPEX_PASSKEY_USERNAME, &info.username, false),
        KeyValueData::new_simple(KPEX_PASSKEY_RELYING_PARTY, &info.rp_id, false),
        KeyValueData::new_simple(KPEX_PASSKEY_USER_HANDLE, &info.user_handle_b64url, true),
        KeyValueData::new_simple(KPEX_PASSKEY_CREDENTIAL_ID, &info.credential_id_b64url, true),
        KeyValueData::new_simple(KPEX_PASSKEY_PRIVATE_KEY_PEM, &info.private_key_pem, true),
    ]
}

// Writes a passkey into the in-memory KDBX structure for `db_key`.
//
// Shared by `store_passkey_entry` (mobile) and `create_and_store_passkey` (desktop).
// Does NOT save the database to disk.
fn apply_passkey_storage(db_key: &str, info: &PasskeyStorageInfo) -> Result<PasskeyStoreOutcome> {
    match info.entry_uuid {
        Some(uuid) => {
            // Update an existing entry via EntryFormData so that
            // update_entry_from_form_data -> Entry::update() creates history.
            let mut form_data = super::get_entry_form_data_by_id(db_key, &uuid)?;
            // Tag the entry as a passkey holder (no-op if already tagged).
            form_data.add_tag(PASSKEY_TAG);
            // Capture the entry's group, type and tags before form_data is
            // consumed by update_entry_from_form_data. The tags now include the
            // Passkey tag so the UI can navigate/filter precisely.
            let outcome = PasskeyStoreOutcome {
                entry_uuid: uuid,
                group_uuid: form_data.group_uuid(),
                entry_type_uuid: form_data.entry_type_uuid(),
                entry_type_name: form_data.entry_type_name().to_string(),
                tags: form_data.tags().to_vec(),
            };
            // Note: we intentionally do NOT overwrite the existing UserName field
            // when adding a passkey to an existing entry, so a user-entered value
            // is preserved.
            // Replace all passkey custom fields.
            form_data.set_or_replace_section_fields(PASSKEY_DETAILS, passkey_kvds(info));
            super::update_entry_from_form_data(db_key, form_data)?;
            Ok(outcome)
        }
        None => {
            // Resolve or create the parent group.
            let parent_uuid: Uuid = if let Some(ref new_name) = info.new_group_name {
                let root_uuid =
                    main_content_action!(db_key, |k: &KeepassFile| Ok(k.root.root_uuid()))?;
                let mut new_group = Group::with_parent(&root_uuid);
                new_group.name = new_name.clone();
                let gid = new_group.uuid;
                super::insert_group(db_key, new_group)?;
                gid
            } else {
                match info.group_uuid {
                    Some(uuid) => uuid,
                    None => main_content_action!(db_key, |k: &KeepassFile| Ok(k.root.root_uuid()))?,
                }
            };

            let login_type_uuid = crate::build_uuid!(entry_type_uuid::LOGIN);
            let mut form_data =
                super::new_entry_form_data_by_id(db_key, &login_type_uuid, Some(&parent_uuid))?;
            let title = info
                .new_entry_name
                .clone()
                .unwrap_or_else(|| info.rp_name.clone());
            form_data.set_title(title);
            form_data.set_field_value_in_section(LOGIN_DETAILS, USER_NAME, &info.username);
            form_data.set_field_value_in_section(
                LOGIN_DETAILS,
                URL,
                &format!("https://{}", &info.rp_id),
            );
            form_data.set_or_replace_section_fields(PASSKEY_DETAILS, passkey_kvds(info));
            // Tag the new entry as a passkey holder.
            form_data.add_tag(PASSKEY_TAG);
            // Capture identifying fields before form_data is consumed by insert.
            let outcome = PasskeyStoreOutcome {
                entry_uuid: form_data.uuid(),
                group_uuid: parent_uuid,
                entry_type_uuid: form_data.entry_type_uuid(),
                entry_type_name: form_data.entry_type_name().to_string(),
                tags: form_data.tags().to_vec(),
            };
            super::insert_entry_from_form_data(db_key, form_data)?;
            Ok(outcome)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

// Returns the human-readable name of the database identified by `db_key`.
pub fn get_db_name(db_key: &str) -> Result<String> {
    let action = |k: &KeepassFile| Ok(k.meta.database_name().clone());
    main_content_action!(db_key, action, no_times)
}

// Returns all user-visible groups in the database, sorted by name.
// Root group is included. Recycle bin group and any groups deleted into trash are excluded.
pub fn get_db_groups(db_key: &str) -> Result<Vec<GroupInfo>> {
    let action = |k: &KeepassFile| {
        let deleted_uuids: std::collections::HashSet<Uuid> =
            k.deleted_group_uuids().into_iter().collect();
        let mut groups: Vec<GroupInfo> = k
            .root
            .get_all_groups(true)
            .into_iter()
            .filter(|g| !deleted_uuids.contains(&g.uuid))
            .map(|g| GroupInfo {
                group_uuid: g.uuid.to_string(),
                name: g.name.clone(),
                parent_group_uuid: g.parent_group_uuid.to_string(),
            })
            .collect();
        groups.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        Ok(groups)
    };
    main_content_action!(db_key, action, no_times)
}

// Returns the active Login-type entries that belong directly to `group_uuid`,
// sorted by title. Only Login entries are returned because passkey custom fields
// are defined for the Login entry type only - the user picks a target entry to
// add a passkey to.
pub fn get_group_entries(db_key: &str, group_uuid: &Uuid) -> Result<Vec<EntryBasicInfo>> {
    let login_type_uuid = crate::build_uuid!(entry_type_uuid::LOGIN);
    let action = |k: &KeepassFile| {
        let group = k
            .root
            .group_by_id(group_uuid)
            .ok_or_else(|| Error::NotFound(format!("Group {} not found", group_uuid)))?;
        let mut entries: Vec<EntryBasicInfo> = group
            .entry_uuids
            .iter()
            .filter_map(|entry_uuid| {
                let entry = k.root.entry_by_id(entry_uuid)?;
                if entry.entry_field.entry_type.uuid != login_type_uuid {
                    return None;
                }
                let title = entry.find_kv_field_value(TITLE).unwrap_or_default();
                Some(EntryBasicInfo {
                    entry_uuid: entry_uuid.to_string(),
                    title,
                })
            })
            .collect();
        entries.sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase()));
        Ok(entries)
    };
    main_content_action!(db_key, action, no_times)
}

// Stores a newly created passkey in KDBX (in-memory only; does not save to disk).
//
// If `info.entry_uuid` is `Some`, the existing entry is updated (with history).
// Otherwise a new Login entry is created.
pub fn store_passkey_entry(db_key: &str, info: PasskeyStorageInfo) -> Result<PasskeyStoreOutcome> {
    apply_passkey_storage(db_key, &info)
}

// Passkey credentials are stored only on Login-type entries: the PASSKEY_DETAILS
// section is defined on Login alone, and registration enforces Login (new entries
// are created as Login; get_group_entries offers only Login targets). The read
// paths below therefore require Login type explicitly, so a non-Login entry that
// was hand-edited to carry KPEX_PASSKEY_* custom fields is never treated as a
// passkey source.
fn is_login_type_entry(entry: &Entry) -> bool {
    entry.entry_field.entry_type.uuid == crate::build_uuid!(entry_type_uuid::LOGIN)
}

// Searches all provided databases for passkey entries matching `rp_id`.
// If `allow_credential_ids` is non-empty, further filters by credential ID.
pub fn find_matching_passkeys(
    enabled_db_keys: &[String],
    rp_id: &str,
    allow_credential_ids: &[String],
) -> Result<Vec<PasskeySummary>> {
    let mut summaries = Vec::new();

    for db_key in enabled_db_keys {
        let action = |k: &KeepassFile| {
            let matches: Vec<PasskeySummary> = k
                .collect_all_active_entries()
                .into_iter()
                .filter_map(|entry| {
                    if !is_login_type_entry(entry) {
                        return None;
                    }
                    let stored_rp_id = entry.find_kv_field_value(KPEX_PASSKEY_RELYING_PARTY)?;
                    if stored_rp_id != rp_id {
                        return None;
                    }
                    let cred_id = entry.find_kv_field_value(KPEX_PASSKEY_CREDENTIAL_ID)?;
                    if !allow_credential_ids.is_empty() && !allow_credential_ids.contains(&cred_id)
                    {
                        return None;
                    }
                    let username = entry
                        .find_kv_field_value(KPEX_PASSKEY_USERNAME)
                        .unwrap_or_default();
                    let user_handle = entry
                        .find_kv_field_value(KPEX_PASSKEY_USER_HANDLE)
                        .unwrap_or_default();
                    Some(PasskeySummary {
                        entry_uuid: entry.get_uuid().to_string(),
                        db_key: db_key.clone(),
                        credential_id_b64url: cred_id,
                        rp_id: stored_rp_id,
                        username,
                        user_handle_b64url: user_handle,
                    })
                })
                .collect();
            Ok(matches)
        };
        if let Ok(mut db_matches) = main_content_action!(db_key, action, no_times) {
            summaries.append(&mut db_matches);
        }
    }

    Ok(summaries)
}

// Returns all passkey entries across the supplied databases — used by the iOS
// credential-identity registration step (no rpId or credentialId filter).
pub fn get_all_passkeys(db_keys: &[String]) -> Result<Vec<PasskeySummary>> {
    let mut summaries = Vec::new();
    for db_key in db_keys {
        let action = |k: &KeepassFile| {
            let matches: Vec<PasskeySummary> = k
                .collect_all_active_entries()
                .into_iter()
                .filter_map(|entry| {
                    if !is_login_type_entry(entry) {
                        return None;
                    }
                    let rp_id = entry.find_kv_field_value(KPEX_PASSKEY_RELYING_PARTY)?;
                    let cred_id = entry.find_kv_field_value(KPEX_PASSKEY_CREDENTIAL_ID)?;
                    let username = entry
                        .find_kv_field_value(KPEX_PASSKEY_USERNAME)
                        .unwrap_or_default();
                    let user_handle = entry
                        .find_kv_field_value(KPEX_PASSKEY_USER_HANDLE)
                        .unwrap_or_default();
                    Some(PasskeySummary {
                        entry_uuid: entry.get_uuid().to_string(),
                        db_key: db_key.clone(),
                        credential_id_b64url: cred_id,
                        rp_id,
                        username,
                        user_handle_b64url: user_handle,
                    })
                })
                .collect();
            Ok(matches)
        };
        if let Ok(mut db_matches) = main_content_action!(db_key, action, no_times) {
            summaries.append(&mut db_matches);
        }
    }
    Ok(summaries)
}

// Returns full private-key material needed to sign a WebAuthn assertion.
pub fn get_passkey_for_assertion(db_key: &str, entry_uuid: &Uuid) -> Result<PasskeyEntry> {
    let action = |k: &KeepassFile| {
        let entry = k.root.entry_by_id(entry_uuid).ok_or_else(|| {
            Error::NotFound(format!(
                "Entry {} not found for passkey assertion",
                entry_uuid
            ))
        })?;

        if !is_login_type_entry(entry) {
            return Err(Error::NotFound(format!(
                "Entry {} is not a Login entry and cannot hold a passkey",
                entry_uuid
            )));
        }

        let credential_id = entry
            .find_kv_field_value(KPEX_PASSKEY_CREDENTIAL_ID)
            .ok_or_else(|| Error::NotFound("KPEX_PASSKEY_CREDENTIAL_ID not found".into()))?;

        let private_key_pem = entry
            .find_kv_field_value(KPEX_PASSKEY_PRIVATE_KEY_PEM)
            .ok_or_else(|| Error::NotFound("KPEX_PASSKEY_PRIVATE_KEY_PEM not found".into()))?;

        let rp_id = entry
            .find_kv_field_value(KPEX_PASSKEY_RELYING_PARTY)
            .ok_or_else(|| Error::NotFound("KPEX_PASSKEY_RELYING_PARTY not found".into()))?;

        let username = entry
            .find_kv_field_value(KPEX_PASSKEY_USERNAME)
            .unwrap_or_default();

        let user_handle = entry
            .find_kv_field_value(KPEX_PASSKEY_USER_HANDLE)
            .unwrap_or_default();

        Ok(PasskeyEntry {
            entry_uuid: entry_uuid.to_string(),
            credential_id_b64url: credential_id,
            rp_id,
            username,
            user_handle_b64url: user_handle,
            private_key_pem,
        })
    };

    main_content_action!(db_key, action)
}

// Creates or updates a passkey entry via the form-data API, then saves the
// database to disk (with backup).
//
// This is the preferred high-level entry point for passkey storage on desktop.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn create_and_store_passkey(
    db_key: &str,
    info: PasskeyStorageInfo,
    backup_file_name: Option<&str>,
) -> Result<PasskeyStoreOutcome> {
    let outcome = apply_passkey_storage(db_key, &info)?;
    super::save_kdbx_with_backup(db_key, backup_file_name, false)?;
    Ok(outcome)
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use uuid::Uuid;

    use crate::db::{KeyStoreOperation, KeyStoreService, NewDatabase};
    use crate::db_service as kp_service;
    use crate::error::Result as KpResult;

    use super::*;

    #[derive(Default)]
    struct InMemoryKeyStore {
        store: HashMap<String, Vec<u8>>,
    }

    impl KeyStoreService for InMemoryKeyStore {
        fn store_key(&mut self, db_key: &str, val: Vec<u8>) -> KpResult<()> {
            self.store.insert(db_key.to_string(), val);
            Ok(())
        }
        fn get_key(&self, db_key: &str) -> Option<Vec<u8>> {
            self.store.get(db_key).cloned()
        }
        fn delete_key(&mut self, db_key: &str) -> KpResult<()> {
            self.store.remove(db_key);
            Ok(())
        }
        fn copy_key(&mut self, src: &str, dst: &str) -> KpResult<()> {
            if let Some(v) = self.store.get(src).cloned() {
                self.store.insert(dst.to_string(), v);
            }
            Ok(())
        }
    }

    fn init_key_store() {
        let kss = Arc::new(Mutex::new(InMemoryKeyStore::default()));
        KeyStoreOperation::init(kss);
    }

    fn setup_test_db(db_key: &str, db_name: &str) {
        init_key_store();
        let ndb = NewDatabase {
            database_name: db_name.to_string(),
            database_file_name: db_key.to_string(),
            ..NewDatabase::default()
        };
        let kdbx_file = ndb.create().expect("NewDatabase::create should succeed");
        kp_service::insert_kdbx_for_test(kdbx_file);
    }

    fn teardown_test_db(db_key: &str) {
        let _ = kp_service::close_kdbx(db_key);
    }

    fn make_test_passkey_info(
        db_key_prefix: &str,
        rp_id: &str,
        cred_id: &str,
        username: &str,
    ) -> PasskeyStorageInfo {
        PasskeyStorageInfo {
            credential_id_b64url: cred_id.to_string(),
            private_key_pem: "-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----"
                .to_string(),
            rp_id: rp_id.to_string(),
            rp_name: rp_id.to_string(),
            username: username.to_string(),
            user_handle_b64url: "dXNlcg".to_string(),
            origin: format!("https://{}", rp_id),
            entry_uuid: None,
            new_entry_name: Some(format!("{}-{}", db_key_prefix, rp_id)),
            group_uuid: None,
            new_group_name: None,
        }
    }

    #[test]
    fn test_make_passkey_kv_protected_flag() {
        let kv = make_passkey_kv(KPEX_PASSKEY_PRIVATE_KEY_PEM, "secret-pem", true);
        assert_eq!(kv.key, KPEX_PASSKEY_PRIVATE_KEY_PEM);
        assert_eq!(kv.value, "secret-pem");
        assert!(kv.protected, "private key field must be protected");
    }

    #[test]
    fn test_make_passkey_kv_unprotected_flag() {
        let kv = make_passkey_kv(KPEX_PASSKEY_CREDENTIAL_ID, "cred-abc", false);
        assert_eq!(kv.key, KPEX_PASSKEY_CREDENTIAL_ID);
        assert_eq!(kv.value, "cred-abc");
        assert!(!kv.protected, "credential-id field must not be protected");
    }

    #[test]
    fn test_write_passkey_fields_sets_all_five_fields() {
        use crate::db_content::Entry;

        let mut entry = Entry::new_login_entry(None);
        let info = PasskeyStorageInfo {
            credential_id_b64url: "cred-id-xyz".to_string(),
            private_key_pem: "pem-content".to_string(),
            rp_id: "example.com".to_string(),
            rp_name: "Example".to_string(),
            username: "alice@example.com".to_string(),
            user_handle_b64url: "dXNlcg".to_string(),
            origin: "https://example.com".to_string(),
            entry_uuid: None,
            new_entry_name: None,
            group_uuid: None,
            new_group_name: None,
        };

        write_passkey_fields(&mut entry, &info);

        assert_eq!(
            entry
                .find_kv_field_value(KPEX_PASSKEY_CREDENTIAL_ID)
                .as_deref(),
            Some("cred-id-xyz")
        );
        assert_eq!(
            entry
                .find_kv_field_value(KPEX_PASSKEY_PRIVATE_KEY_PEM)
                .as_deref(),
            Some("pem-content")
        );
        assert_eq!(
            entry
                .find_kv_field_value(KPEX_PASSKEY_RELYING_PARTY)
                .as_deref(),
            Some("example.com")
        );
        assert_eq!(
            entry.find_kv_field_value(KPEX_PASSKEY_USERNAME).as_deref(),
            Some("alice@example.com")
        );
        assert_eq!(
            entry
                .find_kv_field_value(KPEX_PASSKEY_USER_HANDLE)
                .as_deref(),
            Some("dXNlcg")
        );
    }

    #[test]
    fn test_store_passkey_new_entry_created_and_findable() {
        let db_key = "pk_test_new_entry";
        setup_test_db(db_key, "PasskeyTestDB");

        let info = make_test_passkey_info(db_key, "example.com", "cred-new-001", "alice");
        store_passkey_entry(db_key, info).expect("store_passkey_entry should succeed");

        let db_keys = vec![db_key.to_string()];
        let summaries = find_matching_passkeys(&db_keys, "example.com", &[]).unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].credential_id_b64url, "cred-new-001");
        assert_eq!(summaries[0].username, "alice");
        assert_eq!(summaries[0].rp_id, "example.com");
        assert_eq!(summaries[0].db_key, db_key);

        teardown_test_db(db_key);
    }

    #[test]
    fn test_store_passkey_new_entry_uses_rp_name_as_title_fallback() {
        let db_key = "pk_test_rp_name_title";
        setup_test_db(db_key, "PasskeyTestDB");

        let info = PasskeyStorageInfo {
            credential_id_b64url: "cred-fallback".to_string(),
            private_key_pem: "pem".to_string(),
            rp_id: "fallback.com".to_string(),
            rp_name: "Fallback Site".to_string(),
            username: "user".to_string(),
            user_handle_b64url: "h".to_string(),
            origin: "https://fallback.com".to_string(),
            entry_uuid: None,
            new_entry_name: None,
            group_uuid: None,
            new_group_name: None,
        };
        store_passkey_entry(db_key, info).expect("store_passkey_entry should succeed");

        let db_keys = vec![db_key.to_string()];
        let summaries = find_matching_passkeys(&db_keys, "fallback.com", &[]).unwrap();
        assert_eq!(summaries.len(), 1);

        teardown_test_db(db_key);
    }

    #[test]
    fn test_store_passkey_existing_entry_updated() {
        use crate::constants::entry_keyvalue_key::TITLE;
        use crate::db_content::Entry;

        let db_key = "pk_test_existing_entry";
        setup_test_db(db_key, "PasskeyTestDB");

        let entry_uuid: Uuid = kp_service::call_main_content_mut_action(db_key, |k| {
            let mut entry = Entry::new_login_entry(Some(&k.root.root_uuid()));
            entry.entry_field.update_value(TITLE, "Pre-existing Login");
            let uuid = entry.get_uuid();
            k.insert_entry(entry)?;
            Ok(uuid)
        })
        .expect("insert pre-existing entry should succeed");

        let info = PasskeyStorageInfo {
            credential_id_b64url: "cred-existing-999".to_string(),
            private_key_pem: "pem-key".to_string(),
            rp_id: "existing.com".to_string(),
            rp_name: "Existing Site".to_string(),
            username: "bob@existing.com".to_string(),
            user_handle_b64url: "Ym9i".to_string(),
            origin: "https://existing.com".to_string(),
            entry_uuid: Some(entry_uuid),
            new_entry_name: None,
            group_uuid: None,
            new_group_name: None,
        };
        store_passkey_entry(db_key, info).expect("store_passkey_entry (existing) should succeed");

        let passkey = get_passkey_for_assertion(db_key, &entry_uuid)
            .expect("get_passkey_for_assertion should succeed");
        assert_eq!(passkey.credential_id_b64url, "cred-existing-999");
        assert_eq!(passkey.rp_id, "existing.com");
        assert_eq!(passkey.username, "bob@existing.com");
        assert_eq!(passkey.entry_uuid, entry_uuid.to_string());

        teardown_test_db(db_key);
    }

    #[test]
    fn test_store_passkey_existing_entry_preserves_username_and_adds_tag() {
        use crate::constants::entry_keyvalue_key::{TITLE, USER_NAME};
        use crate::db_content::Entry;

        let db_key = "pk_test_preserve_username";
        setup_test_db(db_key, "PasskeyTestDB");

        let entry_uuid: Uuid = kp_service::call_main_content_mut_action(db_key, |k| {
            let mut entry = Entry::new_login_entry(Some(&k.root.root_uuid()));
            entry.entry_field.update_value(TITLE, "Has Username");
            entry.entry_field.update_value(USER_NAME, "original-user");
            let uuid = entry.get_uuid();
            k.insert_entry(entry)?;
            Ok(uuid)
        })
        .expect("insert pre-existing entry should succeed");

        let info = PasskeyStorageInfo {
            credential_id_b64url: "cred-preserve".to_string(),
            private_key_pem: "pem".to_string(),
            rp_id: "preserve.com".to_string(),
            rp_name: "Preserve".to_string(),
            // A different username from the one already on the entry.
            username: "passkey-user@preserve.com".to_string(),
            user_handle_b64url: "aGFuZGxl".to_string(),
            origin: "https://preserve.com".to_string(),
            entry_uuid: Some(entry_uuid),
            new_entry_name: None,
            group_uuid: None,
            new_group_name: None,
        };
        let outcome = store_passkey_entry(db_key, info).expect("store should succeed");

        // The outcome's tags include the Passkey tag for UI navigation.
        assert!(outcome.tags.iter().any(|t| t == "Passkey"));

        kp_service::call_main_content_mut_action(db_key, |k| {
            let entry = k.root.entry_by_id(&entry_uuid).unwrap();
            // The existing UserName must NOT be overwritten by the passkey username.
            assert_eq!(
                entry.find_kv_field_value(USER_NAME).as_deref(),
                Some("original-user")
            );
            // The Passkey tag is applied.
            assert!(entry.tags.split(';').any(|t| t == "Passkey"));
            Ok(())
        })
        .unwrap();

        teardown_test_db(db_key);
    }

    #[test]
    fn test_store_passkey_new_entry_has_passkey_tag() {
        let db_key = "pk_test_new_entry_tag";
        setup_test_db(db_key, "PasskeyTestDB");

        let info = make_test_passkey_info(db_key, "tagged.com", "cred-tagged", "alice");
        let outcome = store_passkey_entry(db_key, info).expect("store should succeed");

        assert!(outcome.tags.iter().any(|t| t == "Passkey"));

        let entry_uuid = Uuid::parse_str(&outcome.entry_uuid.to_string()).unwrap();
        kp_service::call_main_content_mut_action(db_key, |k| {
            let entry = k.root.entry_by_id(&entry_uuid).unwrap();
            assert!(entry.tags.split(';').any(|t| t == "Passkey"));
            Ok(())
        })
        .unwrap();

        teardown_test_db(db_key);
    }

    #[test]
    fn test_get_group_entries_returns_only_login_entries() {
        use crate::constants::entry_keyvalue_key::TITLE;
        use crate::constants::entry_type_uuid;
        use crate::db_content::Entry;

        let db_key = "pk_test_login_only";
        setup_test_db(db_key, "PasskeyTestDB");

        let (group_uuid, _login_uuid): (Uuid, Uuid) =
            kp_service::call_main_content_mut_action(db_key, |k| {
                let root_uuid = k.root.root_uuid();

                let mut login = Entry::new_login_entry(Some(&root_uuid));
                login.entry_field.update_value(TITLE, "A Login Entry");
                let login_uuid = login.get_uuid();
                k.insert_entry(login)?;

                // A non-Login entry (Credit/Debit Card) in the same (root) group.
                let cc_type_uuid = crate::build_uuid!(entry_type_uuid::CREDIT_DEBIT_CARD);
                let mut card =
                    Entry::new_blank_entry_by_type_id(&cc_type_uuid, None, Some(&root_uuid));
                card.entry_field.update_value(TITLE, "A Card Entry");
                k.insert_entry(card)?;

                Ok((root_uuid, login_uuid))
            })
            .expect("inserting test entries should succeed");

        let entries = get_group_entries(db_key, &group_uuid).expect("get_group_entries should work");
        assert_eq!(entries.len(), 1, "only the Login entry should be returned");
        assert_eq!(entries[0].title, "A Login Entry");

        teardown_test_db(db_key);
    }

    #[test]
    fn test_store_passkey_nonexistent_entry_uuid_returns_error() {
        let db_key = "pk_test_bad_uuid";
        setup_test_db(db_key, "PasskeyTestDB");

        let info = PasskeyStorageInfo {
            credential_id_b64url: "cred".to_string(),
            private_key_pem: "pem".to_string(),
            rp_id: "x.com".to_string(),
            rp_name: "X".to_string(),
            username: "u".to_string(),
            user_handle_b64url: "h".to_string(),
            origin: "https://x.com".to_string(),
            entry_uuid: Some(Uuid::new_v4()),
            new_entry_name: None,
            group_uuid: None,
            new_group_name: None,
        };
        let result = store_passkey_entry(db_key, info);
        assert!(result.is_err(), "should fail for a nonexistent entry UUID");

        teardown_test_db(db_key);
    }

    #[test]
    fn test_find_matching_passkeys_filters_by_rp_id() {
        let db_key = "pk_test_filter_rp";
        setup_test_db(db_key, "PasskeyTestDB");

        store_passkey_entry(
            db_key,
            make_test_passkey_info(db_key, "site-a.com", "cred-a", "alice"),
        )
        .unwrap();
        store_passkey_entry(
            db_key,
            make_test_passkey_info(db_key, "site-b.com", "cred-b", "bob"),
        )
        .unwrap();

        let db_keys = vec![db_key.to_string()];

        let results_a = find_matching_passkeys(&db_keys, "site-a.com", &[]).unwrap();
        assert_eq!(results_a.len(), 1);
        assert_eq!(results_a[0].rp_id, "site-a.com");

        let results_b = find_matching_passkeys(&db_keys, "site-b.com", &[]).unwrap();
        assert_eq!(results_b.len(), 1);
        assert_eq!(results_b[0].rp_id, "site-b.com");

        let results_none = find_matching_passkeys(&db_keys, "site-c.com", &[]).unwrap();
        assert!(results_none.is_empty());

        teardown_test_db(db_key);
    }

    #[test]
    fn test_find_matching_passkeys_filters_by_credential_id() {
        let db_key = "pk_test_filter_cred";
        setup_test_db(db_key, "PasskeyTestDB");

        for (cred_id, user) in [("cred-x", "x-user"), ("cred-y", "y-user")] {
            store_passkey_entry(
                db_key,
                make_test_passkey_info(db_key, "multi.com", cred_id, user),
            )
            .unwrap();
        }

        let db_keys = vec![db_key.to_string()];

        let all = find_matching_passkeys(&db_keys, "multi.com", &[]).unwrap();
        assert_eq!(all.len(), 2);

        let filtered =
            find_matching_passkeys(&db_keys, "multi.com", &["cred-x".to_string()]).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].credential_id_b64url, "cred-x");
        assert_eq!(filtered[0].username, "x-user");

        teardown_test_db(db_key);
    }

    #[test]
    fn test_find_matching_passkeys_ignores_non_login_entry_with_passkey_fields() {
        use crate::constants::entry_keyvalue_key::TITLE;
        use crate::constants::entry_type_uuid;
        use crate::db_content::Entry;

        let db_key = "pk_test_non_login_guard";
        setup_test_db(db_key, "PasskeyTestDB");

        // Hand-craft a Credit/Debit Card entry carrying passkey custom fields with
        // the exact KPEX_* key names (as if a user added them manually). The guard
        // in find_matching_passkeys must still exclude it — only Login entries are
        // valid passkey sources.
        kp_service::call_main_content_mut_action(db_key, |k| {
            let root_uuid = k.root.root_uuid();
            let cc_type_uuid = crate::build_uuid!(entry_type_uuid::CREDIT_DEBIT_CARD);
            let mut card =
                Entry::new_blank_entry_by_type_id(&cc_type_uuid, None, Some(&root_uuid));
            card.entry_field.update_value(TITLE, "Ghost Card");
            card.entry_field.insert_key_value(make_passkey_kv(
                KPEX_PASSKEY_RELYING_PARTY,
                "ghost.com",
                false,
            ));
            card.entry_field.insert_key_value(make_passkey_kv(
                KPEX_PASSKEY_CREDENTIAL_ID,
                "ghost-cred",
                false,
            ));
            k.insert_entry(card)?;
            Ok(())
        })
        .expect("inserting the card entry should succeed");

        let db_keys = vec![db_key.to_string()];
        let results = find_matching_passkeys(&db_keys, "ghost.com", &[]).unwrap();
        assert!(
            results.is_empty(),
            "a non-Login entry with passkey fields must not be returned"
        );

        teardown_test_db(db_key);
    }

    #[test]
    fn test_find_matching_passkeys_empty_db_list_returns_empty() {
        let results = find_matching_passkeys(&[], "example.com", &[]).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_get_passkey_for_assertion_not_found() {
        let db_key = "pk_test_assertion_not_found";
        setup_test_db(db_key, "PasskeyTestDB");

        let result = get_passkey_for_assertion(db_key, &Uuid::new_v4());
        assert!(
            result.is_err(),
            "should fail when entry UUID does not exist"
        );

        teardown_test_db(db_key);
    }

    #[test]
    fn test_get_db_name_returns_correct_name() {
        let db_key = "pk_test_db_name";
        setup_test_db(db_key, "MyPasskeyDatabase");

        let name = get_db_name(db_key).expect("get_db_name should succeed");
        assert_eq!(name, "MyPasskeyDatabase");

        teardown_test_db(db_key);
    }
}
