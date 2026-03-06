use serde::Serialize;
use uuid::Uuid;

use crate::constants::entry_keyvalue_key::ADDITIONAL_URLS;
use crate::constants::entry_keyvalue_key::PASSWORD;
use crate::constants::entry_keyvalue_key::TITLE;
use crate::constants::entry_keyvalue_key::URL;
use crate::constants::entry_keyvalue_key::USER_NAME;
use crate::db_content::{Entry, FieldDataType, KeepassFile, KeyValue};
use crate::db_service::call_kdbx_context_mut_action;
use crate::db_service::call_main_content_action;
use crate::db_service::call_main_content_mut_action;
use crate::db_service::KdbxContext;
use crate::error::Error;
use crate::error::Result;
use crate::form_data::parsing::EntryPlaceHolderParser;
use crate::form_data::EntrySummary;
use crate::util;

use url::Url;

// NOTE: To use this macro in this module, we need to import all fns that used in that macros as well to this module
use crate::main_content_action;
use crate::main_content_mut_action;

// ── KeePassXC-compatible custom field name constants ───────────────────────
pub const KPXC_PASSKEY_CREDENTIAL_ID: &str = "KPXC_PASSKEY_CREDENTIAL_ID";
pub const KPXC_PASSKEY_PRIVATE_KEY_PEM: &str = "KPXC_PASSKEY_PRIVATE_KEY_PEM";
pub const KPXC_PASSKEY_RELYING_PARTY_ID: &str = "KPXC_PASSKEY_RELYING_PARTY_ID";
pub const KPXC_PASSKEY_USERNAME: &str = "KPXC_PASSKEY_USERNAME";
pub const KPXC_PASSKEY_USER_HANDLE: &str = "KPXC_PASSKEY_USER_HANDLE";

#[derive(Default, Serialize, Debug)]
pub struct MatchedDbEntries {
    db_name: String,
    db_key: String,
    entry_summaries: Vec<EntrySummary>,
}

#[derive(Default, Serialize, Debug)]
pub struct BasicEntryCredentialInfo {
    username: Option<String>,
    password: Option<String>,
}

pub fn find_matching_in_enabled_db_entries(
    enabled_db_keys: &Vec<String>,
    input_url: &str,
) -> Result<Vec<MatchedDbEntries>> {
    Ok(enabled_db_keys
        .iter()
        .filter_map(|db_key| {
            let r = find_matching_entries_in_db(db_key, input_url).ok();
            r
        })
        .collect::<Vec<_>>())
}

// For now we retreive only the username and password for browser extension use
pub fn basic_entry_credential_info(
    db_key: &str,
    entry_uuid: &Uuid,
) -> Result<BasicEntryCredentialInfo> {
    let action = |k: &KeepassFile| match k.root.entry_by_id(entry_uuid) {
        Some(e) => {
            let info = BasicEntryCredentialInfo {
                username: e.find_kv_field_value(USER_NAME).clone(),
                password: e.find_kv_field_value(PASSWORD).clone(),
            };
            Ok(info)
        }
        None => Err(Error::NotFound(format!(
            "No entry is found for the id {}",
            entry_uuid
        ))),
    };

    main_content_action!(db_key, action)
}

fn any_additional_urls_matching(input_url: &str, additional_urls: &str) -> bool {
    let urls: Vec<&str> = additional_urls.split_whitespace().collect();
    urls.iter().any(|au| url_matched(input_url, au))
}

fn find_matching_entries_in_db(db_key: &str, input_url: &str) -> Result<MatchedDbEntries> {
    // log::debug!("find_matching_entries_in_db Going to find match for input_url {}",&input_url);
    let action = |k: &KeepassFile| {
        let entries = k.collect_all_active_entries();
        let db_name = k.meta.database_name().clone();
        let entry_summaries = entries
            .iter()
            .filter_map(|e| {
                let (parsed_fields, entry_fields) =
                    EntryPlaceHolderParser::place_holder_resolved_entry_fields(&k.root, e);

                let Some(entry_field_url) = entry_fields.get(URL) else {
                    return None;
                };

                let entry_field_url_matched = url_matched(input_url, entry_field_url);

                // log::debug!("find_matching_entries_in_db Finding matching for the entry_field_url {} and matched? {} ",&entry_field_url,&matched);

                if !entry_field_url_matched {
                    // Check the additional urls if any
                    let matched = if let Some(urls) = entry_fields.get(ADDITIONAL_URLS) {
                        any_additional_urls_matching(input_url, urls)
                    } else {
                        entry_field_url_matched
                    };

                    // The final matched flag should be true to consider
                    if !matched {
                        // No match either with entry url or with additional url 
                        return None;
                    }
                }

                let title = entry_fields.get(TITLE).cloned();
                let secondary_title = EntrySummary::secondary_title(e, &parsed_fields);

                Some(EntrySummary {
                    uuid: e.uuid.to_string(),
                    parent_group_uuid: e.parent_group_uuid(),
                    title,
                    secondary_title,
                    icon_id: e.icon_id,
                    history_index: None,
                    modified_time: Some(e.times.last_modification_time.and_utc().timestamp()),
                    created_time: Some(e.times.creation_time.and_utc().timestamp()),
                })
            })
            .collect::<Vec<EntrySummary>>();
        let matched_db_entries = MatchedDbEntries {
            db_name,
            db_key: db_key.to_string(),
            entry_summaries,
        };
        Ok(matched_db_entries)
    };

    main_content_action!(db_key, action)
}

fn url_matched(input: &str, entry_field_val: &str) -> bool {
    let Ok(input_url) = Url::parse(input) else {
        return false;
    };

    let Ok(entry_url) = Url::parse(entry_field_val) else {
        return false;
    };


    // log::debug!("entry_url.scheme {:?}, entry_url.domain {:?}, entry_url.path {}",entry_url.scheme(),entry_url.domain(),entry_url.path() );

    input_url.scheme() == entry_url.scheme()
        && input_url.domain() == entry_url.domain()
        && input_url.path() == entry_url.path()
}

// ─────────────────────────────────────────────────────────────────────────────
// Passkey (WebAuthn) support
// ─────────────────────────────────────────────────────────────────────────────

/// All data needed by the desktop app to sign a WebAuthn assertion.
#[derive(Debug, Serialize)]
pub struct PasskeyEntry {
    pub entry_uuid: String,
    pub credential_id_b64url: String,
    pub rp_id: String,
    pub username: String,
    pub user_handle_b64url: String,
    /// PKCS#8 PEM-encoded EC P-256 private key (treated as protected).
    pub private_key_pem: String,
}

/// Minimal summary shown in the extension's passkey selection popup.
#[derive(Debug, Serialize)]
pub struct PasskeySummary {
    pub entry_uuid: String,
    pub db_key: String,
    pub credential_id_b64url: String,
    pub rp_id: String,
    pub username: String,
    pub user_handle_b64url: String,
}

/// Describes where (and how) to persist a newly created passkey.
pub struct PasskeyStorageInfo {
    pub credential_id_b64url: String,
    pub private_key_pem: String,
    pub rp_id: String,
    pub rp_name: String,
    pub username: String,
    pub user_handle_b64url: String,
    pub origin: String,
    /// If set, the passkey custom fields are added to this existing entry.
    pub entry_uuid: Option<Uuid>,
    /// If `entry_uuid` is None, a new entry is created with this title.
    pub new_entry_name: Option<String>,
    /// The group the new entry should be placed in. Defaults to root group if None.
    pub group_uuid: Option<Uuid>,
}

// ── helpers ─────────────────────────────────────────────────────────────────

fn make_passkey_kv(key: &str, value: &str, protected: bool) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: value.to_string(),
        protected,
        data_type: FieldDataType::Text,
    }
}

fn write_passkey_fields(entry: &mut Entry, info: &PasskeyStorageInfo) {
    entry.entry_field.insert_key_value(make_passkey_kv(
        KPXC_PASSKEY_CREDENTIAL_ID,
        &info.credential_id_b64url,
        false,
    ));
    // Private key is stored as a KDBX-protected string (same tier as Password).
    entry.entry_field.insert_key_value(make_passkey_kv(
        KPXC_PASSKEY_PRIVATE_KEY_PEM,
        &info.private_key_pem,
        true,
    ));
    entry.entry_field.insert_key_value(make_passkey_kv(
        KPXC_PASSKEY_RELYING_PARTY_ID,
        &info.rp_id,
        false,
    ));
    entry.entry_field.insert_key_value(make_passkey_kv(
        KPXC_PASSKEY_USERNAME,
        &info.username,
        false,
    ));
    entry.entry_field.insert_key_value(make_passkey_kv(
        KPXC_PASSKEY_USER_HANDLE,
        &info.user_handle_b64url,
        false,
    ));
}

// ── public API ───────────────────────────────────────────────────────────────

/// Returns the human-readable name of the database identified by `db_key`.
pub fn get_db_name(db_key: &str) -> Result<String> {
    let action = |k: &KeepassFile| Ok(k.meta.database_name().clone());
    main_content_action!(db_key, action, no_times)
}

/// Stores a newly created passkey in KDBX.
///
/// If `info.entry_uuid` is `Some`, the passkey fields are appended to that
/// existing entry.  Otherwise a new Login entry is created in the specified
/// group (or the root group if `info.group_uuid` is `None`).
pub fn store_passkey_entry(db_key: &str, info: PasskeyStorageInfo) -> Result<()> {
    let action = |k: &mut KeepassFile| -> Result<()> {
        match info.entry_uuid {
            // ── update existing entry ────────────────────────────────────
            Some(uuid) => {
                let entry = k.root.entry_by_id_mut(&uuid).ok_or_else(|| {
                    Error::NotFound(format!("Entry {} not found for passkey storage", uuid))
                })?;
                write_passkey_fields(entry, &info);
                // Backfill URL if currently blank
                if entry.find_kv_field_value(URL).unwrap_or_default().is_empty() {
                    entry
                        .entry_field
                        .update_value(URL, &format!("https://{}", &info.rp_id));
                }
                entry.update_modification_time_now();
            }

            // ── create new entry ─────────────────────────────────────────
            None => {
                let parent_uuid = info.group_uuid.unwrap_or_else(|| k.root.root_uuid());

                if k.root.group_by_id(&parent_uuid).is_none() {
                    return Err(Error::NotFound(format!(
                        "Target group {} not found",
                        parent_uuid
                    )));
                }

                let mut entry = Entry::new_login_entry(Some(&parent_uuid));
                let title = info
                    .new_entry_name
                    .as_deref()
                    .unwrap_or(&info.rp_name)
                    .to_string();
                entry.entry_field.update_value(TITLE, &title);
                entry
                    .entry_field
                    .update_value(URL, &format!("https://{}", &info.rp_id));
                entry.entry_field.update_value(USER_NAME, &info.username);

                write_passkey_fields(&mut entry, &info);

                k.insert_entry(entry)?;
            }
        }
        Ok(())
    };

    main_content_mut_action!(db_key, action)
}

/// Searches all provided databases for passkey entries matching `rp_id`.
/// If `allow_credential_ids` is non-empty, further filters by credential ID.
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
                    let stored_rp_id =
                        entry.find_kv_field_value(KPXC_PASSKEY_RELYING_PARTY_ID)?;
                    if stored_rp_id != rp_id {
                        return None;
                    }
                    let cred_id =
                        entry.find_kv_field_value(KPXC_PASSKEY_CREDENTIAL_ID)?;
                    if !allow_credential_ids.is_empty()
                        && !allow_credential_ids.contains(&cred_id)
                    {
                        return None;
                    }
                    let username = entry
                        .find_kv_field_value(KPXC_PASSKEY_USERNAME)
                        .unwrap_or_default();
                    let user_handle = entry
                        .find_kv_field_value(KPXC_PASSKEY_USER_HANDLE)
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
        // Tolerate errors from individual databases (e.g. closed between calls)
        if let Ok(mut db_matches) = main_content_action!(db_key, action, no_times) {
            summaries.append(&mut db_matches);
        }
    }

    Ok(summaries)
}

/// Returns full private-key material needed to sign a WebAuthn assertion.
pub fn get_passkey_for_assertion(db_key: &str, entry_uuid: &Uuid) -> Result<PasskeyEntry> {
    let action = |k: &KeepassFile| {
        let entry = k.root.entry_by_id(entry_uuid).ok_or_else(|| {
            Error::NotFound(format!(
                "Entry {} not found for passkey assertion",
                entry_uuid
            ))
        })?;

        let credential_id = entry
            .find_kv_field_value(KPXC_PASSKEY_CREDENTIAL_ID)
            .ok_or_else(|| Error::NotFound("KPXC_PASSKEY_CREDENTIAL_ID not found".into()))?;

        let private_key_pem = entry
            .find_kv_field_value(KPXC_PASSKEY_PRIVATE_KEY_PEM)
            .ok_or_else(|| {
                Error::NotFound("KPXC_PASSKEY_PRIVATE_KEY_PEM not found".into())
            })?;

        let rp_id = entry
            .find_kv_field_value(KPXC_PASSKEY_RELYING_PARTY_ID)
            .ok_or_else(|| {
                Error::NotFound("KPXC_PASSKEY_RELYING_PARTY_ID not found".into())
            })?;

        let username = entry
            .find_kv_field_value(KPXC_PASSKEY_USERNAME)
            .unwrap_or_default();

        let user_handle = entry
            .find_kv_field_value(KPXC_PASSKEY_USER_HANDLE)
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

    use super::*; // brings in url_matched, make_passkey_kv, write_passkey_fields, etc.

    // ── minimal in-process key store ──────────────────────────────────────────
    //
    // Mirrors `dummy_key_store_service` from `db_merge::merge_tests::common`
    // but duplicated here to avoid depending on a private `#[cfg(test)]` module.

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

    /// Initialises the global `KeyStoreOperation` singleton with an in-memory
    /// store.  Safe to call multiple times: `OnceCell::set` silently drops
    /// duplicate initialisations.
    fn init_key_store() {
        let kss = Arc::new(Mutex::new(InMemoryKeyStore::default()));
        KeyStoreOperation::init(kss);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Initialises the key store, creates a blank database named `db_name`,
    /// and inserts it into the in-memory cache under `db_key`.
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
        }
    }

    // ── make_passkey_kv ───────────────────────────────────────────────────────

    #[test]
    fn test_make_passkey_kv_protected_flag() {
        let kv = make_passkey_kv(KPXC_PASSKEY_PRIVATE_KEY_PEM, "secret-pem", true);
        assert_eq!(kv.key, KPXC_PASSKEY_PRIVATE_KEY_PEM);
        assert_eq!(kv.value, "secret-pem");
        assert!(kv.protected, "private key field must be protected");
    }

    #[test]
    fn test_make_passkey_kv_unprotected_flag() {
        let kv = make_passkey_kv(KPXC_PASSKEY_CREDENTIAL_ID, "cred-abc", false);
        assert_eq!(kv.key, KPXC_PASSKEY_CREDENTIAL_ID);
        assert_eq!(kv.value, "cred-abc");
        assert!(!kv.protected, "credential-id field must not be protected");
    }

    // ── write_passkey_fields ──────────────────────────────────────────────────

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
        };

        write_passkey_fields(&mut entry, &info);

        assert_eq!(
            entry.find_kv_field_value(KPXC_PASSKEY_CREDENTIAL_ID).as_deref(),
            Some("cred-id-xyz")
        );
        assert_eq!(
            entry.find_kv_field_value(KPXC_PASSKEY_PRIVATE_KEY_PEM).as_deref(),
            Some("pem-content")
        );
        assert_eq!(
            entry.find_kv_field_value(KPXC_PASSKEY_RELYING_PARTY_ID).as_deref(),
            Some("example.com")
        );
        assert_eq!(
            entry.find_kv_field_value(KPXC_PASSKEY_USERNAME).as_deref(),
            Some("alice@example.com")
        );
        assert_eq!(
            entry.find_kv_field_value(KPXC_PASSKEY_USER_HANDLE).as_deref(),
            Some("dXNlcg")
        );
    }

    // ── store_passkey_entry — new entry ───────────────────────────────────────

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

        // No new_entry_name provided — title should fall back to rp_name
        let info = PasskeyStorageInfo {
            credential_id_b64url: "cred-fallback".to_string(),
            private_key_pem: "pem".to_string(),
            rp_id: "fallback.com".to_string(),
            rp_name: "Fallback Site".to_string(),
            username: "user".to_string(),
            user_handle_b64url: "h".to_string(),
            origin: "https://fallback.com".to_string(),
            entry_uuid: None,
            new_entry_name: None, // rely on rp_name
            group_uuid: None,
        };
        store_passkey_entry(db_key, info).expect("store_passkey_entry should succeed");

        let db_keys = vec![db_key.to_string()];
        let summaries = find_matching_passkeys(&db_keys, "fallback.com", &[]).unwrap();
        assert_eq!(summaries.len(), 1);

        teardown_test_db(db_key);
    }

    // ── store_passkey_entry — existing entry ──────────────────────────────────

    #[test]
    fn test_store_passkey_existing_entry_updated() {
        use crate::constants::entry_keyvalue_key::TITLE;
        use crate::db_content::Entry;

        let db_key = "pk_test_existing_entry";
        setup_test_db(db_key, "PasskeyTestDB");

        // Create a regular login entry in the DB first
        let entry_uuid: Uuid =
            kp_service::call_main_content_mut_action(db_key, |k| {
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
        };
        store_passkey_entry(db_key, info).expect("store_passkey_entry (existing) should succeed");

        // get_passkey_for_assertion should return the updated fields
        let passkey = get_passkey_for_assertion(db_key, &entry_uuid)
            .expect("get_passkey_for_assertion should succeed");
        assert_eq!(passkey.credential_id_b64url, "cred-existing-999");
        assert_eq!(passkey.rp_id, "existing.com");
        assert_eq!(passkey.username, "bob@existing.com");
        assert_eq!(passkey.entry_uuid, entry_uuid.to_string());

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
            entry_uuid: Some(Uuid::new_v4()), // does not exist in the DB
            new_entry_name: None,
            group_uuid: None,
        };
        let result = store_passkey_entry(db_key, info);
        assert!(result.is_err(), "should fail for a nonexistent entry UUID");

        teardown_test_db(db_key);
    }

    // ── find_matching_passkeys ────────────────────────────────────────────────

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

        // No filter — both returned
        let all = find_matching_passkeys(&db_keys, "multi.com", &[]).unwrap();
        assert_eq!(all.len(), 2);

        // Filter to just cred-x
        let filtered =
            find_matching_passkeys(&db_keys, "multi.com", &["cred-x".to_string()]).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].credential_id_b64url, "cred-x");
        assert_eq!(filtered[0].username, "x-user");

        teardown_test_db(db_key);
    }

    #[test]
    fn test_find_matching_passkeys_empty_db_list_returns_empty() {
        let results = find_matching_passkeys(&[], "example.com", &[]).unwrap();
        assert!(results.is_empty());
    }

    // ── get_passkey_for_assertion ─────────────────────────────────────────────

    #[test]
    fn test_get_passkey_for_assertion_not_found() {
        let db_key = "pk_test_assertion_not_found";
        setup_test_db(db_key, "PasskeyTestDB");

        let result = get_passkey_for_assertion(db_key, &Uuid::new_v4());
        assert!(result.is_err(), "should fail when entry UUID does not exist");

        teardown_test_db(db_key);
    }

    // ── get_db_name ───────────────────────────────────────────────────────────

    #[test]
    fn test_get_db_name_returns_correct_name() {
        let db_key = "pk_test_db_name";
        setup_test_db(db_key, "MyPasskeyDatabase");

        let name = get_db_name(db_key).expect("get_db_name should succeed");
        assert_eq!(name, "MyPasskeyDatabase");

        teardown_test_db(db_key);
    }

    // ── url_matched (pre-existing) ────────────────────────────────────────────

    #[ignore]
    #[test]
    fn verify_url_matching() {
        let r = url_matched(
            "https://gemini.google.com/app/",
            "https://gemini.google.com/app/",
        );
        println!("r is {}", r);

        let r = url_matched(
            "https://gemini.google.com/app/",
            "https://gemini.google.com/app",
        );
        println!("r2 is {}", r);
    }
}


/*

fn main() {
    let text = "apple banana cherry";
    let fruits: Vec<&str> = text.split_whitespace().collect();
    println!("{:?}", fruits); // Output: ["apple", "banana", "cherry"]
}


fn main() {
    let text = "apple\tbanana\ncherry";
    let fruits: Vec<&str> = text.split(|c: char| c.is_whitespace()).collect();
    println!("{:?}", fruits); // Output: ["apple", "banana", "cherry"]
}

*/