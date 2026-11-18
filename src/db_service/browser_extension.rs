// Browser extension credential lookup helpers (desktop only).
//
// Passkey types and functions have moved to [`super::passkey`] which is
// compiled on all platforms.  This module re-exports the types that existing
// desktop callers referenced via `browser_extension::`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Serialize;

use crate::constants::entry_keyvalue_key::PASSWORD;
use crate::constants::entry_keyvalue_key::USER_NAME;
use crate::db_content::KeepassFile;
use crate::db_service::{call_kdbx_context_mut_action, call_main_content_action, KdbxContext};
use crate::error::Error;
use crate::error::Result;
use crate::form_data::EntrySummary;
use crate::util;

use uuid::Uuid;

// NOTE: To use these macros in this module, we need to import all fns used
// inside the macro expansion as well.
use crate::main_content_action;

// Re-export passkey types for backward compatibility with desktop callers that
// previously imported them from this module.
pub use super::passkey::{
    create_and_store_passkey, find_matching_passkeys, get_db_groups, get_db_name,
    get_group_entries, get_passkey_for_assertion, store_passkey_entry, EntryBasicInfo, GroupInfo,
    PasskeyEntry, PasskeyStorageInfo, PasskeyStoreOutcome, PasskeySummary,
};

// ─────────────────────────────────────────────────────────────────────────────
// Browser credential lookup (URL-based, non-passkey)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Default, Serialize, Debug)]
pub struct MatchedDbEntries {
    db_name: String,
    db_key: String,
    entry_summaries: Vec<EntrySummary>,
}

struct RankedDbEntries {
    db_name: String,
    db_key: String,
    entries: Vec<super::autofill::RankedEntrySummary>,
}

#[derive(Default, Serialize, Debug)]
pub struct BrowserExtensionCustomIcon {
    custom_icon_uuid: String,
    data_base64: String,
    mime_type: String,
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
    let databases: Vec<_> = enabled_db_keys
        .iter()
        .filter_map(|db_key| find_matching_entries_in_db(db_key, input_url).ok())
        .collect();

    // Prefer exact hosts across the whole request, not independently per vault.
    // Keep related-domain fallback only when no enabled vault has an exact match,
    // so SSO flows with a different login host still work. Field source breaks ties
    // within a vault but must not discard explicit Additional URLs matches.
    let best_host_strength = databases
        .iter()
        .flat_map(|db| db.entries.iter().map(|(rank, _)| rank.0))
        .min();

    Ok(databases
        .into_iter()
        .map(|db| MatchedDbEntries {
            db_name: db.db_name,
            db_key: db.db_key,
            entry_summaries: db
                .entries
                .into_iter()
                .filter(|(rank, _)| Some(rank.0) == best_host_strength)
                .map(|(_, summary)| summary)
                .collect(),
        })
        .collect())
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

pub fn custom_icon_for_browser_extension(
    db_key: &str,
    custom_icon_uuid: &str,
) -> Result<BrowserExtensionCustomIcon> {
    let custom_icon_uuid = custom_icon_uuid.to_string();
    let action = move |k: &KeepassFile| {
        let icon = crate::custom_icons::get_custom_icon(k, &custom_icon_uuid)?;
        Ok(BrowserExtensionCustomIcon {
            custom_icon_uuid: custom_icon_uuid.clone(),
            data_base64: STANDARD.encode(&icon.data),
            mime_type: "image/png".to_string(),
        })
    };

    main_content_action!(db_key, action)
}

// Retain the shared matcher's ranks until all enabled databases are collected.
// The browser then chooses the strongest host matches across those databases.
fn find_matching_entries_in_db(db_key: &str, input_url: &str) -> Result<RankedDbEntries> {
    let entries = super::autofill::find_ranked_matching_entries(db_key, input_url, false)?;
    Ok(RankedDbEntries {
        db_name: get_db_name(db_key)?,
        db_key: db_key.to_string(),
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::entry_keyvalue_key::{ADDITIONAL_URLS, TITLE, URL};
    use crate::db::KdbxFile;
    use crate::db_content::{Entry, Group};

    // Populate only the in-memory content used by matching. No passwords or disk IO.
    struct TestDb(String);

    impl TestDb {
        fn new(entries: &[(&str, &str, &str)]) -> Self {
            let key = format!("autofill-test-{}", Uuid::new_v4());
            let mut content = KeepassFile::new();
            let group = Group::new_with_id();
            let root = group.uuid;
            content.root.set_root_uuid(root);
            content.root.insert_to_all_groups(group);
            for (title, url, additional) in entries {
                let mut entry = Entry::new_login_entry(Some(&root));
                entry.entry_field.update_value(TITLE, title);
                entry.entry_field.update_value(URL, url);
                entry.entry_field.update_value(ADDITIONAL_URLS, additional);
                content.insert_entry(entry).unwrap();
            }
            crate::db_service::insert_kdbx_for_test(KdbxFile {
                database_file_name: key.clone(),
                keepass_main_content: Some(content),
                ..KdbxFile::default()
            });
            Self(key)
        }
    }

    impl Drop for TestDb {
        fn drop(&mut self) {
            crate::db_service::main_store()
                .lock()
                .unwrap()
                .remove(&self.0);
        }
    }

    fn titles(dbs: &[&TestDb], url: &str) -> Vec<String> {
        let keys = dbs.iter().map(|db| db.0.clone()).collect();
        let mut titles: Vec<_> = find_matching_in_enabled_db_entries(&keys, url)
            .unwrap()
            .into_iter()
            .flat_map(|db| db.entry_summaries)
            .filter_map(|entry| entry.title)
            .collect();
        titles.sort();
        titles
    }

    #[test]
    fn exact_host_suggestions_distinguish_apex_and_sibling_subdomains() {
        let db = TestDb::new(&[
            ("apex", "https://example.com/", ""),
            ("mail", "https://mail.example.com/", ""),
            ("admin", "https://admin.example.com/", ""),
        ]);
        assert_eq!(titles(&[&db], "https://example.com/login"), ["apex"]);
        assert_eq!(titles(&[&db], "https://mail.example.com/auth"), ["mail"]);
        assert_eq!(titles(&[&db], "https://admin.example.com/"), ["admin"]);
    }

    #[test]
    fn exact_host_preference_applies_across_all_enabled_databases() {
        let broad = TestDb::new(&[("apex", "https://example.com/", "")]);
        let exact = TestDb::new(&[("mail", "https://mail.example.com/", "")]);
        assert_eq!(
            titles(&[&broad, &exact], "https://mail.example.com/"),
            ["mail"]
        );
        assert_eq!(
            titles(&[&exact, &broad], "https://mail.example.com/"),
            ["mail"]
        );
    }

    #[test]
    fn explicit_additional_host_is_kept_alongside_exact_primary_urls() {
        let db = TestDb::new(&[
            (
                "explicit",
                "https://example.com/",
                "https://mail.example.com/login",
            ),
            ("primary", "https://mail.example.com/", ""),
            ("sibling", "https://admin.example.com/", ""),
        ]);
        assert_eq!(
            titles(&[&db], "https://mail.example.com/"),
            ["explicit", "primary"]
        );
    }

    #[test]
    fn related_domain_fallback_preserves_sso_when_no_exact_host_is_saved() {
        let first = TestDb::new(&[("www", "https://www.example.com/", "")]);
        let second = TestDb::new(&[("account", "https://account.example.com/", "")]);
        assert_eq!(
            titles(&[&first, &second], "https://login.example.com/transient"),
            ["account", "www"]
        );
        assert!(titles(&[&first, &second], "http://login.example.com/").is_empty());
        assert!(titles(&[&first, &second], "https://example.com.evil.test/").is_empty());
    }

    #[test]
    fn login_card_and_bank_types_are_autofill_eligible() {
        use crate::constants::entry_type_uuid;
        use crate::db_service::is_autofill_eligible_type;

        let login = crate::build_uuid!(entry_type_uuid::LOGIN);
        let card = crate::build_uuid!(entry_type_uuid::CREDIT_DEBIT_CARD);
        let bank = crate::build_uuid!(entry_type_uuid::BANK_ACCOUNT);

        // All three carry a Login Details section, so all are autofill candidates.
        assert!(is_autofill_eligible_type(&login));
        assert!(is_autofill_eligible_type(&card));
        assert!(is_autofill_eligible_type(&bank));

        // A non-credential type stays ineligible.
        let passport = crate::build_uuid!(entry_type_uuid::PASSPORT);
        assert!(!is_autofill_eligible_type(&passport));
    }
}
