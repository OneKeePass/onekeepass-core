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

// Builds the per-db matched-entries result. The actual URL matching is delegated
// to the shared autofill matcher (crate::db_service::autofill) so the desktop
// browser extension and the mobile autofill flows match identically.
fn find_matching_entries_in_db(db_key: &str, input_url: &str) -> Result<MatchedDbEntries> {
    let entry_summaries =
        crate::db_service::autofill::find_matching_login_entries(db_key, input_url)?;
    Ok(MatchedDbEntries {
        db_name: get_db_name(db_key)?,
        db_key: db_key.to_string(),
        entry_summaries,
    })
}

#[cfg(test)]
mod tests {
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
