// Browser extension credential lookup and save helpers (desktop only).
//
// Passkey types and functions have moved to [`super::passkey`] which is
// compiled on all platforms.  This module re-exports the types that existing
// desktop callers referenced via `browser_extension::`.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroize;

use crate::constants::entry_keyvalue_key::{PASSWORD, TITLE, URL, USER_NAME};
use crate::constants::entry_type_uuid;
use crate::db_content::KeepassFile;
use crate::db_service::{call_kdbx_context_mut_action, call_main_content_action, KdbxContext};
use crate::error::Error;
use crate::error::Result;
use crate::form_data::parsing::EntryPlaceHolderParser;
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
// Passkey-only entries are left out: they have no password to fill and are
// offered through the passkey (WebAuthn) list instead.
fn find_matching_entries_in_db(db_key: &str, input_url: &str) -> Result<RankedDbEntries> {
    let entries = super::autofill::find_ranked_password_entries(db_key, input_url)?;
    Ok(RankedDbEntries {
        db_name: get_db_name(db_key)?,
        db_key: db_key.to_string(),
        entries,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Saving a login submitted in the browser (add new / update changed password)
// ─────────────────────────────────────────────────────────────────────────────
//
// Flow: the extension captures the username and password a user submits on a
// site and asks the app to check them (check_login_credential). The check runs
// here, in the app, so the stored password never goes back to the browser: the
// answer is only a status plus entry titles. If the user then confirms a save in
// the extension popup, save_login_credential adds a new entry or updates the
// password of an existing one. An update goes through Entry::update, so the
// previous password is kept in the entry's history.
//
// Both functions work on the in-memory database only and do not write the file;
// the caller saves the database as it does after any other change.
//
// Every save request is re-validated here and never trusted on the extension's
// word: the database must be one the caller has enabled for the browser, the site
// url must be http(s), and an entry to update must be an active autofill-eligible
// entry for that same site and username.

// Upper bounds for the text a save request may carry.
const MAX_CREDENTIAL_FIELD_LEN: usize = 4096;
const MAX_TITLE_LEN: usize = 256;

// What a site login the user submitted means for the browser-enabled databases.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginCredentialStatus {
    // No entry in any browser-enabled database is for this site: offer to add one.
    NoEntryForSite,
    // Entries exist for this site but none with this username: offer to add one.
    NewUsername,
    // An entry for this site and username already holds this password: nothing to save.
    Unchanged,
    // Entries for this site and username hold a different password: offer to update
    // one of `update_candidates`. When no username was captured, every entry for the
    // site is a candidate and the user picks one.
    PasswordChanged,
}

// An existing entry that a submitted password may be saved to. Carries no secret.
#[derive(Serialize, Debug, Clone)]
pub struct LoginEntryCandidate {
    pub db_key: String,
    pub db_name: String,
    pub entry_uuid: String,
    pub title: String,
    pub username: String,
}

// A database (with its groups) a new login entry can be added to.
#[derive(Serialize, Debug)]
pub struct LoginSaveTarget {
    pub db_key: String,
    pub db_name: String,
    pub groups: Vec<GroupInfo>,
}

#[derive(Serialize, Debug)]
pub struct LoginCredentialCheck {
    pub status: LoginCredentialStatus,
    // The site's origin (scheme + host + port) the login was submitted on.
    pub site: String,
    // Set for PasswordChanged only.
    pub update_candidates: Vec<LoginEntryCandidate>,
    // Browser-enabled databases a new entry can be added to.
    pub save_targets: Vec<LoginSaveTarget>,
}

// A login submitted on a site, sent by the extension to be checked.
// The password is wiped from memory when this is dropped.
#[derive(Deserialize)]
pub struct LoginCredentialInput {
    // The url of the page the login was submitted on. The extension takes it from
    // the browser's own record of the sending tab, not from the page.
    pub url: String,
    #[serde(default)]
    pub username: String,
    pub password: String,
}

impl Drop for LoginCredentialInput {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl std::fmt::Debug for LoginCredentialInput {
    // Never print the password.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginCredentialInput")
            .field("url", &self.url)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

// The user's confirmed choice of where to save a submitted login.
// The password is wiped from memory when this is dropped.
#[derive(Deserialize)]
pub struct LoginCredentialSaveInfo {
    pub db_key: String,
    pub url: String,
    #[serde(default)]
    pub username: String,
    pub password: String,
    // Set: update the password of this existing entry.
    pub entry_uuid: Option<Uuid>,
    // For a new entry: the group to add it to; the root group when None.
    pub group_uuid: Option<Uuid>,
    // For a new entry: its title; the site's host when None or blank.
    pub title: Option<String>,
}

impl Drop for LoginCredentialSaveInfo {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl std::fmt::Debug for LoginCredentialSaveInfo {
    // Never print the password.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginCredentialSaveInfo")
            .field("db_key", &self.db_key)
            .field("url", &self.url)
            .field("username", &self.username)
            .field("entry_uuid", &self.entry_uuid)
            .field("group_uuid", &self.group_uuid)
            .field("title", &self.title)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct LoginCredentialSaveOutcome {
    pub entry_uuid: Uuid,
    pub group_uuid: Uuid,
    pub entry_type_uuid: Uuid,
    pub entry_type_name: String,
    // The entry's tags, so a UI can navigate to it when entries are grouped by tag
    pub tags: Vec<String>,
    // True when a new entry was added, false when an existing one was updated.
    pub created: bool,
}

// How one entry for the site compares with a submitted login. Holds no password.
struct SiteLoginComparison {
    // How strongly the entry's host matched the site (smaller is stronger)
    host_strength: u8,
    entry_uuid: Uuid,
    title: String,
    username: String,
    username_matches: bool,
    password_matches: bool,
}

// Returns the origin (scheme + host + port) of an http(s) url. Any other url is
// refused: a login is only saved for a web site.
fn site_origin(url: &str) -> Result<String> {
    let parsed = Url::parse(url.trim())
        .map_err(|_| Error::UnexpectedError("The site url is not valid".into()))?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(Error::UnexpectedError(
            "Logins can be saved only for http or https sites".into(),
        ));
    }
    if parsed.host_str().map_or(true, str::is_empty) {
        return Err(Error::UnexpectedError("The site url has no host".into()));
    }
    Ok(parsed.origin().ascii_serialization())
}

// Default title for a new entry: the site's host without a leading "www.".
fn default_title(site: &str) -> String {
    Url::parse(site)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.trim_start_matches("www.").to_string()))
        .unwrap_or_else(|| site.to_string())
}

// Usernames are compared ignoring surrounding white space and letter case: sites
// treat "Alice@Example.com" and "alice@example.com" as the same account.
fn same_username(a: &str, b: &str) -> bool {
    a.trim().to_lowercase() == b.trim().to_lowercase()
}

// Compares two secrets without stopping at the first differing byte.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn wipe_values(map: &mut HashMap<String, String>) {
    for v in map.values_mut() {
        v.zeroize();
    }
}

// Compares the submitted login with every active autofill-eligible entry for
// `site` in `db_key`. The stored passwords are compared here and never returned.
fn compare_site_logins(
    db_key: &str,
    site: &str,
    username: &str,
    password: &str,
) -> Result<Vec<SiteLoginComparison>> {
    let action = |k: &KeepassFile| {
        let mut comparisons = vec![];
        for e in k.collect_all_active_entries() {
            if !crate::db_service::is_autofill_eligible_type(&e.entry_field.entry_type.uuid) {
                continue;
            }
            let (mut parsed, mut fields) =
                EntryPlaceHolderParser::place_holder_resolved_entry_fields(&k.root, e);
            if let Some(host_strength) =
                crate::db_service::autofill::entry_fields_host_strength(&fields, site)
            {
                let stored_username = fields.get(USER_NAME).cloned().unwrap_or_default();
                let stored_password = fields.get(PASSWORD).map(String::as_str).unwrap_or("");
                comparisons.push(SiteLoginComparison {
                    host_strength,
                    entry_uuid: e.uuid,
                    title: fields.get(TITLE).cloned().unwrap_or_default(),
                    username_matches: same_username(&stored_username, username),
                    username: stored_username,
                    password_matches: !stored_password.is_empty()
                        && constant_time_eq(stored_password.as_bytes(), password.as_bytes()),
                });
            }
            // The resolved copies include the password: wipe them.
            wipe_values(&mut parsed);
            wipe_values(&mut fields);
        }
        Ok(comparisons)
    };
    main_content_action!(db_key, action)
}

// Checks a login the user submitted on a site against the browser-enabled
// databases (`enabled_db_keys`) and says whether to offer adding it, updating an
// existing entry, or nothing. A database that cannot be read (e.g. locked) is
// skipped, as the fill list does.
pub fn check_login_credential(
    enabled_db_keys: &[String],
    input: &LoginCredentialInput,
) -> Result<LoginCredentialCheck> {
    let site = site_origin(&input.url)?;
    if input.password.is_empty() {
        return Err(Error::UnexpectedError("No password was submitted".into()));
    }
    let username_given = !input.username.trim().is_empty();

    let mut unchanged = false;
    let mut same_username_entries = vec![];
    let mut site_entries = vec![];
    let mut save_targets = vec![];

    let mut per_db = vec![];
    for db_key in enabled_db_keys {
        // A database that cannot be read (e.g. locked) is skipped
        if let Ok(comparisons) =
            compare_site_logins(db_key, &site, &input.username, &input.password)
        {
            per_db.push((db_key, comparisons));
        }
    }
    // As the fill list does, prefer exact-host entries across all databases: the
    // related-domain ones count only when no database has an exact-host entry
    let best_host_strength = per_db
        .iter()
        .flat_map(|(_, cs)| cs.iter().map(|c| c.host_strength))
        .min();

    for (db_key, comparisons) in per_db {
        let db_name = get_db_name(db_key).unwrap_or_default();
        for c in comparisons
            .into_iter()
            .filter(|c| Some(c.host_strength) == best_host_strength)
        {
            // Without a username, a stored password alone tells the login is known.
            if c.password_matches && (c.username_matches || !username_given) {
                unchanged = true;
            }
            let candidate = LoginEntryCandidate {
                db_key: db_key.clone(),
                db_name: db_name.clone(),
                entry_uuid: c.entry_uuid.to_string(),
                title: c.title,
                username: c.username,
            };
            if c.username_matches {
                same_username_entries.push(candidate.clone());
            }
            site_entries.push(candidate);
        }
        if let Ok(groups) = get_db_groups(db_key) {
            save_targets.push(LoginSaveTarget {
                db_key: db_key.clone(),
                db_name,
                groups,
            });
        }
    }

    let (status, update_candidates) = if unchanged {
        (LoginCredentialStatus::Unchanged, vec![])
    } else if username_given && !same_username_entries.is_empty() {
        (LoginCredentialStatus::PasswordChanged, same_username_entries)
    } else if !username_given && !site_entries.is_empty() {
        (LoginCredentialStatus::PasswordChanged, site_entries)
    } else if !site_entries.is_empty() {
        (LoginCredentialStatus::NewUsername, vec![])
    } else {
        (LoginCredentialStatus::NoEntryForSite, vec![])
    };

    Ok(LoginCredentialCheck {
        status,
        site,
        update_candidates,
        save_targets,
    })
}

// What the stored entry looks like, for re-validating an update request.
struct UpdateTargetState {
    for_site: bool,
    username: String,
    password_is_reference: bool,
}

fn update_target_state(db_key: &str, entry_uuid: &Uuid, site: &str) -> Result<UpdateTargetState> {
    let action = |k: &KeepassFile| {
        // Only an active entry (not in the recycle bin) can be updated.
        let entry = k
            .collect_all_active_entries()
            .into_iter()
            .find(|e| &e.uuid == entry_uuid)
            .ok_or_else(|| Error::NotFound(format!("No entry is found for the id {}", entry_uuid)))?;
        if !crate::db_service::is_autofill_eligible_type(&entry.entry_field.entry_type.uuid) {
            return Err(Error::UnexpectedError(
                "This entry type does not hold a login".into(),
            ));
        }
        let (mut parsed, mut fields) =
            EntryPlaceHolderParser::place_holder_resolved_entry_fields(&k.root, entry);
        let state = UpdateTargetState {
            for_site: crate::db_service::autofill::entry_fields_match_url(&fields, site),
            username: fields.get(USER_NAME).cloned().unwrap_or_default(),
            // parsed holds, by upper-cased field name, the fields whose value is a
            // place holder (e.g. a {REF:...} to another entry's password).
            password_is_reference: parsed.contains_key(&PASSWORD.to_uppercase()),
        };
        wipe_values(&mut parsed);
        wipe_values(&mut fields);
        Ok(state)
    };
    main_content_action!(db_key, action, no_times)
}

fn validate_group(db_key: &str, group_uuid: &Uuid) -> Result<()> {
    let action = |k: &KeepassFile| {
        let usable = k.root.group_by_id(group_uuid).is_some()
            && *group_uuid != k.root.recycle_bin_uuid()
            && !k.deleted_group_uuids().contains(group_uuid);
        if usable {
            Ok(())
        } else {
            Err(Error::NotFound(format!("No group is found for the id {}", group_uuid)))
        }
    };
    main_content_action!(db_key, action, no_times)
}

// Saves a login the user confirmed in the extension: updates the password of
// `info.entry_uuid`, or adds a new Login entry when it is None. `enabled_db_keys`
// are the databases the user enabled for the browser; no other one is written.
pub fn save_login_credential(
    enabled_db_keys: &[String],
    info: &LoginCredentialSaveInfo,
) -> Result<LoginCredentialSaveOutcome> {
    if !enabled_db_keys.iter().any(|k| k == &info.db_key) {
        return Err(Error::UnexpectedError(
            "This database is not enabled for the browser extension".into(),
        ));
    }
    let site = site_origin(&info.url)?;
    if info.password.is_empty() {
        return Err(Error::UnexpectedError("No password was submitted".into()));
    }
    if info.password.len() > MAX_CREDENTIAL_FIELD_LEN
        || info.username.len() > MAX_CREDENTIAL_FIELD_LEN
    {
        return Err(Error::UnexpectedError("The submitted login is too long".into()));
    }
    let db_key = info.db_key.as_str();
    let username = info.username.trim();

    match info.entry_uuid {
        Some(entry_uuid) => {
            let state = update_target_state(db_key, &entry_uuid, &site)?;
            if !state.for_site {
                return Err(Error::UnexpectedError(
                    "This entry is not for the site the login was submitted on".into(),
                ));
            }
            let stored_username = state.username.trim();
            if !username.is_empty()
                && !stored_username.is_empty()
                && !same_username(stored_username, username)
            {
                return Err(Error::UnexpectedError(
                    "This entry is for a different username".into(),
                ));
            }
            if state.password_is_reference {
                return Err(Error::UnexpectedError(
                    "This entry's password refers to another entry. Update it there".into(),
                ));
            }

            let mut form_data = crate::db_service::get_entry_form_data_by_id(db_key, &entry_uuid)?;
            if !form_data.set_field_value(PASSWORD, &info.password) {
                return Err(Error::UnexpectedError(
                    "This entry has no password field".into(),
                ));
            }
            // Fill in a username the entry did not have yet. A stored one is kept.
            if stored_username.is_empty() && !username.is_empty() {
                form_data.set_field_value(USER_NAME, username);
            }
            let outcome = LoginCredentialSaveOutcome {
                entry_uuid,
                group_uuid: form_data.group_uuid(),
                entry_type_uuid: form_data.entry_type_uuid(),
                entry_type_name: form_data.entry_type_name().to_string(),
                tags: form_data.tags().to_vec(),
                created: false,
            };
            // Entry::update keeps the previous version in the entry's history.
            crate::db_service::update_entry_from_form_data(db_key, form_data)?;
            Ok(outcome)
        }
        None => {
            let parent_uuid = match info.group_uuid {
                Some(group_uuid) => {
                    validate_group(db_key, &group_uuid)?;
                    group_uuid
                }
                None => main_content_action!(db_key, |k: &KeepassFile| Ok(k.root.root_uuid()), no_times)?,
            };
            let title = info
                .title
                .as_deref()
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(|t| t.chars().take(MAX_TITLE_LEN).collect::<String>())
                .unwrap_or_else(|| default_title(&site));

            let login_type_uuid = crate::build_uuid!(entry_type_uuid::LOGIN);
            let mut form_data = crate::db_service::new_entry_form_data_by_id(
                db_key,
                &login_type_uuid,
                Some(&parent_uuid),
            )?;
            form_data.set_title(title);
            form_data.set_field_value(USER_NAME, username);
            form_data.set_field_value(URL, &site);
            if !form_data.set_field_value(PASSWORD, &info.password) {
                return Err(Error::UnexpectedError(
                    "The Login entry type has no password field".into(),
                ));
            }
            let outcome = LoginCredentialSaveOutcome {
                entry_uuid: form_data.uuid(),
                group_uuid: parent_uuid,
                entry_type_uuid: form_data.entry_type_uuid(),
                entry_type_name: form_data.entry_type_name().to_string(),
                tags: form_data.tags().to_vec(),
                created: true,
            };
            crate::db_service::insert_entry_from_form_data(db_key, form_data)?;
            Ok(outcome)
        }
    }
}

// As save_login_credential, then writes the database file (with a backup when
// `backup_file_name` is given), the same way create_and_store_passkey does.
pub fn save_login_credential_to_db(
    enabled_db_keys: &[String],
    info: &LoginCredentialSaveInfo,
    backup_file_name: Option<&str>,
) -> Result<LoginCredentialSaveOutcome> {
    let outcome = save_login_credential(enabled_db_keys, info)?;
    crate::db_service::save_kdbx_with_backup(&info.db_key, backup_file_name, false)?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::entry_keyvalue_key::{ADDITIONAL_URLS, TITLE, URL};
    use crate::db::KdbxFile;
    use crate::db_content::{Entry, Group, KeyValue};

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

    use std::sync::{Arc, Mutex};

    use uuid::Uuid;

    use crate::constants::entry_keyvalue_key::{
        KPEX_PASSKEY_CREDENTIAL_ID, KPEX_PASSKEY_RELYING_PARTY,
    };
    use crate::db::{KeyStoreOperation, KeyStoreService, NewDatabase};
    use crate::db_service as kp_service;
    use crate::error::Result as KpResult;

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

    fn setup_test_db(db_key: &str) {
        KeyStoreOperation::init(Arc::new(Mutex::new(InMemoryKeyStore::default())));
        let ndb = NewDatabase {
            database_name: format!("{}-name", db_key),
            database_file_name: db_key.to_string(),
            ..NewDatabase::default()
        };
        let kdbx_file = ndb.create().expect("NewDatabase::create should succeed");
        kp_service::insert_kdbx_for_test(kdbx_file);
    }

    fn teardown_test_db(db_key: &str) {
        let _ = kp_service::close_kdbx(db_key);
    }

    // Adds a Login entry for `url` and returns its uuid.
    fn add_login(db_key: &str, title: &str, url: &str, username: &str, password: &str) -> Uuid {
        kp_service::call_main_content_mut_action(db_key, |k| {
            let mut entry = Entry::new_login_entry(Some(&k.root.root_uuid()));
            entry.entry_field.update_value(TITLE, title);
            entry.entry_field.update_value(URL, url);
            entry.entry_field.update_value(USER_NAME, username);
            entry.entry_field.update_value(PASSWORD, password);
            let uuid = entry.get_uuid();
            k.insert_entry(entry)?;
            Ok(uuid)
        })
        .expect("insert test entry should succeed")
    }

    fn input(url: &str, username: &str, password: &str) -> LoginCredentialInput {
        LoginCredentialInput {
            url: url.into(),
            username: username.into(),
            password: password.into(),
        }
    }

    fn save_info(
        db_key: &str,
        url: &str,
        username: &str,
        password: &str,
        entry_uuid: Option<Uuid>,
    ) -> LoginCredentialSaveInfo {
        LoginCredentialSaveInfo {
            db_key: db_key.into(),
            url: url.into(),
            username: username.into(),
            password: password.into(),
            entry_uuid,
            group_uuid: None,
            title: None,
        }
    }

    fn stored(db_key: &str, entry_uuid: &Uuid, field: &str) -> Option<String> {
        kp_service::call_main_content_action(db_key, |k| {
            Ok(k.root.entry_by_id(entry_uuid).and_then(|e| e.find_kv_field_value(field)))
        })
        .unwrap()
    }

    fn history_len(db_key: &str, entry_uuid: &Uuid) -> usize {
        kp_service::call_main_content_action(db_key, |k| {
            Ok(k.root.entry_by_id(entry_uuid).map_or(0, |e| e.histories().len()))
        })
        .unwrap()
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

    #[test]
    fn site_origin_accepts_only_web_urls() {
        assert_eq!(
            site_origin("https://login.example.com/path?q=1#x").unwrap(),
            "https://login.example.com"
        );
        assert_eq!(site_origin("http://localhost:8080/a").unwrap(), "http://localhost:8080");
        assert!(site_origin("file:///etc/passwd").is_err());
        assert!(site_origin("chrome-extension://abc/page.html").is_err());
        assert!(site_origin("javascript:alert(1)").is_err());
        assert!(site_origin("not a url").is_err());
    }

    #[test]
    fn username_and_secret_comparisons() {
        assert!(same_username(" Alice@Example.com ", "alice@example.com"));
        assert!(!same_username("alice", "alice2"));
        assert!(constant_time_eq(b"s3cret", b"s3cret"));
        assert!(!constant_time_eq(b"s3cret", b"s3creT"));
        assert!(!constant_time_eq(b"s3cret", b"s3cret!"));
    }

    #[test]
    fn check_reports_each_status() {
        let db_key = "be_check_status";
        setup_test_db(db_key);
        let dbs = vec![db_key.to_string()];
        let entry = add_login(db_key, "Example", "https://example.com", "alice", "old-pass");

        // Same username and password: nothing to save.
        let c = check_login_credential(&dbs, &input("https://www.example.com/login", "ALICE", "old-pass")).unwrap();
        assert_eq!(c.status, LoginCredentialStatus::Unchanged);
        assert_eq!(c.site, "https://www.example.com");
        assert!(c.update_candidates.is_empty());

        // Same username, new password: offer to update that entry.
        let c = check_login_credential(&dbs, &input("https://example.com/", "alice", "new-pass")).unwrap();
        assert_eq!(c.status, LoginCredentialStatus::PasswordChanged);
        assert_eq!(c.update_candidates.len(), 1);
        assert_eq!(c.update_candidates[0].entry_uuid, entry.to_string());
        assert_eq!(c.save_targets.len(), 1);
        assert!(!c.save_targets[0].groups.is_empty());

        // Another username on the same site: offer to add.
        let c = check_login_credential(&dbs, &input("https://example.com/", "bob", "pw")).unwrap();
        assert_eq!(c.status, LoginCredentialStatus::NewUsername);
        assert!(c.update_candidates.is_empty());

        // A site with no entry: offer to add.
        let c = check_login_credential(&dbs, &input("https://other.org/", "alice", "pw")).unwrap();
        assert_eq!(c.status, LoginCredentialStatus::NoEntryForSite);

        // A look-alike host is a different site.
        let c = check_login_credential(&dbs, &input("https://example.com.evil.net/", "alice", "x")).unwrap();
        assert_eq!(c.status, LoginCredentialStatus::NoEntryForSite);

        // No username captured: a known password is Unchanged, an unknown one lists
        // every entry for the site so the user picks one.
        let c = check_login_credential(&dbs, &input("https://example.com/", "", "old-pass")).unwrap();
        assert_eq!(c.status, LoginCredentialStatus::Unchanged);
        add_login(db_key, "Example 2", "https://example.com", "carol", "pw2");
        let c = check_login_credential(&dbs, &input("https://example.com/", "", "new")).unwrap();
        assert_eq!(c.status, LoginCredentialStatus::PasswordChanged);
        assert_eq!(c.update_candidates.len(), 2);

        // A non-web url and an empty password are refused.
        assert!(check_login_credential(&dbs, &input("ftp://example.com/", "a", "b")).is_err());
        assert!(check_login_credential(&dbs, &input("https://example.com/", "a", "")).is_err());

        teardown_test_db(db_key);
    }

    #[test]
    fn check_prefers_exact_host_entries() {
        let db_key = "be_check_exact_host";
        setup_test_db(db_key);
        let dbs = vec![db_key.to_string()];
        add_login(db_key, "Apex", "https://example.com", "alice", "apex-pass");
        let mail = add_login(db_key, "Mail", "https://mail.example.com", "alice", "mail-pass");

        // On mail.example.com only the exact-host entry is a candidate
        let c = check_login_credential(&dbs, &input("https://mail.example.com", "alice", "new")).unwrap();
        assert_eq!(c.status, LoginCredentialStatus::PasswordChanged);
        assert_eq!(c.update_candidates.len(), 1);
        assert_eq!(c.update_candidates[0].entry_uuid, mail.to_string());

        // The apex password typed on mail.example.com is not "unchanged" for it
        let c = check_login_credential(&dbs, &input("https://mail.example.com", "alice", "apex-pass")).unwrap();
        assert_eq!(c.status, LoginCredentialStatus::PasswordChanged);

        // With no exact-host entry, the related-domain entry is the candidate
        let c = check_login_credential(&dbs, &input("https://shop.example.com", "alice", "apex-pass")).unwrap();
        assert_eq!(c.status, LoginCredentialStatus::Unchanged);

        teardown_test_db(db_key);
    }

    #[test]
    fn check_skips_databases_not_enabled() {
        let db_key = "be_check_not_enabled";
        setup_test_db(db_key);
        add_login(db_key, "Example", "https://example.com", "alice", "pw");
        let c = check_login_credential(&[], &input("https://example.com/", "alice", "pw")).unwrap();
        assert_eq!(c.status, LoginCredentialStatus::NoEntryForSite);
        assert!(c.save_targets.is_empty());
        teardown_test_db(db_key);
    }

    #[test]
    fn update_changes_password_and_keeps_history() {
        let db_key = "be_update_password";
        setup_test_db(db_key);
        let dbs = vec![db_key.to_string()];
        let entry = add_login(db_key, "Example", "https://example.com", "alice", "old-pass");
        assert_eq!(history_len(db_key, &entry), 0);

        let out = save_login_credential(
            &dbs,
            &save_info(db_key, "https://example.com/account", "Alice", "new-pass", Some(entry)),
        )
        .unwrap();
        assert!(!out.created);
        assert_eq!(out.entry_uuid, entry);
        assert_eq!(stored(db_key, &entry, PASSWORD).as_deref(), Some("new-pass"));
        // The stored username keeps its own spelling.
        assert_eq!(stored(db_key, &entry, USER_NAME).as_deref(), Some("alice"));
        // The old password is in the history.
        assert_eq!(history_len(db_key, &entry), 1);

        let c = check_login_credential(&dbs, &input("https://example.com/", "alice", "new-pass")).unwrap();
        assert_eq!(c.status, LoginCredentialStatus::Unchanged);

        teardown_test_db(db_key);
    }

    #[test]
    fn update_fills_a_missing_username() {
        let db_key = "be_update_fill_username";
        setup_test_db(db_key);
        let dbs = vec![db_key.to_string()];
        let entry = add_login(db_key, "Example", "https://example.com", "", "old");
        save_login_credential(&dbs, &save_info(db_key, "https://example.com", "dave", "new", Some(entry))).unwrap();
        assert_eq!(stored(db_key, &entry, USER_NAME).as_deref(), Some("dave"));
        assert_eq!(stored(db_key, &entry, PASSWORD).as_deref(), Some("new"));
        teardown_test_db(db_key);
    }

    #[test]
    fn update_refuses_unsafe_requests() {
        let db_key = "be_update_refused";
        setup_test_db(db_key);
        let dbs = vec![db_key.to_string()];
        let entry = add_login(db_key, "Example", "https://example.com", "alice", "old");

        // The entry is for another site than the one the login was submitted on.
        assert!(save_login_credential(&dbs, &save_info(db_key, "https://evil.net", "alice", "x", Some(entry))).is_err());
        // The entry is for another username.
        assert!(save_login_credential(&dbs, &save_info(db_key, "https://example.com", "mallory", "x", Some(entry))).is_err());
        // The database is not enabled for the browser.
        assert!(save_login_credential(&[], &save_info(db_key, "https://example.com", "alice", "x", Some(entry))).is_err());
        // No such entry.
        assert!(save_login_credential(&dbs, &save_info(db_key, "https://example.com", "alice", "x", Some(Uuid::new_v4()))).is_err());
        // Empty or oversized password.
        assert!(save_login_credential(&dbs, &save_info(db_key, "https://example.com", "alice", "", Some(entry))).is_err());
        let huge = "p".repeat(MAX_CREDENTIAL_FIELD_LEN + 1);
        assert!(save_login_credential(&dbs, &save_info(db_key, "https://example.com", "alice", &huge, Some(entry))).is_err());

        // Nothing was changed by the refused requests.
        assert_eq!(stored(db_key, &entry, PASSWORD).as_deref(), Some("old"));
        assert_eq!(history_len(db_key, &entry), 0);

        teardown_test_db(db_key);
    }

    #[test]
    fn update_refuses_a_referenced_password() {
        let db_key = "be_update_ref_password";
        setup_test_db(db_key);
        let dbs = vec![db_key.to_string()];
        let source = add_login(db_key, "Source", "https://source.example", "s", "shared-secret");
        let reference = format!("{{REF:P@I:{}}}", source.simple().to_string().to_uppercase());
        let entry = add_login(db_key, "Example", "https://example.com", "alice", &reference);

        // The reference resolves, so the check sees the real password.
        let c = check_login_credential(&dbs, &input("https://example.com", "alice", "shared-secret")).unwrap();
        assert_eq!(c.status, LoginCredentialStatus::Unchanged);

        // Overwriting it would break the link to the other entry.
        assert!(save_login_credential(&dbs, &save_info(db_key, "https://example.com", "alice", "x", Some(entry))).is_err());
        assert_eq!(stored(db_key, &entry, PASSWORD).as_deref(), Some(reference.as_str()));

        teardown_test_db(db_key);
    }

    #[test]
    fn add_creates_a_login_entry_for_the_site() {
        let db_key = "be_add_entry";
        setup_test_db(db_key);
        let dbs = vec![db_key.to_string()];

        let out = save_login_credential(
            &dbs,
            &save_info(db_key, "https://www.example.com/signup?x=1", " erin ", "pw-1", None),
        )
        .unwrap();
        assert!(out.created);
        assert_eq!(stored(db_key, &out.entry_uuid, TITLE).as_deref(), Some("example.com"));
        assert_eq!(stored(db_key, &out.entry_uuid, URL).as_deref(), Some("https://www.example.com"));
        assert_eq!(stored(db_key, &out.entry_uuid, USER_NAME).as_deref(), Some("erin"));
        assert_eq!(stored(db_key, &out.entry_uuid, PASSWORD).as_deref(), Some("pw-1"));

        // The new entry is offered in the fill list for the site.
        let matched = find_matching_in_enabled_db_entries(&dbs, "https://www.example.com").unwrap();
        assert_eq!(matched[0].entry_summaries.len(), 1);

        // A custom title and an unknown group.
        let mut info = save_info(db_key, "https://example.com", "f", "pw", None);
        info.title = Some("  My Shop  ".into());
        let out = save_login_credential(&dbs, &info).unwrap();
        assert_eq!(stored(db_key, &out.entry_uuid, TITLE).as_deref(), Some("My Shop"));
        info.group_uuid = Some(Uuid::new_v4());
        assert!(save_login_credential(&dbs, &info).is_err());

        teardown_test_db(db_key);
    }

    #[test]
    fn password_fill_list_leaves_out_passkey_only_entries() {
        let db_key = "be_fill_list_passkeys";
        setup_test_db(db_key);
        let dbs = vec![db_key.to_string()];
        add_login(db_key, "Password login", "https://example.com", "alice", "pw");
        let passkey_only = add_login(db_key, "Passkey", "https://example.com", "alice", "");
        let both = add_login(db_key, "Both", "https://example.com", "bob", "pw2");
        kp_service::call_main_content_mut_action(db_key, |k| {
            for id in [passkey_only, both] {
                let e = k.root.entry_by_id_mut(&id).unwrap();
                e.entry_field.insert_key_value(KeyValue::from(
                    KPEX_PASSKEY_RELYING_PARTY.into(),
                    "example.com".into(),
                    false,
                ));
                e.entry_field.insert_key_value(KeyValue::from(
                    KPEX_PASSKEY_CREDENTIAL_ID.into(),
                    format!("cred-{}", id),
                    true,
                ));
            }
            Ok(())
        })
        .unwrap();

        let matched = find_matching_in_enabled_db_entries(&dbs, "https://example.com").unwrap();
        let titles: Vec<_> = matched[0]
            .entry_summaries
            .iter()
            .filter_map(|s| s.title.clone())
            .collect();
        assert_eq!(titles.len(), 2, "titles: {:?}", titles);
        assert!(titles.contains(&"Password login".to_string()));
        assert!(titles.contains(&"Both".to_string()));
        assert!(!titles.contains(&"Passkey".to_string()));

        // The passkey list still finds both passkeys.
        let passkeys = find_matching_passkeys(&dbs, "example.com", &[]).unwrap();
        assert_eq!(passkeys.len(), 2);

        teardown_test_db(db_key);
    }
}
