// URL-based autofill entry matching - shared by the desktop browser extension
// and the mobile (iOS / Android) autofill flows.
//
// This module is compiled for all platforms. It is the single match authority so
// that every platform offers the same entries for a given login URL:
//   * only Login-type entries are considered (see is_autofill_eligible_type), and
//   * an entry matches when the incoming URL matches its URL field or any of its
//     Additional URLs.

use url::Url;
use uuid::Uuid;

use crate::constants::entry_keyvalue_key::{ADDITIONAL_URLS, TITLE, URL};
use crate::db_content::KeepassFile;
use crate::db_service::{call_kdbx_context_mut_action, call_main_content_action, KdbxContext};
use crate::error::Result;
use crate::form_data::parsing::EntryPlaceHolderParser;
use crate::form_data::EntrySummary;
use crate::util;

use super::EntrySearchResult;

// NOTE: To use the macro in this module, the fns used inside its expansion must
// also be in scope (call_main_content_action, call_kdbx_context_mut_action).
use crate::main_content_action;

// Decides whether a stored entry URL matches the incoming login URL.
//
// Matching (see the URL-Matching-Relaxation plan): require scheme + exact
// host equality and ignore the path. The path is dropped because real login flows
// (OAuth / SSO) use transient paths and trailing-slash differences are common.
//
// The host comparison is the phishing boundary and is kept strict - exact host
// including any subdomain (host_str compares the full host and treats distinct IP
// literals as different). The scheme is kept so an https credential is not offered
// on an http page. Port is not compared (consistent with the previous behaviour).
//
// Host matching is intentionally exact for now. Broadening it (apex <-> www, or
// registrable-domain via the Public Suffix List) is a deliberate, riskier step
// left for a later phase.
fn url_matched(input: &str, entry_field_val: &str) -> bool {
    let Ok(input_url) = Url::parse(input) else {
        return false;
    };

    let Ok(entry_url) = Url::parse(entry_field_val) else {
        return false;
    };

    scheme_key(input_url.scheme()) == scheme_key(entry_url.scheme())
        && input_url.host_str() == entry_url.host_str()
}

// Canonicalises a scheme for comparison. Android native-app association tokens use
// the scheme `android://<packageName>`; KeePassDX / Keepass2Android store the same
// identity as `androidapp://<packageName>`. We treat them as the same app identity
// so databases shared with those apps interoperate. All other schemes (http, https,
// ...) are returned unchanged, so the https/http boundary is preserved.
fn scheme_key(scheme: &str) -> &str {
    if scheme == "androidapp" {
        "android"
    } else {
        scheme
    }
}

// Returns true if any whitespace-separated token in `additional_urls` matches
// `input_url`.
fn any_additional_urls_matching(input_url: &str, additional_urls: &str) -> bool {
    additional_urls
        .split_whitespace()
        .any(|au| url_matched(input_url, au))
}

// Returns the Login-type entries in `db_key` whose URL field (or Additional URLs
// field) matches `input_url`. URL place holders are resolved before matching.
pub fn find_matching_login_entries(db_key: &str, input_url: &str) -> Result<Vec<EntrySummary>> {
    main_content_action!(db_key, |k: &KeepassFile| {
        let summaries = k
            .collect_all_active_entries()
            .iter()
            .filter_map(|e| {
                // Only Login-type entries are offered for autofill.
                if !super::is_autofill_eligible_type(&e.entry_field.entry_type.uuid) {
                    return None;
                }

                let (parsed_fields, entry_fields) =
                    EntryPlaceHolderParser::place_holder_resolved_entry_fields(&k.root, e);

                let url_match = entry_fields
                    .get(URL)
                    .map_or(false, |u| url_matched(input_url, u));

                let matched = url_match
                    || entry_fields
                        .get(ADDITIONAL_URLS)
                        .map_or(false, |urls| any_additional_urls_matching(input_url, urls));

                if !matched {
                    return None;
                }

                let title = entry_fields.get(TITLE).cloned();
                let secondary_title = EntrySummary::secondary_title(e, &parsed_fields);

                Some(EntrySummary {
                    uuid: e.uuid.to_string(),
                    parent_group_uuid: e.parent_group_uuid(),
                    title,
                    secondary_title,
                    entry_type_name: e.entry_field.entry_type.name.clone(),
                    entry_type_uuid: e.entry_field.entry_type.uuid.to_string(),
                    icon_id: e.icon_id,
                    custom_icon_uuid: e.custom_icon_uuid.map(|u| u.to_string()),
                    history_index: None,
                    modified_time: Some(e.times.last_modification_time.and_utc().timestamp()),
                    created_time: Some(e.times.creation_time.and_utc().timestamp()),
                })
            })
            .collect::<Vec<EntrySummary>>();

        Ok(summaries)
    })
}

// Manual (user-typed) autofill search. Returns Login-type entries whose URL
// field or Additional URLs field contains `term` (case-insensitive substring).
//
// Only URL fields are searched - in autofill mode the user is looking for a site,
// so matching other fields (notes, password, custom fields) is not meaningful.
// URL place holders are resolved before matching. An empty term yields no results.
pub fn autofill_search_term(db_key: &str, term: &str) -> Result<EntrySearchResult> {
    let term_lc = term.trim().to_lowercase();

    main_content_action!(db_key, |k: &KeepassFile| {
        let mut result = EntrySearchResult {
            term: term.to_string(),
            entry_items: vec![],
        };

        if term_lc.is_empty() {
            return Ok(result);
        }

        let contains_term = |v: &String| v.to_lowercase().contains(&term_lc);

        for e in k.collect_all_active_entries() {
            // Only Login-type entries are offered for autofill.
            if !super::is_autofill_eligible_type(&e.entry_field.entry_type.uuid) {
                continue;
            }

            let (parsed_fields, entry_fields) =
                EntryPlaceHolderParser::place_holder_resolved_entry_fields(&k.root, e);

            let matched = entry_fields.get(URL).map_or(false, contains_term)
                || entry_fields.get(ADDITIONAL_URLS).map_or(false, contains_term);

            if !matched {
                continue;
            }

            let title = entry_fields.get(TITLE).cloned();
            let secondary_title = EntrySummary::secondary_title(e, &parsed_fields);

            result.entry_items.push(EntrySummary {
                uuid: e.uuid.to_string(),
                parent_group_uuid: e.parent_group_uuid(),
                title,
                secondary_title,
                entry_type_name: e.entry_field.entry_type.name.clone(),
                entry_type_uuid: e.entry_field.entry_type.uuid.to_string(),
                icon_id: e.icon_id,
                custom_icon_uuid: e.custom_icon_uuid.map(|u| u.to_string()),
                history_index: None,
                modified_time: Some(e.times.last_modification_time.and_utc().timestamp()),
                created_time: Some(e.times.creation_time.and_utc().timestamp()),
            });
        }

        Ok(result)
    })
}

// Associates a native-app identity (e.g. "android://com.vanguard.app") with an
// existing entry by appending it to the entry's Additional URLs field, so the app
// is offered for autofill next time. This is the capture-on-fill counterpart to
// url matching: native apps that expose no web domain arrive as android://<pkg>,
// which never matches stored https URLs until the app is associated.
//
// No-op (returns Ok(false)) when an equivalent token is already present - android://
// and androidapp:// are treated as the same identity (see scheme_key) so we neither
// duplicate our own token nor re-add one a KeePassDX-shared db already has. Returns
// Ok(true) when the entry was modified and saved (a history entry is created by
// update_entry_from_form_data, like any other entry edit).
pub fn associate_app_to_entry(db_key: &str, entry_uuid: &Uuid, app_uri: &str) -> Result<bool> {
    let mut form_data = super::get_entry_form_data_by_id(db_key, entry_uuid)?;

    let already_present = form_data.additional_urls().map_or(false, |urls| {
        urls.split_whitespace().any(|t| url_matched(app_uri, t))
    });

    if already_present || !form_data.append_additional_url(app_uri) {
        return Ok(false);
    }

    super::update_entry_from_form_data(db_key, form_data)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_host_different_path_matches() {
        // OAuth / SSO style transient path must still match.
        assert!(url_matched(
            "https://signin.costco.com/abc-123/B2C_1A_SSO/oauth2/v2.0/authorize",
            "https://signin.costco.com/login",
        ));
    }

    #[test]
    fn trailing_slash_difference_matches() {
        assert!(url_matched(
            "https://example.com/login",
            "https://example.com/login/",
        ));
        assert!(url_matched("https://example.com", "https://example.com/"));
    }

    #[test]
    fn exact_host_required_no_subdomain_match() {
        // Keeps exact host: apex <-> www and sibling subdomains do NOT
        // match (that broadening is a deliberate later phase).
        assert!(!url_matched("https://www.viator.com/", "https://viator.com/"));
        assert!(!url_matched(
            "https://mail.google.com/",
            "https://accounts.google.com/",
        ));
    }

    #[test]
    fn phishing_hosts_do_not_match() {
        // Look-alike and suffix-appended hosts must never match.
        assert!(!url_matched(
            "https://paypal.com.evil.com/login",
            "https://paypal.com/login",
        ));
        assert!(!url_matched(
            "https://paypa1.com/login",
            "https://paypal.com/login",
        ));
    }

    #[test]
    fn scheme_must_match() {
        assert!(!url_matched("http://example.com/", "https://example.com/"));
    }

    #[test]
    fn distinct_ip_hosts_do_not_match() {
        assert!(!url_matched("https://10.0.0.1/", "https://10.0.0.2/"));
        assert!(url_matched("https://10.0.0.1/a", "https://10.0.0.1/b"));
    }

    #[test]
    fn unparseable_urls_do_not_match() {
        assert!(!url_matched("not a url", "https://example.com/"));
        assert!(!url_matched("https://example.com/", "also not a url"));
    }

    #[test]
    fn android_app_token_matches() {
        // A native-app request (android://<pkg>) matches a stored token of either
        // scheme, but only for the same package (host).
        assert!(url_matched(
            "android://com.vanguard.app",
            "android://com.vanguard.app",
        ));
        // KeePassDX-style androidapp:// stored token is treated as the same identity.
        assert!(url_matched(
            "android://com.vanguard.app",
            "androidapp://com.vanguard.app",
        ));
        // Different package must not match.
        assert!(!url_matched(
            "android://com.vanguard.app",
            "android://com.evil.app",
        ));
        // The android scheme normalisation must not bleed into web schemes.
        assert!(!url_matched("android://example.com", "https://example.com"));
    }

    #[test]
    fn additional_urls_token_matches() {
        let additional = "https://other.com/x https://example.com/login https://third.com";
        assert!(any_additional_urls_matching(
            "https://example.com/anything",
            additional
        ));
        assert!(!any_additional_urls_matching(
            "https://nomatch.com/",
            additional
        ));
    }
}
