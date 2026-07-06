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

use crate::constants::entry_keyvalue_key::{ADDITIONAL_URLS, NOTES, OTP, TITLE, URL, USER_NAME};
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

// How strongly a stored entry URL matches the incoming login URL, strongest first.
// Also the substrate for a future exact-vs-registrable user setting (which would
// keep only `ExactHost` when strict). Ordered so a smaller `as u8` is stronger.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MatchStrength {
    ExactHost = 0,
    RegistrableDomain = 1,
}

// Decides whether a stored entry URL matches the incoming login URL, and how
// strongly (None = no match).
//
// Matching (see the URL-Matching-Relaxation plan): require scheme + a host match
// and ignore the path. The path is dropped because real login flows (OAuth / SSO)
// use transient paths and trailing-slash differences are common.
//
// Host matching: exact host is the strongest match (covers IP literals and android
// app tokens). Otherwise a web request matches - more weakly - when the two hosts
// share a registrable domain (eTLD+1) per the Public Suffix List, so secure.chase.com
// and www.chase.com both reduce to chase.com and match. This is the phishing
// boundary: it moves from exact host to registrable domain (the standard password
// manager model). paypal.com.evil.com reduces to evil.com and stays rejected;
// multi-part suffixes (bbc.co.uk vs hmrc.co.uk) and shared suffixes (a.github.io
// vs b.github.io) stay non-matching because the PSL is authoritative. The scheme is
// kept so an https credential is not offered on an http page. Port is not compared.
fn url_match_strength(input: &str, entry_field_val: &str) -> Option<MatchStrength> {
    let input_url = Url::parse(input).ok()?;
    let entry_url = Url::parse(entry_field_val).ok()?;

    if scheme_key(input_url.scheme()) != scheme_key(entry_url.scheme()) {
        return None;
    }

    let (input_host, entry_host) = (input_url.host_str()?, entry_url.host_str()?);

    // Exact host is the strongest match. Also covers android://<packageName> tokens
    // (host = package name) and IP literals.
    if input_host == entry_host {
        return Some(MatchStrength::ExactHost);
    }

    // For web requests, two hosts are the same site (weaker match) when they share a
    // registrable domain (eTLD+1) per the PSL. Non-web schemes require exact host.
    if is_web_scheme(input_url.scheme()) {
        if let (Some(input_domain), Some(entry_domain)) =
            (registrable_domain(input_host), registrable_domain(entry_host))
        {
            if input_domain == entry_domain {
                return Some(MatchStrength::RegistrableDomain);
            }
        }
    }

    None
}

// Whether a stored entry URL matches at all (any strength). Thin wrapper so callers
// that only need a yes/no (Additional-URLs dedup, place-holder URL match) are
// unchanged.
fn url_matched(input: &str, entry_field_val: &str) -> bool {
    url_match_strength(input, entry_field_val).is_some()
}

// http/https are the schemes where Public-Suffix registrable-domain matching is
// meaningful. Other schemes fall back to exact host equality.
fn is_web_scheme(scheme: &str) -> bool {
    matches!(scheme, "http" | "https")
}

// Registrable domain (eTLD+1) of a host per the embedded Public Suffix List, or
// None for IP literals and hosts without a valid registrable domain. The list is
// compiled into the binary by the `psl` crate, so this is an offline in-memory
// lookup (no network / file I/O).
fn registrable_domain(host: &str) -> Option<String> {
    psl::domain_str(host).map(|d| d.to_ascii_lowercase())
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

// Best (strongest) match among the whitespace-separated tokens in `additional_urls`,
// or None if none match.
fn additional_urls_match_strength(input_url: &str, additional_urls: &str) -> Option<MatchStrength> {
    additional_urls
        .split_whitespace()
        .filter_map(|au| url_match_strength(input_url, au))
        .min_by_key(|s| *s as u8)
}

// Sort key for auto-match results: (host strength, field source), smaller = better.
// Primary key host strength (exact host before registrable-domain); secondary key
// field source (URL field before Additional-URLs). Returns the best pairing across
// the entry's URL-field and Additional-URLs matches, or None when neither matched.
fn match_rank(
    url_field_strength: Option<MatchStrength>,
    additional_urls_strength: Option<MatchStrength>,
) -> Option<(u8, u8)> {
    // field source: URL field = 0, Additional URLs = 1
    let url_pair = url_field_strength.map(|s| (s as u8, 0u8));
    let additional_pair = additional_urls_strength.map(|s| (s as u8, 1u8));
    [url_pair, additional_pair].into_iter().flatten().min()
}

// Returns the autofill-eligible entries in `db_key` whose URL field (or Additional
// URLs field) matches `input_url`, ordered by match strength: exact host before
// registrable-domain (primary), URL-field before Additional-URLs (secondary). URL
// place holders are resolved before matching.
pub fn find_matching_login_entries(db_key: &str, input_url: &str) -> Result<Vec<EntrySummary>> {
    main_content_action!(db_key, |k: &KeepassFile| {
        // (rank, summary) pairs; rank = (host strength, field source), smaller = better.
        let mut ranked: Vec<((u8, u8), EntrySummary)> = k
            .collect_all_active_entries()
            .iter()
            .filter_map(|e| {
                // Only autofill-eligible types (Login / Card / Bank) are offered.
                if !super::is_autofill_eligible_type(&e.entry_field.entry_type.uuid) {
                    return None;
                }

                let (parsed_fields, entry_fields) =
                    EntryPlaceHolderParser::place_holder_resolved_entry_fields(&k.root, e);

                let url_field_strength = entry_fields
                    .get(URL)
                    .and_then(|u| url_match_strength(input_url, u));
                let additional_urls_strength = entry_fields
                    .get(ADDITIONAL_URLS)
                    .and_then(|urls| additional_urls_match_strength(input_url, urls));

                let rank = match_rank(url_field_strength, additional_urls_strength)?;

                let title = entry_fields.get(TITLE).cloned();
                let secondary_title = EntrySummary::secondary_title(e, &parsed_fields);

                Some((
                    rank,
                    EntrySummary {
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
                    },
                ))
            })
            .collect();

        // Stable sort by rank; entries with the same rank keep their database order.
        ranked.sort_by_key(|(rank, _)| *rank);
        let summaries = ranked.into_iter().map(|(_, summary)| summary).collect();

        Ok(summaries)
    })
}

// Field names never matched by the manual autofill search. Notes and the one-time
// password (OTP) are not site/identity search targets - OTP also holds a shared
// secret - and passkey (KPEX_*) fields hold credential material. Protected fields
// (Password and any protected custom field) are excluded separately via the
// KeyValue `protected` flag, so a search never keys off a secret value.
fn is_search_excluded_field(key: &str) -> bool {
    key == NOTES || key == OTP || key.starts_with("KPEX_PASSKEY")
}

// Priority of a matched field for ordering manual-search results (lower = higher
// priority). URL and Additional URLs (the site the user is looking for) rank above
// Title and UserName, which rank above any other non-protected custom field.
fn search_field_priority(key: &str) -> u8 {
    match key {
        URL => 0,
        ADDITIONAL_URLS => 1,
        TITLE => 2,
        USER_NAME => 3,
        _ => 4,
    }
}

// Manual (user-typed) autofill search. Returns autofill-eligible entries (Login /
// Card / Bank, see is_autofill_eligible_type) with a case-insensitive substring
// match in any of their "selective" fields: URL, Additional URLs, Title, UserName
// and any non-protected custom field. Protected fields (Password, protected custom
// fields) and the excluded set (Notes / OTP / passkey KPEX_*) are never matched.
// URL place holders are resolved before matching. An empty term yields no results.
//
// The earlier, stricter URL-only version is kept for reference in the commented-out
// `autofill_search_term_url_only` below. Ordering results by field priority
// (url > additional urls > title > ...) is a separate ranking step, not done here.
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

        // (priority, summary) pairs; the priority is the best (lowest) rank among the
        // entry's matching fields, used to order results url > additional urls >
        // title > username > other custom fields.
        let mut ranked: Vec<(u8, EntrySummary)> = vec![];

        for e in k.collect_all_active_entries() {
            // Only autofill-eligible types (Login / Card / Bank) are offered.
            if !super::is_autofill_eligible_type(&e.entry_field.entry_type.uuid) {
                continue;
            }

            let (parsed_fields, entry_fields) =
                EntryPlaceHolderParser::place_holder_resolved_entry_fields(&k.root, e);

            // Best (lowest) priority among the entry's matching non-protected,
            // non-excluded fields. get_key_values carries the per-field protected
            // flag; entry_fields carries the place-holder resolved value (fall back
            // to the raw value when a field was not resolved). None => no field matched.
            let best_rank = e
                .entry_field
                .get_key_values()
                .iter()
                .filter(|kv| !kv.protected && !is_search_excluded_field(&kv.key))
                .filter(|kv| {
                    let value = entry_fields.get(&kv.key).unwrap_or(&kv.value);
                    value.to_lowercase().contains(&term_lc)
                })
                .map(|kv| search_field_priority(&kv.key))
                .min();

            let Some(rank) = best_rank else {
                continue;
            };

            let title = entry_fields.get(TITLE).cloned();
            let secondary_title = EntrySummary::secondary_title(e, &parsed_fields);

            ranked.push((
                rank,
                EntrySummary {
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
                },
            ));
        }

        // Stable sort by field priority; entries that matched the same field keep
        // their database order.
        ranked.sort_by_key(|(rank, _)| *rank);
        result.entry_items = ranked.into_iter().map(|(_, summary)| summary).collect();

        Ok(result)
    })
}

/*
// Reference (kept, not compiled): the earlier URL-only manual autofill search.
// Matched only the URL and Additional URLs fields (case-insensitive substring),
// on the rationale that in autofill mode the user is looking for a site so other
// fields are not meaningful. Superseded by the selective-fields search above, which
// also matches Title / UserName / non-protected custom fields.
pub fn autofill_search_term_url_only(db_key: &str, term: &str) -> Result<EntrySearchResult> {
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
*/

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
    fn same_registrable_domain_matches() {
        // Phase 2: apex <-> www and sibling subdomains match when they share a
        // registrable domain (eTLD+1).
        assert!(url_matched("https://www.viator.com/", "https://viator.com/"));
        assert!(url_matched(
            "https://mail.google.com/",
            "https://accounts.google.com/",
        ));
        // The reported bank cases: login host differs from the stored host only by
        // subdomain.
        assert!(url_matched(
            "https://staticweb.bankofamerica.com/cavmwebbactouch/common/index.html#home",
            "https://www.bankofamerica.com/",
        ));
        assert!(url_matched(
            "https://secure.chase.com/web/auth/?fromOrigin=x#/logon",
            "https://www.chase.com/",
        ));
        assert!(url_matched(
            "https://sws-gateway-nr.schwab.com/ui/host/#/login-one-step",
            "https://www.schwab.com",
        ));
        assert!(url_matched(
            "https://sws-gateway-nr.schwab.com/ui/host/#/login-one-step",
            "https://client.schwab.com/Areas/Access/Login",
        ));
    }

    #[test]
    fn phishing_hosts_do_not_match() {
        // Look-alike and suffix-appended hosts must never match. Registrable-domain
        // matching keeps these rejected: evil.com != paypal.com, paypa1.com != paypal.com.
        assert!(!url_matched(
            "https://paypal.com.evil.com/login",
            "https://paypal.com/login",
        ));
        assert!(!url_matched(
            "https://paypa1.com/login",
            "https://paypal.com/login",
        ));
        // Multi-part public suffix: distinct sites under co.uk must not collapse to co.uk.
        assert!(!url_matched("https://bbc.co.uk/", "https://hmrc.co.uk/"));
        // Shared public suffix: distinct sites under github.io must not match.
        assert!(!url_matched(
            "https://alice.github.io/",
            "https://bob.github.io/",
        ));
        // Same registrable domain across a multi-part suffix still matches.
        assert!(url_matched("https://www.bbc.co.uk/", "https://bbc.co.uk/"));
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
    fn search_excluded_fields() {
        use crate::constants::entry_keyvalue_key::{
            ADDITIONAL_URLS, KPEX_PASSKEY_CREDENTIAL_ID, NOTES, OTP, TITLE, URL, USER_NAME,
        };
        // Never searched: Notes, OTP, passkey fields.
        assert!(is_search_excluded_field(NOTES));
        assert!(is_search_excluded_field(OTP));
        assert!(is_search_excluded_field(KPEX_PASSKEY_CREDENTIAL_ID));
        // Searched (not excluded here; Password is dropped via the protected flag).
        assert!(!is_search_excluded_field(URL));
        assert!(!is_search_excluded_field(ADDITIONAL_URLS));
        assert!(!is_search_excluded_field(TITLE));
        assert!(!is_search_excluded_field(USER_NAME));
        assert!(!is_search_excluded_field("My Custom Field"));
    }

    #[test]
    fn search_field_priority_order() {
        use crate::constants::entry_keyvalue_key::{ADDITIONAL_URLS, TITLE, URL, USER_NAME};
        // url > additional urls > title > username > other custom fields.
        assert!(
            search_field_priority(URL)
                < search_field_priority(ADDITIONAL_URLS)
        );
        assert!(search_field_priority(ADDITIONAL_URLS) < search_field_priority(TITLE));
        assert!(search_field_priority(TITLE) < search_field_priority(USER_NAME));
        assert!(search_field_priority(USER_NAME) < search_field_priority("My Custom Field"));
    }

    #[test]
    fn match_rank_orders_host_strength_then_field_source() {
        use MatchStrength::{ExactHost, RegistrableDomain};

        let url_exact = match_rank(Some(ExactHost), None); // (0,0)
        let add_exact = match_rank(None, Some(ExactHost)); // (0,1)
        let url_reg = match_rank(Some(RegistrableDomain), None); // (1,0)
        let add_reg = match_rank(None, Some(RegistrableDomain)); // (1,1)

        assert_eq!(match_rank(None, None), None);
        // Same host strength: URL field ranks above Additional-URLs.
        assert!(url_exact < add_exact);
        // Host strength is primary: an exact Additional-URLs match beats a
        // registrable URL-field match.
        assert!(add_exact < url_reg);
        assert!(url_reg < add_reg);
        // When both fields match, the stronger pairing is chosen.
        assert_eq!(match_rank(Some(RegistrableDomain), Some(ExactHost)), add_exact);
    }

    #[test]
    fn additional_urls_token_matches() {
        let additional = "https://other.com/x https://example.com/login https://third.com";
        assert!(additional_urls_match_strength("https://example.com/anything", additional).is_some());
        assert!(additional_urls_match_strength("https://nomatch.com/", additional).is_none());
    }
}
