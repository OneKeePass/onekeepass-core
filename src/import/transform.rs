// Value level normalisations applied to a source cell before it becomes an
// ImportedField. Each one is a pure function so it can be unit tested on its own and
// referenced by id from a per-exporter profile.

use crate::db_content::OtpSettings;

// Turns whatever the exporter put in a TOTP column into a canonical otpauth:// url.
// Vendors are inconsistent here - Bitwarden's login_totp is often a bare base32 secret
// while 1Password's OTPAuth is a full url - and a bare secret stored as-is looks like a
// working OTP field but never generates a token.
//
// Returns None when the value cannot be understood, so the caller drops the field
// rather than writing something unusable into the entry.
pub(crate) fn otp_normalise(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Handles both forms: a url is parsed as a url, anything else is treated as a
    // base32 secret and given the standard 30s / 6 digit / SHA1 defaults
    let settings = OtpSettings {
        secret_or_url: trimmed.to_string(),
        period: None,
        digits: None,
        hash_algorithm: None,
    };

    settings.otp_url().ok()
}

// Exporters emit a comma separated tag list; kdbx uses semicolons. Splitting on both
// means an already-semicolon list passes through unchanged while a vendor list is
// converted. Blank entries left by trailing separators are dropped.
pub(crate) fn tags_normalise(value: &str) -> Option<String> {
    let tags: Vec<&str> = value
        .split([',', ';'])
        .map(|tag| tag.trim())
        .filter(|tag| !tag.is_empty())
        .collect();

    if tags.is_empty() {
        None
    } else {
        Some(tags.join(";"))
    }
}

// Splits a "Work/Clients" style folder into nested group names. Only used when the
// exporter is known to write paths this way - in a generic csv a group name is allowed
// to contain a separator, so this must not be applied by default. The separator differs
// per product: most use '/', LastPass uses a backslash.
pub(crate) fn folder_path_split(value: &str, separator: char) -> Vec<String> {
    value
        .split(separator)
        .map(|segment| segment.trim())
        .filter(|segment| !segment.is_empty())
        .map(|segment| segment.to_string())
        .collect()
}

// The whole cell is one group name. This is what a generic csv Group column has always
// meant and stays the default.
pub(crate) fn folder_path_single(value: &str) -> Vec<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        vec![]
    } else {
        vec![trimmed.to_string()]
    }
}

// Highest standard kdbx icon index. The set is shared by every kdbx application, so an
// exporter's icon number means the same thing here - see all-icons in db_icons.cljs,
// which holds 0 to 68
const MAX_STANDARD_ICON_ID: i32 = 68;

// An exporter's icon column into a standard icon index. Anything outside the standard
// set is dropped rather than clamped: a number we do not recognise is more likely to be
// a custom icon reference than a slightly wrong standard one, and the entry is better
// off with its entry type's default icon than with an arbitrary picture.
pub(crate) fn icon_id(value: &str) -> Option<i32> {
    let id: i32 = value.trim().parse().ok()?;
    (0..=MAX_STANDARD_ICON_ID).contains(&id).then_some(id)
}

// Whether a boolean-ish column is set. Exporters disagree on the spelling - Bitwarden
// writes 1, LastPass writes 0 or 1, 1Password leaves the cell empty or puts the word in
// it - so anything not recognised as "off" and not blank counts as set.
pub(crate) fn is_truthy(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    !matches!(
        trimmed.to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "n" | "off"
    )
}

// Adds a tag to an already normalised (semicolon separated) list, leaving it alone when
// the tag is already there.
pub(crate) fn tags_append(tags: Option<String>, extra: &str) -> Option<String> {
    let Some(existing) = tags else {
        return Some(extra.to_string());
    };

    if existing.split(';').any(|tag| tag.trim() == extra) {
        Some(existing)
    } else {
        Some(format!("{existing};{extra}"))
    }
}

// Bitwarden packs an item's custom fields into a single cell, one "name: value" per
// line. Returned in file order so the entry shows them the way the export had them.
//
// A line with no colon is treated as the continuation of the previous value rather than
// discarded, so a multi line custom field survives the round trip. Such a line before
// any named field has nothing to attach to and is dropped.
//
// Hidden (masked) fields are written into the same blob with nothing marking them as
// hidden, so the caller cannot know to protect them - they arrive as ordinary fields.
pub(crate) fn packed_fields(value: &str) -> Vec<(String, String)> {
    let mut fields: Vec<(String, String)> = vec![];

    for line in value.lines() {
        match line.split_once(':') {
            Some((name, field_value)) if !name.trim().is_empty() => {
                fields.push((name.trim().to_string(), field_value.trim().to_string()));
            }
            _ => {
                if let Some((_, previous)) = fields.last_mut() {
                    previous.push('\n');
                    previous.push_str(line);
                }
            }
        }
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_base32_secret_becomes_an_otpauth_url() {
        let url = otp_normalise("JBSWY3DPEHPK3PXP").expect("should normalise");
        assert!(url.starts_with("otpauth://totp/"), "got {url}");
        assert!(url.contains("secret=JBSWY3DPEHPK3PXP"), "got {url}");
    }

    // Bitwarden exports secrets with spaces in them often enough to matter
    #[test]
    fn a_spaced_lowercase_secret_is_accepted() {
        let url = otp_normalise("jbsw y3dp ehpk 3pxp").expect("should normalise");
        assert!(url.contains("secret=JBSWY3DPEHPK3PXP"), "got {url}");
    }

    #[test]
    fn an_existing_otpauth_url_is_preserved() {
        let url =
            otp_normalise("otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=8")
                .expect("should normalise");
        assert!(url.contains("secret=JBSWY3DPEHPK3PXP"), "got {url}");
        assert!(url.contains("digits=8"), "non default digits kept: {url}");
    }

    // Anything we cannot turn into a working token is dropped rather than stored
    #[test]
    fn an_unusable_otp_value_is_dropped() {
        assert!(otp_normalise("").is_none());
        assert!(otp_normalise("   ").is_none());
        // '1' and '8' are not in the base32 alphabet
        assert!(otp_normalise("not-a-secret-18").is_none());
    }

    #[test]
    fn comma_separated_tags_become_semicolon_separated() {
        assert_eq!(tags_normalise("work, email ,social").as_deref(), Some("work;email;social"));
    }

    #[test]
    fn an_already_semicolon_separated_list_is_unchanged() {
        assert_eq!(tags_normalise("work;email").as_deref(), Some("work;email"));
    }

    #[test]
    fn blank_tag_values_are_dropped() {
        assert!(tags_normalise("").is_none());
        assert!(tags_normalise(" , ; ").is_none());
    }

    #[test]
    fn a_folder_path_splits_into_segments() {
        assert_eq!(folder_path_split("Work/Clients", '/'), vec!["Work", "Clients"]);
        assert_eq!(folder_path_split(" Work / Clients ", '/'), vec!["Work", "Clients"]);
        // Leading, trailing and repeated separators do not produce blank groups
        assert_eq!(folder_path_split("/Work//Clients/", '/'), vec!["Work", "Clients"]);
        assert!(folder_path_split("", '/').is_empty());
        assert!(folder_path_split("///", '/').is_empty());
    }

    // LastPass nests with a backslash, and a slash there is part of the name
    #[test]
    fn a_backslash_separator_is_supported() {
        assert_eq!(
            folder_path_split(r"Work\Clients", '\\'),
            vec!["Work", "Clients"]
        );
        assert_eq!(folder_path_split("Work/Clients", '\\'), vec!["Work/Clients"]);
    }

    #[test]
    fn a_single_segment_folder_keeps_its_slashes() {
        assert_eq!(folder_path_single("Work/Clients"), vec!["Work/Clients"]);
        assert_eq!(folder_path_single("  Work  "), vec!["Work"]);
        assert!(folder_path_single("   ").is_empty());
    }

    // The icon numbers seen in a real KeePassXC export
    #[test]
    fn a_standard_icon_number_is_accepted() {
        for value in ["0", "2", "5", "6", "13", "40", "54", "59", "68"] {
            assert_eq!(icon_id(value), Some(value.parse().unwrap()));
        }
        assert_eq!(icon_id(" 13 "), Some(13));
    }

    // Out of range or unparseable leaves the entry with its type's default icon
    #[test]
    fn an_unknown_icon_number_is_dropped() {
        assert_eq!(icon_id("69"), None);
        assert_eq!(icon_id("-1"), None);
        assert_eq!(icon_id(""), None);
        assert_eq!(icon_id("folder"), None);
    }

    // Each exporter spells its favourite flag differently
    #[test]
    fn the_favourite_spellings_of_each_exporter_are_recognised() {
        // Bitwarden and LastPass
        assert!(is_truthy("1"));
        assert!(!is_truthy("0"));
        // 1Password and anything else that writes a word
        assert!(is_truthy("true"));
        assert!(is_truthy("TRUE"));
        assert!(is_truthy(" yes "));
        assert!(!is_truthy("false"));
        assert!(!is_truthy("No"));
        // Not set at all
        assert!(!is_truthy(""));
        assert!(!is_truthy("   "));
    }

    #[test]
    fn a_tag_is_appended_to_an_existing_list() {
        assert_eq!(tags_append(None, "Favorites").as_deref(), Some("Favorites"));
        assert_eq!(
            tags_append(Some("work;email".to_string()), "Favorites").as_deref(),
            Some("work;email;Favorites")
        );
    }

    // The source list may already carry the tag - the entry must not end up with it twice
    #[test]
    fn an_already_present_tag_is_not_added_again() {
        assert_eq!(
            tags_append(Some("Favorites".to_string()), "Favorites").as_deref(),
            Some("Favorites")
        );
        assert_eq!(
            tags_append(Some("work;Favorites;email".to_string()), "Favorites").as_deref(),
            Some("work;Favorites;email")
        );
    }

    #[test]
    fn a_packed_fields_cell_splits_into_named_fields() {
        let fields = packed_fields("Security question: mother\nAccount no: 12345");
        assert_eq!(
            fields,
            vec![
                ("Security question".to_string(), "mother".to_string()),
                ("Account no".to_string(), "12345".to_string()),
            ]
        );
    }

    // A value may itself contain a colon, so only the first one separates
    #[test]
    fn only_the_first_colon_separates_a_packed_field() {
        assert_eq!(
            packed_fields("Recovery url: https://example.com/a:b"),
            vec![(
                "Recovery url".to_string(),
                "https://example.com/a:b".to_string()
            )]
        );
    }

    // A custom field holding several lines must not lose the lines after the first
    #[test]
    fn a_multi_line_packed_value_is_kept_whole() {
        let fields = packed_fields("Address: 12 High Street\nSomewhere\nPhone: 555");
        assert_eq!(
            fields,
            vec![
                ("Address".to_string(), "12 High Street\nSomewhere".to_string()),
                ("Phone".to_string(), "555".to_string()),
            ]
        );
    }

    #[test]
    fn an_empty_or_nameless_packed_cell_produces_nothing() {
        assert!(packed_fields("").is_empty());
        assert!(packed_fields("   ").is_empty());
        // Nothing to attach a continuation line to
        assert!(packed_fields("just some text").is_empty());
        assert!(packed_fields(": no name").is_empty());
    }
}
