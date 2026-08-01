// Per-exporter csv profiles. A profile is a starting point for the column mapping the
// user confirms in the UI - it is never applied silently, and the user can always
// override the detected product or fall back to a generic csv.
//
// The table is compiled in rather than loaded from a json resource. A resource would
// let a profile be corrected without a release, but needs asset path plumbing through
// both the desktop and mobile shells. It is kept as plain data here so moving it out
// later is a mechanical change.

use serde::Serialize;

use super::model::ImportedKind;
use crate::constants::entry_keyvalue_key::{NOTES, OTP, PASSWORD, TITLE, URL, USER_NAME};

// Mirrors the two pseudo fields the csv mapping already understands
const GROUP: &str = "Group";
const TAGS: &str = "Tags";

pub(crate) struct CsvProfile {
    pub(crate) id: &'static str,
    pub(crate) display_name: &'static str,

    // Every one of these must appear in the header row for the profile to match.
    // Comparison is case and whitespace insensitive
    signature: &'static [&'static str],

    // (okp entry field name, source column name)
    mapping: &'static [(&'static str, &'static str)],

    // Separator used inside a group cell when the exporter writes a nested path.
    // None means the whole cell is a single group name
    pub(crate) folder_separator: Option<char>,

    // Column holding the item type, and how its values map to an entry kind. An
    // unlisted value falls back to Login
    pub(crate) type_column: Option<&'static str>,
    pub(crate) type_values: &'static [(&'static str, ImportedKind)],

    // Column marking the item as a favourite. OKP has no favourite flag on an entry -
    // the Favorites category collects entries carrying the "Favorites" tag - so a set
    // value becomes that tag
    pub(crate) favourite_column: Option<&'static str>,

    // Column holding several of the item's own custom fields packed into one cell. Left
    // as-is it imports as a single unreadable blob
    pub(crate) packed_fields_column: Option<&'static str>,

    // Whether the group path starts at the database's own root group. KeePassXC writes
    // "MyDatabase/Work/Clients", where the first segment is the source database name
    // rather than a folder the user made, and importing it as one buries the whole
    // import under a group named after the old database
    pub(crate) strip_root_folder: bool,

    // Top level source folders whose rows are not imported at all. Matched case
    // insensitively against the first segment left after any root strip, so nested
    // folders below one of these go too
    pub(crate) skip_folders: &'static [&'static str],

    // Column holding the standard kdbx icon index of the item
    pub(crate) icon_column: Option<&'static str>,

    // Columns deliberately not imported. Unlike the columns above nothing reads these -
    // they are named so the mapping dialog stops offering them, since turning them into
    // custom fields on every entry produces noise the user then has to delete by hand
    pub(crate) ignored_columns: &'static [&'static str],
}

impl CsvProfile {
    // Resolves this profile's mapping against a real header row. Only columns actually
    // present are returned, so a profile still applies to a slightly trimmed export
    pub(crate) fn mapping_for(&self, headers: &[String]) -> Vec<SuggestedMapping> {
        self.mapping
            .iter()
            .filter_map(|(field_name, source)| {
                headers
                    .iter()
                    .find(|h| eq_loose(h, source))
                    .map(|matched| SuggestedMapping {
                        field_name: field_name.to_string(),
                        mapped_name: matched.clone(),
                    })
            })
            .collect()
    }

    // Columns that never appear in the user visible mapping, and must not be offered as
    // unmapped ones either. Either the profile has already read the column itself - to
    // produce the entry kind, the Favorites tag, the icon or a set of custom fields - or
    // it is one the profile deliberately ignores. Offering any of them again as a raw
    // custom field on every entry is pure noise
    pub(crate) fn consumed_columns(&self, headers: &[String]) -> Vec<String> {
        [
            self.type_column,
            self.favourite_column,
            self.packed_fields_column,
            self.icon_column,
        ]
        .into_iter()
        .flatten()
        .chain(self.ignored_columns.iter().copied())
        .filter_map(|name| headers.iter().find(|h| eq_loose(h, name)).cloned())
        .collect()
    }

    fn matches(&self, headers: &[String]) -> bool {
        self.signature
            .iter()
            .all(|sig| headers.iter().any(|h| eq_loose(h, sig)))
    }
}

fn eq_loose(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

#[derive(Debug, Clone, Serialize)]
pub struct SuggestedMapping {
    pub field_name: String,
    pub mapped_name: String,
}

// Sent to the UI so the mapping dialog can say what was detected and pre-fill itself
#[derive(Debug, Clone, Serialize)]
pub struct DetectedProfile {
    pub id: String,
    pub display_name: String,
    pub mapping: Vec<SuggestedMapping>,

    // Columns this profile reads itself. The UI excludes them from the unmapped set so
    // they are not turned into custom fields
    pub consumed_columns: Vec<String>,
}

impl DetectedProfile {
    pub(crate) fn of(p: &CsvProfile, headers: &[String]) -> Self {
        Self {
            id: p.id.to_string(),
            display_name: p.display_name.to_string(),
            mapping: p.mapping_for(headers),
            consumed_columns: p.consumed_columns(headers),
        }
    }
}

// Listed in the UI override dropdown
#[derive(Debug, Clone, Serialize)]
pub struct ProfileInfo {
    pub id: String,
    pub display_name: String,
}

pub(crate) const PROFILES: &[CsvProfile] = &[
    CsvProfile {
        id: "bitwarden",
        display_name: "Bitwarden",
        signature: &["login_username", "login_password", "login_uri"],
        mapping: &[
            (TITLE, "name"),
            (USER_NAME, "login_username"),
            (PASSWORD, "login_password"),
            (URL, "login_uri"),
            (NOTES, "notes"),
            (OTP, "login_totp"),
            (GROUP, "folder"),
        ],
        folder_separator: Some('/'),
        type_column: Some("type"),
        // A Bitwarden csv only ever carries logins and notes. Notes stay Login with the
        // text in Notes, matching what KeePass and KeePassXC do
        type_values: &[("login", ImportedKind::Login), ("note", ImportedKind::Login)],
        favourite_column: Some("favorite"),
        // Bitwarden puts every custom field an item has into this one cell
        packed_fields_column: Some("fields"),
        strip_root_folder: false,
        skip_folders: &[],
        icon_column: None,
        ignored_columns: &[],
    },
    CsvProfile {
        id: "onepassword",
        display_name: "1Password",
        // Longer than the Safari signature below, which a 1Password row also satisfies
        signature: &["OTPAuth", "Archived", "Favorite", "Tags", "Title"],
        mapping: &[
            (TITLE, "Title"),
            (USER_NAME, "Username"),
            (PASSWORD, "Password"),
            (URL, "Url"),
            (NOTES, "Notes"),
            (OTP, "OTPAuth"),
            (TAGS, "Tags"),
        ],
        folder_separator: None,
        type_column: None,
        type_values: &[],
        favourite_column: Some("Favorite"),
        packed_fields_column: None,
        strip_root_folder: false,
        skip_folders: &[],
        icon_column: None,
        ignored_columns: &[],
    },
    CsvProfile {
        id: "lastpass",
        display_name: "LastPass",
        signature: &["grouping", "extra", "totp", "fav", "name"],
        mapping: &[
            (TITLE, "name"),
            (USER_NAME, "username"),
            (PASSWORD, "password"),
            (URL, "url"),
            (NOTES, "extra"),
            (OTP, "totp"),
            (GROUP, "grouping"),
        ],
        // LastPass nests with a backslash
        folder_separator: Some('\\'),
        type_column: None,
        type_values: &[],
        favourite_column: Some("fav"),
        packed_fields_column: None,
        strip_root_folder: false,
        skip_folders: &[],
        icon_column: None,
        ignored_columns: &[],
    },
    CsvProfile {
        id: "keepassxc",
        display_name: "KeePassXC",
        signature: &["Group", "Title", "TOTP"],
        mapping: &[
            (TITLE, "Title"),
            (USER_NAME, "Username"),
            (PASSWORD, "Password"),
            (URL, "URL"),
            (NOTES, "Notes"),
            (OTP, "TOTP"),
            (GROUP, "Group"),
        ],
        folder_separator: Some('/'),
        type_column: None,
        type_values: &[],
        favourite_column: None,
        packed_fields_column: None,
        // Every row's Group starts with the source database's root group name
        strip_root_folder: true,
        // KeePassXC exports deleted entries too. Importing them would resurrect what the
        // user threw away, so they are left behind. Only the English group name is
        // matched - a localised KeePassXC writes its own spelling and those rows import
        // as an ordinary group
        skip_folders: &["Recycle Bin"],
        // KeePassXC writes the standard kdbx icon index, which means the same here
        icon_column: Some("Icon"),
        // Source timestamps are deliberately not applied to an imported entry
        ignored_columns: &["Last Modified", "Created"],
    },
    CsvProfile {
        id: "nordpass",
        display_name: "NordPass",
        signature: &["cardholdername", "cardnumber", "cvc", "folder", "type"],
        mapping: &[
            (TITLE, "name"),
            (USER_NAME, "username"),
            (PASSWORD, "password"),
            (URL, "url"),
            (NOTES, "note"),
            (GROUP, "folder"),
        ],
        folder_separator: None,
        type_column: Some("type"),
        type_values: &[
            ("password", ImportedKind::Login),
            ("credit_card", ImportedKind::CreditCard),
            ("identity", ImportedKind::Identity),
        ],
        favourite_column: None,
        packed_fields_column: None,
        strip_root_folder: false,
        skip_folders: &[],
        icon_column: None,
        ignored_columns: &[],
    },
    CsvProfile {
        id: "protonpass",
        display_name: "Proton Pass",
        signature: &["vault", "totp", "createTime", "modifyTime", "type"],
        mapping: &[
            (TITLE, "name"),
            (USER_NAME, "username"),
            (PASSWORD, "password"),
            (URL, "url"),
            (NOTES, "note"),
            (OTP, "totp"),
            (GROUP, "vault"),
        ],
        folder_separator: None,
        type_column: Some("type"),
        type_values: &[
            ("login", ImportedKind::Login),
            ("note", ImportedKind::Login),
            ("credit_card", ImportedKind::CreditCard),
        ],
        favourite_column: None,
        packed_fields_column: None,
        strip_root_folder: false,
        skip_folders: &[],
        icon_column: None,
        ignored_columns: &[],
    },
    CsvProfile {
        id: "dashlane",
        display_name: "Dashlane",
        signature: &["otpSecret", "category"],
        mapping: &[
            (TITLE, "title"),
            (USER_NAME, "username"),
            (PASSWORD, "password"),
            (URL, "url"),
            (NOTES, "note"),
            (OTP, "otpSecret"),
            (GROUP, "category"),
        ],
        folder_separator: None,
        type_column: None,
        type_values: &[],
        favourite_column: None,
        packed_fields_column: None,
        strip_root_folder: false,
        skip_folders: &[],
        icon_column: None,
        ignored_columns: &[],
    },
    CsvProfile {
        id: "safari",
        display_name: "Safari / iCloud Passwords",
        signature: &["OTPAuth", "Title", "URL", "Notes"],
        mapping: &[
            (TITLE, "Title"),
            (USER_NAME, "Username"),
            (PASSWORD, "Password"),
            (URL, "URL"),
            (NOTES, "Notes"),
            (OTP, "OTPAuth"),
        ],
        folder_separator: None,
        type_column: None,
        type_values: &[],
        favourite_column: None,
        packed_fields_column: None,
        strip_root_folder: false,
        skip_folders: &[],
        icon_column: None,
        ignored_columns: &[],
    },
    CsvProfile {
        id: "firefox",
        display_name: "Firefox",
        signature: &["formActionOrigin", "httpRealm", "guid"],
        mapping: &[
            // Firefox exports no title column, so the url doubles as one
            (TITLE, "url"),
            (USER_NAME, "username"),
            (PASSWORD, "password"),
            (URL, "url"),
        ],
        folder_separator: None,
        type_column: None,
        type_values: &[],
        favourite_column: None,
        packed_fields_column: None,
        strip_root_folder: false,
        skip_folders: &[],
        icon_column: None,
        ignored_columns: &[],
    },
    CsvProfile {
        id: "chrome",
        display_name: "Chrome / Edge",
        // The most generic row there is. Every profile that could also match a Chrome
        // export therefore needs a signature longer than this one
        signature: &["name", "url", "username", "password"],
        mapping: &[
            (TITLE, "name"),
            (USER_NAME, "username"),
            (PASSWORD, "password"),
            (URL, "url"),
            (NOTES, "note"),
        ],
        folder_separator: None,
        type_column: None,
        type_values: &[],
        favourite_column: None,
        packed_fields_column: None,
        strip_root_folder: false,
        skip_folders: &[],
        icon_column: None,
        ignored_columns: &[],
    },
];

pub(crate) fn by_id(id: &str) -> Option<&'static CsvProfile> {
    PROFILES.iter().find(|p| p.id == id)
}

// The most specific match wins. Several exporters share the plain
// name/url/username/password columns, so a profile that pins down more columns is
// preferred over one that pins down fewer
pub(crate) fn detect(headers: &[String]) -> Option<&'static CsvProfile> {
    PROFILES
        .iter()
        .filter(|p| p.matches(headers))
        .max_by_key(|p| p.signature.len())
}

pub fn all_profiles() -> Vec<ProfileInfo> {
    PROFILES
        .iter()
        .map(|p| ProfileInfo {
            id: p.id.to_string(),
            display_name: p.display_name.to_string(),
        })
        .collect()
}

// Returns None for an unknown id, which the UI treats as "map it by hand"
pub fn profile_mapping(profile_id: &str, headers: &[String]) -> Option<DetectedProfile> {
    by_id(profile_id).map(|p| DetectedProfile::of(p, headers))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn bitwarden_headers() -> Vec<String> {
        headers(&[
            "folder",
            "favorite",
            "type",
            "name",
            "notes",
            "fields",
            "reprompt",
            "login_uri",
            "login_username",
            "login_password",
            "login_totp",
        ])
    }

    fn onepassword_headers() -> Vec<String> {
        headers(&[
            "Title", "Url", "Username", "Password", "OTPAuth", "Favorite", "Archived", "Tags",
            "Notes",
        ])
    }

    #[test]
    fn the_sample_exports_are_detected() {
        assert_eq!(detect(&bitwarden_headers()).unwrap().id, "bitwarden");
        assert_eq!(detect(&onepassword_headers()).unwrap().id, "onepassword");
    }

    // The real header row of a KeePassXC export. It carries no column any other profile
    // keys on, so nothing competes with it
    #[test]
    fn a_keepassxc_export_is_detected_and_fully_mapped() {
        let kxc = headers(&[
            "Group",
            "Title",
            "Username",
            "Password",
            "URL",
            "Notes",
            "TOTP",
            "Icon",
            "Last Modified",
            "Created",
        ]);

        let profile = detect(&kxc).unwrap();
        assert_eq!(profile.id, "keepassxc");
        assert!(profile.strip_root_folder, "paths start at the source root");

        let mapping = profile.mapping_for(&kxc);
        for expected in ["Group", "Title", "Username", "Password", "URL", "Notes", "TOTP"] {
            assert!(
                mapping.iter().any(|m| m.mapped_name == expected),
                "{expected} should be mapped"
            );
        }
        assert_eq!(mapping.len(), 7);

        // Every remaining column is accounted for, so a KeePassXC export leaves the user
        // with nothing unmapped to decide about. Icon is read by the profile itself, the
        // two timestamps are deliberately not imported
        assert_eq!(
            profile.consumed_columns(&kxc),
            vec!["Icon", "Last Modified", "Created"]
        );
    }

    #[test]
    fn an_unknown_header_row_matches_nothing() {
        assert!(detect(&headers(&["a", "b", "c"])).is_none());
        assert!(detect(&[]).is_none());
    }

    // Chrome's signature is a subset of several richer exports. Longest signature wins,
    // so a NordPass file must not be taken for a Chrome one
    #[test]
    fn the_most_specific_profile_wins_over_a_subset() {
        let nordpass = headers(&[
            "name",
            "url",
            "username",
            "password",
            "note",
            "cardholdername",
            "cardnumber",
            "cvc",
            "folder",
            "type",
        ]);
        assert_eq!(detect(&nordpass).unwrap().id, "nordpass");

        let chrome = headers(&["name", "url", "username", "password", "note"]);
        assert_eq!(detect(&chrome).unwrap().id, "chrome");
    }

    // Safari and 1Password overlap almost completely. A Safari file has no Archived or
    // Tags column, so only Safari matches it; a 1Password file matches both and the
    // longer 1Password signature has to win
    #[test]
    fn safari_and_onepassword_are_told_apart() {
        let safari = headers(&["Title", "URL", "Username", "Password", "Notes", "OTPAuth"]);
        assert_eq!(detect(&safari).unwrap().id, "safari");
        assert_eq!(detect(&onepassword_headers()).unwrap().id, "onepassword");
    }

    #[test]
    fn detection_ignores_case_and_padding() {
        let padded = headers(&[" Folder ", "TYPE", "Name", "LOGIN_URI", "login_username", "login_password"]);
        assert_eq!(detect(&padded).unwrap().id, "bitwarden");
    }

    #[test]
    fn a_mapping_uses_the_actual_header_spelling() {
        let padded = headers(&["  LOGIN_USERNAME  ", "login_password", "login_uri", "name"]);
        let mapping = by_id("bitwarden").unwrap().mapping_for(&padded);

        let user = mapping.iter().find(|m| m.field_name == "UserName").unwrap();
        assert_eq!(
            user.mapped_name, "  LOGIN_USERNAME  ",
            "must return the header exactly as it appears in the file"
        );
    }

    // A profile still applies when the export is missing some optional columns
    #[test]
    fn columns_absent_from_the_file_are_not_suggested() {
        let trimmed = headers(&["name", "login_username", "login_password", "login_uri"]);
        let mapping = by_id("bitwarden").unwrap().mapping_for(&trimmed);

        assert!(mapping.iter().all(|m| m.field_name != "Group"));
        assert!(mapping.iter().all(|m| m.field_name != "otp"));
        assert!(mapping.iter().any(|m| m.field_name == "Title"));
    }

    // Columns the profile reads itself must be reported as consumed and never offered to
    // the user as unmapped ones - they have already produced the entry kind, the
    // Favorites tag and the item's custom fields
    #[test]
    fn columns_the_profile_reads_itself_are_reported_as_consumed() {
        let consumed = by_id("bitwarden")
            .unwrap()
            .consumed_columns(&bitwarden_headers());
        assert_eq!(consumed, vec!["type", "favorite", "fields"]);

        // 1Password has only a favourite column
        assert_eq!(
            by_id("onepassword")
                .unwrap()
                .consumed_columns(&onepassword_headers()),
            vec!["Favorite"]
        );

        // A profile that reads no column of its own consumes nothing
        assert!(by_id("safari")
            .unwrap()
            .consumed_columns(&headers(&["Title", "URL", "Username", "Password", "OTPAuth"]))
            .is_empty());
    }

    // A file that simply has no such column must not report a phantom one
    #[test]
    fn a_missing_consumed_column_is_not_reported() {
        let no_type = headers(&["name", "login_username", "login_password", "login_uri"]);
        assert!(by_id("bitwarden")
            .unwrap()
            .consumed_columns(&no_type)
            .is_empty());
    }

    #[test]
    fn every_profile_id_is_unique() {
        let mut ids: Vec<&str> = PROFILES.iter().map(|p| p.id).collect();
        ids.sort();
        let count = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), count, "duplicate profile id");
    }
}
