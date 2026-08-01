use std::{collections::HashMap, path::Path, sync::Mutex};

use csv::ReaderBuilder;
use log::debug;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{
    constants::{
        entry_keyvalue_key::{OTP, PASSWORD},
        general_category_names::FAVORITES,
    },
    db::NewDatabase,
    db_content::KeepassFile,
    db_service::{self, call_kdbx_context_mut_action, call_main_content_mut_action, KdbxContext},
    error::Result,
    form_data::KdbxLoaded,
    main_content_mut_action,
};

use super::{
    model::{ImportedField, ImportedItem, ImportedKind},
    profile::{self, DetectedProfile},
    transform,
    writer::ImportWriter,
};

const GROUP: &str = "Group";

const TAGS: &str = "Tags";

// Fields routed to 'CsvLookup.other_fields' instead of becoming entry key values.
// Only GROUP and TAGS are acted on. "Modified Time" and "Created Time" are listed
// deliberately so that, if they are ever mapped, they are ignored rather than turned
// into junk custom fields named "Modified Time". Applying a source timestamp to an
// imported entry was considered and rejected. Both are currently commented out in the
// UI mapping list, so they cannot be reached at all today.
const OTHER_FIELDS: [&str; 4] = [GROUP, TAGS, "Modified Time", "Created Time"];

// A csv record held in memory as owned strings. csv::StringRecord does not expose its
// internal buffer, so records are stored this way to be zeroized - they hold every
// plaintext password in the user's export.
type CsvDataRecord = Vec<String>;

fn zeroize_records(records: &mut Vec<CsvDataRecord>) {
    for record in records.iter_mut() {
        for field in record.iter_mut() {
            field.zeroize();
        }
    }
    records.clear();
}

const IMPORT_DEFAULT_GROUP: &str = "CsvImported";

// Similar to okp-filed-to-csv-header-mapping in cljs
#[derive(Debug, Deserialize)]
pub struct MappedField {
    // This indicates one of entry field 'key' (see )
    field_name: String,

    // This is the header field
    mapped_name: String,
}

#[derive(Debug, Deserialize)]
pub struct CsvImportMapping {
    // The original header fields
    headers: Vec<String>,

    mapped_fields: Vec<MappedField>,

    // Header fields not mapped to any of the entry fields
    not_mapped_headers: Vec<String>,

    // Indicates that we need to create custom fields
    unmapped_custom_field: bool,

    // Exporter profile the user confirmed in the mapping dialog, if any. It supplies
    // the group path separator and the item type column. Absent means a generic csv
    #[serde(default)]
    profile_id: Option<String>,
}

impl CsvImportMapping {
    // create_new_db_with_imported_csv
    pub fn create_new_db(&self, new_db: NewDatabase) -> Result<KdbxLoaded> {
        let mut kdbx_file = new_db.create()?;
        let keepass_file = kdbx_file.keepass_main_content_mut();

        debug!("Going to apply the imported data");

        self.apply_imported_csv_data(keepass_file)?;

        // After creating the content from csv data, we need to write the new db to the file system
        db_service::write_new_db_kdbx_file(kdbx_file)
    }

    pub fn import_into_db(&self, db_key: &str) -> Result<()> {
        main_content_mut_action!(db_key, |k: &mut KeepassFile| {
            self.apply_imported_csv_data(k)?;
            Ok(())
        })
    }

    // Creates all required groups and entries from the previously loaded csv records
    fn apply_imported_csv_data(&self, keepass_file: &mut KeepassFile) -> Result<()> {
        let CsvImportMapping {
            headers,
            mapped_fields,
            not_mapped_headers,
            unmapped_custom_field,
            profile_id,
        } = self;

        let profile = profile_id.as_deref().and_then(profile::by_id);

        // First we create a easy look up map so as to locate the field value from the StringRecord
        let field_to_index: (
            HashMap<String, usize>,
            HashMap<String, usize>,
            HashMap<String, usize>,
        ) = headers.iter().enumerate().fold(
            (HashMap::default(), HashMap::default(), HashMap::default()),
            |(mut acc1, mut acc2, mut acc3), (idx, header_item)| {
                if let Some(mapped_field_found) = mapped_fields
                    .iter()
                    .find(|mapped_field_item| &mapped_field_item.mapped_name == header_item)
                {
                    if OTHER_FIELDS.contains(&mapped_field_found.field_name.as_str()) {
                        // Optionally Group or Tags field to index of 'StringRecord'
                        acc1.insert(mapped_field_found.field_name.clone(), idx);
                        (acc1, acc2, acc3)
                    } else {
                        // Standard entry fields to index of 'StringRecord'
                        acc2.insert(mapped_field_found.field_name.clone(), idx);
                        (acc1, acc2, acc3)
                    }
                } else if *unmapped_custom_field && not_mapped_headers.contains(header_item) {
                    // Custom fields to index of 'StringRecord'
                    // The custom field name will be the same as header name
                    acc3.insert(header_item.to_string(), idx);
                    (acc1, acc2, acc3)
                } else {
                    (acc1, acc2, acc3)
                }
            },
        );

        // These columns are named by the profile, not by the user's mapping, so they are
        // resolved against the raw header row
        let column_index = |name: Option<&'static str>| {
            name.and_then(|name| {
                headers
                    .iter()
                    .position(|h| h.trim().eq_ignore_ascii_case(name.trim()))
            })
        };

        let csv_lookup = CsvLookup {
            other_fields: field_to_index.0,
            standard_fields: field_to_index.1,
            custom_fields: field_to_index.2,
            // Without a profile a Group cell is one group name, slashes included
            folder_separator: profile.and_then(|p| p.folder_separator),
            type_column: column_index(profile.and_then(|p| p.type_column)),
            type_values: profile.map_or(&[], |p| p.type_values),
            favourite_column: column_index(profile.and_then(|p| p.favourite_column)),
            packed_fields_column: column_index(profile.and_then(|p| p.packed_fields_column)),
            strip_root_folder: profile.map_or(false, |p| p.strip_root_folder),
            skip_folders: profile.map_or(&[], |p| p.skip_folders),
            icon_column: column_index(profile.and_then(|p| p.icon_column)),
        };

        // The csv records are turned into the canonical import model first, and a single
        // writer puts them into the database. Group creation, entry type selection and
        // field writing therefore live in one place shared with future source formats
        let items = CsvImport::imported_items(&csv_lookup);

        let writer = ImportWriter {
            default_group_name: IMPORT_DEFAULT_GROUP.to_string(),
        };
        writer.write(&items, keepass_file)?;

        CsvImport::clear_stored_records();

        Ok(())
    }
}

// Resolves a csv record's cells into the canonical import model. Holds only the column
// indexes worked out from the user's mapping - it does not touch the database
struct CsvLookup {
    // Key is from OTHER_FIELDS
    other_fields: HashMap<String, usize>,
    // Key is the Entry field name (UserName, Password....)
    standard_fields: HashMap<String, usize>,
    // Key is the unmapped csv header field name
    custom_fields: HashMap<String, usize>,

    // Separator inside a Group cell when the exporter writes a nested path. None for a
    // generic csv, where a group name is allowed to contain a slash
    folder_separator: Option<char>,

    // Column holding the source item type, and how its values map to an entry kind.
    // Only a profile can identify these
    type_column: Option<usize>,
    type_values: &'static [(&'static str, ImportedKind)],

    // Column marking the item as a favourite, becoming the "Favorites" tag
    favourite_column: Option<usize>,

    // Column holding several custom fields packed into one cell
    packed_fields_column: Option<usize>,

    // Whether the first group segment is the source database's own root group
    strip_root_folder: bool,

    // Source folders whose rows are dropped rather than imported
    skip_folders: &'static [&'static str],

    // Column holding the standard kdbx icon index
    icon_column: Option<usize>,
}

impl CsvLookup {
    fn to_imported_items(&self, records: &Vec<CsvDataRecord>) -> Vec<ImportedItem> {
        records
            .iter()
            .filter(|r| !self.is_skipped(r))
            .map(|r| self.to_imported_item(r))
            .collect()
    }

    // Rows the profile says not to import at all, such as an exported recycle bin
    fn is_skipped(&self, csv_record: &CsvDataRecord) -> bool {
        if self.skip_folders.is_empty() {
            return false;
        }

        self.folder_path(csv_record)
            .first()
            .map_or(false, |segment| {
                self.skip_folders
                    .iter()
                    .any(|skipped| skipped.eq_ignore_ascii_case(segment))
            })
    }

    fn to_imported_item(&self, csv_record: &CsvDataRecord) -> ImportedItem {
        ImportedItem {
            kind: self.kind(csv_record),
            folder_path: self.folder_path(csv_record),
            fields: self.fields(csv_record),
            tags: self.tags(csv_record),
            icon_id: self
                .icon_column
                .and_then(|i| csv_record.get(i))
                .and_then(|v| transform::icon_id(v)),
        }
    }

    // An exporter's favourite flag has no equivalent field on a kdbx entry. OKP's
    // Favorites category is a tag query, so setting that tag is what makes the imported
    // entry appear there
    fn tags(&self, csv_record: &CsvDataRecord) -> Option<String> {
        let tags = self
            .other_fields
            .get(TAGS)
            .and_then(|i| csv_record.get(*i))
            .and_then(|v| transform::tags_normalise(v));

        let favourite = self
            .favourite_column
            .and_then(|i| csv_record.get(i))
            .map_or(false, |v| transform::is_truthy(v));

        if favourite {
            transform::tags_append(tags, FAVORITES)
        } else {
            tags
        }
    }

    // A row's entry kind comes from the exporter's item type column. Without a profile
    // there is no such column and everything stays a Login, which is what a generic csv
    // has always produced. An unrecognised value also falls back to Login
    fn kind(&self, csv_record: &CsvDataRecord) -> ImportedKind {
        self.type_column
            .and_then(|i| csv_record.get(i))
            .map(|value| value.trim())
            .and_then(|value| {
                self.type_values
                    .iter()
                    .find(|(source, _)| source.eq_ignore_ascii_case(value))
                    .map(|(_, kind)| *kind)
            })
            .unwrap_or_default()
    }

    // An empty or blank group cell is treated the same as no group mapping at all.
    // Exporters emit an empty folder for unfiled items (Bitwarden does), and without
    // this filter such rows would land in a group with a blank name
    fn folder_path(&self, csv_record: &CsvDataRecord) -> Vec<String> {
        let mut path = self
            .other_fields
            .get(GROUP)
            .and_then(|i| csv_record.get(*i))
            .map(|value| match self.folder_separator {
                Some(separator) => transform::folder_path_split(value, separator),
                None => transform::folder_path_single(value),
            })
            .unwrap_or_default();

        // An exporter that writes the path from its own root leaves the source database
        // name as the first segment. Kept as a folder it would bury the whole import one
        // level down under the name of the database being left behind. A row directly at
        // the source root is left with no path and goes to the default import group
        if self.strip_root_folder && !path.is_empty() {
            path.remove(0);
        }

        path
    }

    fn fields(&self, csv_record: &CsvDataRecord) -> Vec<ImportedField> {
        let standard = self
            .standard_fields
            .iter()
            .map(|(name, i)| (name, i, name == PASSWORD, false));
        // A column the profile reads itself is already excluded from the unmapped set by
        // the mapping dialog. Filtering here too means a stale mapping cannot import the
        // packed cell as one raw blob alongside the fields expanded out of it
        let consumed = [self.favourite_column, self.packed_fields_column];
        let custom = self
            .custom_fields
            .iter()
            .filter(move |(_, i)| !consumed.contains(&Some(**i)))
            .map(|(name, i)| (name, i, false, true));

        let mut fields: Vec<ImportedField> = standard
            .chain(custom)
            .filter_map(|(name, i, protected, custom)| {
                let value = csv_record.get(*i)?;

                // A TOTP column is normalised to a canonical otpauth:// url. Vendors
                // write either a bare base32 secret or a full url, and a bare secret
                // stored as-is looks like a working OTP field but never generates a
                // token. An unusable value drops the field instead
                let value = if name == OTP {
                    transform::otp_normalise(value)?
                } else {
                    value.clone()
                };

                Some(ImportedField {
                    name: name.clone(),
                    value,
                    protected,
                    custom,
                })
            })
            .collect();

        self.append_packed_fields(csv_record, &mut fields);

        fields
    }

    // Expands the exporter's packed custom field cell into separate entry fields. Names
    // come from the item itself, so a name may collide with a field already on the
    // entry - an entry's fields are keyed by name and the later write would silently
    // replace the real Password or Notes. A colliding field is dropped instead, which
    // loses one custom field rather than a credential
    fn append_packed_fields(&self, csv_record: &CsvDataRecord, fields: &mut Vec<ImportedField>) {
        let Some(packed) = self.packed_fields_column.and_then(|i| csv_record.get(i)) else {
            return;
        };

        for (name, value) in transform::packed_fields(packed) {
            if fields.iter().any(|f| f.name.eq_ignore_ascii_case(&name)) {
                debug!("Packed custom field {name} clashes with an existing field, skipping it");
                continue;
            }

            fields.push(ImportedField {
                name,
                value,
                // The export does not say which of these were hidden fields
                protected: false,
                custom: true,
            });
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CsvImportOptions {
    // The number of fields in records is allowed to change or not
    flexible: bool,

    // first row is a header row
    has_headers: bool,

    // The field delimiter. The default is b','
    delimiter: Option<String>,

    // The quote character to use. The default is b'"'
    quote: Option<String>,

    // The escape character to use. In some variants of CSV, quotes are escaped
    // using a special escape character like \ (instead of escaping quotes by doubling them)
    escape: Option<String>,

    // If the start of a record begins with the byte given here, then that line is ignored by the CSV parser
    comment: Option<String>,
    // record_terminator:Option<String>,

    // TODO: Need to do something similar to cvs::Trim
    //trim: Trim,
}

impl Default for CsvImportOptions {
    fn default() -> Self {
        Self {
            flexible: true,
            has_headers: true,
            delimiter: None,
            quote: None,
            escape: None,
            comment: None,
        }
    }
}

impl CsvImportOptions {
    fn reader_builder(&self) -> ReaderBuilder {
        let mut builder = csv::ReaderBuilder::new();
        builder
            //.trim(csv::Trim::All)
            .flexible(self.flexible)
            .has_headers(self.has_headers);
        builder
    }
}

// This will also works
// static RECORDS: Mutex<Vec<StringRecord>> = Mutex::new(vec![]);

// If we use OnceLock, we need to use Mutex for mut global variable (internal mutability).
static NON_HEADER_RECORDS: std::sync::OnceLock<Mutex<Vec<CsvDataRecord>>> =
    std::sync::OnceLock::new();

#[derive(Debug, Serialize)]
pub struct CvsHeaderInfo {
    headers: Vec<String>,

    // The exporter recognised from the header row, with a ready made column mapping the
    // UI pre-fills the dialog with. None means an unrecognised csv, where the user maps
    // the columns by hand exactly as before
    detected_profile: Option<DetectedProfile>,
}

fn detected_profile_for(headers: &[String]) -> Option<DetectedProfile> {
    profile::detect(headers).map(|p| DetectedProfile::of(p, headers))
}

pub struct CsvImport {}

impl CsvImport {
    pub fn read_from_path<P: AsRef<Path>>(
        path: P,
        import_options: Option<CsvImportOptions>,
    ) -> Result<CvsHeaderInfo> {
        let import_options =
            import_options.map_or_else(|| CsvImportOptions::default(), |imp_opt| imp_opt);
        let mut csv_rdr = import_options.reader_builder().from_path(path.as_ref())?;

        let header_row = if csv_rdr.has_headers() {
            let headers = csv_rdr.headers()?;
            let v = headers
                .iter()
                .enumerate()
                .map(|(idx, r)| {
                    if r.is_empty() {
                        //"Column" + " " + &idx.to_string()
                        vec!["Column", &idx.to_string()].join(" ")
                    } else {
                        r.to_string()
                    }
                })
                .collect::<Vec<_>>();
            // println!(" headers in v is {:?}", &v);
            let detected_profile = detected_profile_for(&v);
            CvsHeaderInfo {
                headers: v,
                detected_profile,
            }
        } else {
            let headers = csv_rdr.headers()?;
            // println!(" headers len is {:?}", headers.len());
            // vec.iter().enumerate() to get the both the index and the value of each element
            let v = headers
                .iter()
                .enumerate()
                .map(|(idx, _s)| vec!["Column", &idx.to_string()].join(" "))
                .collect::<Vec<_>>();
            // let v = headers.iter().map(|r| r.to_string()).collect::<Vec<_>>();
            // A file without a header row has only generated "Column n" names, so there
            // is nothing an exporter profile could match against
            CvsHeaderInfo {
                headers: v,
                detected_profile: None,
            }
        };

        let rows = csv_rdr
            .records()
            .map(|r| r.ok())
            .flatten()
            .map(|r| r.iter().map(|f| f.to_string()).collect::<CsvDataRecord>())
            .collect::<Vec<_>>();

        // let mut v = RECORDS.lock().unwrap();
        // v.clear();
        // v.extend(rows);

        let mut mv = NON_HEADER_RECORDS
            .get_or_init(|| Default::default())
            .lock()
            .unwrap();
        // Wipe any records left over from a previous import before replacing them
        zeroize_records(&mut mv);
        mv.extend(rows);

        Ok(header_row)
    }

    // pub(crate) fn data_records() -> std::sync::MutexGuard<'static, Vec<StringRecord>> {
    //     NON_HEADER_RECORDS
    //         .get_or_init(|| Default::default())
    //         .lock()
    //         .unwrap()
    // }

    fn imported_items(csv_lookup: &CsvLookup) -> Vec<ImportedItem> {
        if let Some(mtx) = NON_HEADER_RECORDS.get() {
            let records = mtx.lock().unwrap();
            csv_lookup.to_imported_items(&records)
        } else {
            vec![]
        }
    }

    // These records hold the plaintext of every credential in the user's export, so the
    // string buffers are overwritten and not just dropped. Called after a successful
    // import, and from the 'clear_csv_data_cache' command when the user backs out of
    // either import dialog
    pub fn clear_stored_records() {
        if let Some(m) = NON_HEADER_RECORDS.get() {
            let mut v = m.lock().unwrap();
            zeroize_records(&mut v);
            debug!("Previously stored csv records are cleared");
        }
    }

    #[cfg(test)]
    pub fn create_entries() {
        // let data_wows = RECORDS.lock().unwrap();
        // for r in data_wows.iter() {
        //     println!("Data row is {:?}", &r);
        // }

        if let Some(m) = NON_HEADER_RECORDS.get() {
            let data_wows = m.lock().unwrap();
            for r in data_wows.iter() {
                println!("Data row is {:?}", &r);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CsvDataRecord, CsvImport, CsvImportOptions, CsvLookup, GROUP, TAGS};
    use crate::import::model::ImportedKind;
    use std::collections::HashMap;

    fn record(fields: &[&str]) -> CsvDataRecord {
        fields.iter().map(|s| s.to_string()).collect()
    }

    fn lookup_with_group_at(idx: usize) -> CsvLookup {
        let mut other_fields = HashMap::new();
        other_fields.insert(GROUP.to_string(), idx);
        CsvLookup {
            other_fields,
            standard_fields: HashMap::default(),
            custom_fields: HashMap::default(),
            folder_separator: None,
            type_column: None,
            type_values: &[],
            favourite_column: None,
            packed_fields_column: None,
            strip_root_folder: false,
            skip_folders: &[],
            icon_column: None,
        }
    }

    // Exporters emit an empty folder cell for unfiled items (Bitwarden does). Those rows
    // must produce no folder path at all, so the writer routes them to the default
    // import group instead of creating a group with a blank name
    #[test]
    fn a_blank_group_cell_produces_no_folder_path() {
        let lookup = lookup_with_group_at(0);

        assert_eq!(lookup.folder_path(&record(&["Work"])), vec!["Work"]);
        assert!(lookup.folder_path(&record(&[""])).is_empty());
        assert!(lookup.folder_path(&record(&["   "])).is_empty());
    }

    // Without a profile a group cell is trimmed but not split - a path separator stays
    // part of the name, since a generic csv may legitimately have one there
    #[test]
    fn a_group_cell_is_trimmed_and_stays_a_single_segment() {
        let lookup = lookup_with_group_at(0);
        assert_eq!(lookup.folder_path(&record(&["  Work  "])), vec!["Work"]);
        assert_eq!(
            lookup.folder_path(&record(&["Work/Clients"])),
            vec!["Work/Clients"]
        );
    }

    #[test]
    fn an_unmapped_group_column_produces_no_folder_path() {
        let lookup = CsvLookup {
            other_fields: HashMap::default(),
            standard_fields: HashMap::default(),
            custom_fields: HashMap::default(),
            folder_separator: None,
            type_column: None,
            type_values: &[],
            favourite_column: None,
            packed_fields_column: None,
            strip_root_folder: false,
            skip_folders: &[],
            icon_column: None,
        };
        assert!(lookup.folder_path(&record(&["Work"])).is_empty());
    }

    #[test]
    fn mapped_fields_become_imported_fields_with_password_protected() {
        let mut standard_fields = HashMap::new();
        standard_fields.insert("Title".to_string(), 0);
        standard_fields.insert("Password".to_string(), 1);
        let mut custom_fields = HashMap::new();
        custom_fields.insert("Reference".to_string(), 2);
        let mut other_fields = HashMap::new();
        other_fields.insert(TAGS.to_string(), 3);

        let lookup = CsvLookup {
            other_fields,
            standard_fields,
            custom_fields,
            folder_separator: None,
            type_column: None,
            type_values: &[],
            favourite_column: None,
            packed_fields_column: None,
            strip_root_folder: false,
            skip_folders: &[],
            icon_column: None,
        };

        let item = lookup.to_imported_item(&record(&["Site", "s3cret", "ref-1", "a;b"]));

        assert_eq!(item.tags.as_deref(), Some("a;b"));
        assert_eq!(item.fields.len(), 3);

        let protected: Vec<_> = item
            .fields
            .iter()
            .filter(|f| f.protected)
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(protected, vec!["Password"], "only Password is protected");

        let reference = item.fields.iter().find(|f| f.name == "Reference").unwrap();
        assert_eq!(reference.value, "ref-1");
        assert!(!reference.protected);
    }

    // A column mapped to the otp field is normalised on the way in, so a vendor's bare
    // base32 secret becomes a url the entry can actually generate tokens from
    #[test]
    fn an_otp_column_is_normalised_to_a_url() {
        let mut standard_fields = HashMap::new();
        standard_fields.insert("otp".to_string(), 0);

        let lookup = CsvLookup {
            other_fields: HashMap::default(),
            standard_fields,
            custom_fields: HashMap::default(),
            folder_separator: None,
            type_column: None,
            type_values: &[],
            favourite_column: None,
            packed_fields_column: None,
            strip_root_folder: false,
            skip_folders: &[],
            icon_column: None,
        };

        let item = lookup.to_imported_item(&record(&["JBSWY3DPEHPK3PXP"]));
        let otp = item.fields.iter().find(|f| f.name == "otp").expect("otp field");
        assert!(otp.value.starts_with("otpauth://totp/"), "got {}", otp.value);

        // An unusable value drops the field rather than storing a dead otp
        let item = lookup.to_imported_item(&record(&["not-a-secret-18"]));
        assert!(item.fields.iter().all(|f| f.name != "otp"));
    }

    #[test]
    fn a_comma_separated_tags_column_is_converted_to_the_kdbx_convention() {
        let mut other_fields = HashMap::new();
        other_fields.insert(TAGS.to_string(), 0);

        let lookup = CsvLookup {
            other_fields,
            standard_fields: HashMap::default(),
            custom_fields: HashMap::default(),
            folder_separator: None,
            type_column: None,
            type_values: &[],
            favourite_column: None,
            packed_fields_column: None,
            strip_root_folder: false,
            skip_folders: &[],
            icon_column: None,
        };

        let item = lookup.to_imported_item(&record(&["work, email ,social"]));
        assert_eq!(item.tags.as_deref(), Some("work;email;social"));
    }

    // Only enabled for exporters known to write paths. A generic csv keeps the slash
    #[test]
    fn folder_path_splitting_is_opt_in() {
        let mut lookup = lookup_with_group_at(0);
        assert_eq!(
            lookup.folder_path(&record(&["Work/Clients"])),
            vec!["Work/Clients"]
        );

        lookup.folder_separator = Some('/');
        assert_eq!(
            lookup.folder_path(&record(&["Work/Clients"])),
            vec!["Work", "Clients"]
        );
    }

    // Without a profile there is no type column, so everything stays a Login
    #[test]
    fn a_row_is_a_login_when_no_type_column_is_known() {
        let lookup = lookup_with_group_at(0);
        assert_eq!(lookup.to_imported_item(&record(&["Work"])).kind, ImportedKind::Login);
    }

    #[test]
    fn a_type_column_selects_the_entry_kind() {
        let mut lookup = lookup_with_group_at(0);
        lookup.type_column = Some(1);
        lookup.type_values = &[
            ("password", ImportedKind::Login),
            ("credit_card", ImportedKind::CreditCard),
        ];

        let kind_of = |value: &str| lookup.to_imported_item(&record(&["Work", value])).kind;

        assert_eq!(kind_of("credit_card"), ImportedKind::CreditCard);
        assert_eq!(kind_of("CREDIT_CARD"), ImportedKind::CreditCard, "case insensitive");
        assert_eq!(kind_of("password"), ImportedKind::Login);
        // An unlisted or blank value falls back rather than failing the row
        assert_eq!(kind_of("something-new"), ImportedKind::Login);
        assert_eq!(kind_of(""), ImportedKind::Login);
    }

    // A kdbx entry has no favourite flag - OKP's Favorites category collects entries
    // carrying the tag - so the exporter's flag has to become that tag
    #[test]
    fn a_set_favourite_column_adds_the_favorites_tag() {
        let mut other_fields = HashMap::new();
        other_fields.insert(TAGS.to_string(), 0);

        let mut lookup = lookup_with_group_at(2);
        lookup.other_fields = other_fields;
        lookup.favourite_column = Some(1);

        let tags_of = |tags: &str, fav: &str| {
            lookup
                .to_imported_item(&record(&[tags, fav, "Work"]))
                .tags
        };

        assert_eq!(tags_of("", "1").as_deref(), Some("Favorites"));
        assert_eq!(tags_of("work", "1").as_deref(), Some("work;Favorites"));
        // Not a favourite, so the tag list is left exactly as the source had it
        assert_eq!(tags_of("work", "0").as_deref(), Some("work"));
        assert_eq!(tags_of("", "0"), None);
    }

    #[test]
    fn a_packed_fields_column_becomes_separate_custom_fields() {
        let mut standard_fields = HashMap::new();
        standard_fields.insert("Title".to_string(), 0);

        let mut lookup = lookup_with_group_at(2);
        lookup.standard_fields = standard_fields;
        lookup.packed_fields_column = Some(1);

        let item = lookup.to_imported_item(&record(&[
            "Site",
            "Security question: mother\nAccount no: 12345",
            "Work",
        ]));

        let custom: Vec<(&str, &str)> = item
            .fields
            .iter()
            .filter(|f| f.custom)
            .map(|f| (f.name.as_str(), f.value.as_str()))
            .collect();

        assert_eq!(
            custom,
            vec![("Security question", "mother"), ("Account no", "12345")]
        );
        // The mapped column stays a standard field
        assert!(item.fields.iter().any(|f| f.name == "Title" && !f.custom));
    }

    // Entry fields are keyed by name, so a packed field named like a standard one would
    // overwrite the real value. Losing one custom field beats losing the password
    #[test]
    fn a_packed_field_never_overwrites_a_mapped_field() {
        let mut standard_fields = HashMap::new();
        standard_fields.insert("Password".to_string(), 0);

        let mut lookup = lookup_with_group_at(2);
        lookup.standard_fields = standard_fields;
        lookup.packed_fields_column = Some(1);

        let item =
            lookup.to_imported_item(&record(&["real-secret", "password: decoy\nPin: 1234", "Work"]));

        let password = item.fields.iter().find(|f| f.name == "Password").unwrap();
        assert_eq!(password.value, "real-secret");
        assert!(password.protected);
        assert_eq!(
            item.fields.iter().filter(|f| f.custom).count(),
            1,
            "only the non clashing packed field is kept"
        );
    }

    // KeePassXC writes the path from its own root group, so every row of a real export
    // is prefixed with the source database's name. Kept as a folder it would bury the
    // whole import under a group named after the database being migrated away from
    #[test]
    fn the_source_databases_root_group_is_not_imported_as_a_folder() {
        let mut lookup = lookup_with_group_at(0);
        lookup.folder_separator = Some('/');
        lookup.strip_root_folder = true;

        assert_eq!(
            lookup.folder_path(&record(&["Test34/Group1/Group1-1"])),
            vec!["Group1", "Group1-1"]
        );
        // An entry sitting directly in the source root has no folder of its own, so it
        // goes to the default import group
        assert!(lookup.folder_path(&record(&["Test34"])).is_empty());
        assert!(lookup.folder_path(&record(&[""])).is_empty());
    }

    // KeePassXC exports deleted entries alongside live ones. Importing them would
    // resurrect what the user threw away
    #[test]
    fn rows_from_a_skipped_folder_are_not_imported() {
        let mut lookup = lookup_with_group_at(0);
        lookup.folder_separator = Some('/');
        lookup.strip_root_folder = true;
        lookup.skip_folders = &["Recycle Bin"];

        let records = vec![
            record(&["Test34/Group1"]),
            record(&["Test34/Recycle Bin"]),
            // Anything nested below the recycle bin was deleted too
            record(&["Test34/Recycle Bin/Old Group"]),
            record(&["Test34"]),
        ];

        let items = lookup.to_imported_items(&records);

        assert_eq!(items.len(), 2, "only the live rows are imported");
        assert_eq!(items[0].folder_path, vec!["Group1"]);
        assert!(items[1].folder_path.is_empty());
    }

    // A folder merely containing the word must still be imported
    #[test]
    fn only_an_exact_skipped_folder_name_is_dropped() {
        let mut lookup = lookup_with_group_at(0);
        lookup.folder_separator = Some('/');
        lookup.skip_folders = &["Recycle Bin"];

        let items = lookup.to_imported_items(&vec![record(&["Recycle Bin Notes"])]);
        assert_eq!(items.len(), 1);
    }

    // The source icon is a standard kdbx index, so it carries straight over
    #[test]
    fn an_icon_column_sets_the_entry_icon() {
        let mut lookup = lookup_with_group_at(0);
        lookup.icon_column = Some(1);

        let icon_of = |value: &str| lookup.to_imported_item(&record(&["Work", value])).icon_id;

        assert_eq!(icon_of("13"), Some(13));
        assert_eq!(icon_of("0"), Some(0));
        // Nothing usable leaves the entry with its entry type's own icon
        assert_eq!(icon_of(""), None);
        assert_eq!(icon_of("999"), None);
    }

    #[test]
    fn no_icon_column_leaves_the_entry_icon_alone() {
        let lookup = lookup_with_group_at(0);
        assert_eq!(lookup.to_imported_item(&record(&["Work"])).icon_id, None);
    }

    #[test]
    fn stored_records_are_wiped_when_cleared() {
        let mut records = vec![record(&["secret-password", "user@example.com"])];
        super::zeroize_records(&mut records);
        assert!(records.is_empty());
    }

    #[ignore]
    #[test]
    fn verify1() {
        let cfile = "/Users/jeyasankar/Downloads/enpass1.csv";
        let mut opt = CsvImportOptions::default();
        opt.has_headers = true;
        let imp = CsvImport::read_from_path(cfile, Some(opt)).unwrap();

        println!("Header row returned {:?}", &imp);

        CsvImport::create_entries();

        CsvImport::clear_stored_records();
        println!("-----------");

        CsvImport::create_entries();
    }
}
