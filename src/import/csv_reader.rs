use std::{collections::HashMap, path::Path, sync::Mutex};

use csv::{ReaderBuilder, StringRecord};
use log::debug;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    constants::entry_keyvalue_key::PASSWORD,
    db::NewDatabase,
    db_content::{Entry, Group, KeepassFile, KeyValue, Section},
    db_service::{self,KdbxContext,call_main_content_mut_action,call_kdbx_context_mut_action},
    error::Result,
    form_data::KdbxLoaded,
    main_content_mut_action,
};

const GROUP: &str = "Group";

const TAGS: &str = "Tags";

const OTHER_FIELDS: [&str; 4] = [GROUP, TAGS, "Modified Time", "Created Time"];

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
}

impl CsvImportMapping {
    // create_new_db_with_imported_csv
    #[cfg(any(target_os = "macos",target_os = "windows",target_os = "linux"))]
    pub fn create_new_db(&self, new_db: NewDatabase) -> Result<KdbxLoaded> {
        let mut kdbx_file = new_db.create()?;
        let keepass_file = kdbx_file.keepass_main_content_mut();

        debug!("Going to apply the imported data");

        self.apply_imported_csv_data(keepass_file)?;

        // After creating the content from csv data, we need to write the new db to the file system
        db_service::write_new_db_kdbx_file(kdbx_file)
    }

    pub fn import_into_db(&self,db_key: &str) -> Result<()> {
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
        } = self;

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

        let custom_field_section = if *unmapped_custom_field && !not_mapped_headers.is_empty() {
            let field_names: Vec<&str> = not_mapped_headers.iter().map(|s| s.as_str()).collect();
            Some(Section::new_custom_field_section(field_names))
        } else {
            None
        };

        let mut csv_lookup = CsvLookup {
            other_fields: field_to_index.0,
            standard_fields: field_to_index.1,
            custom_fields: field_to_index.2,
            custom_field_section,
            keepass_file,
        };

        CsvImport::apply_data_records(&mut csv_lookup)?;

        CsvImport::clear_stored_records();

        Ok(())
    }
}

struct CsvLookup<'a> {
    // Key is from OTHER_FIELDS
    other_fields: HashMap<String, usize>,
    // Key is the Entry field name (UserName, Password....)
    standard_fields: HashMap<String, usize>,
    // Key is the unmapped csv header field name
    custom_fields: HashMap<String, usize>,
    //
    custom_field_section: Option<Section>,

    keepass_file: &'a mut KeepassFile,
}

impl<'a> CsvLookup<'a> {
    fn apply_csv_data(&mut self, records: &Vec<StringRecord>) -> Result<()> {
        // let records = NON_HEADER_RECORDS
        //     .get()
        //     .ok_or_else(|| "No data record is found")?
        //     .lock()
        //     .unwrap();

        //  MutexGuard
        //let records = CsvImport::data_records();

        debug!(
            "Going to create content from {} csv records ",
            &records.len()
        );

        for sr in records.iter() {
            let parent_group_uuid = self.create_group(sr)?;

            // Create a new entry
            let mut entry = Entry::new_login_entry(Some(&parent_group_uuid));

            // Add custom section def
            if let Some(section) = self.custom_field_section.as_ref() {
                entry.entry_field.entry_type.add_section(section);
            }

            // Add tags to entry
            if let Some(tags) = self.other_fields.get(TAGS).and_then(|i| sr.get(*i)) {
                entry.set_tags(tags);
            }

            // Form KVs from  standard_fields and custom_fields if not empty
            self.add_entry_values(&mut entry, sr);

            // Insert new entry to keepass file
            self.keepass_file.root.insert_entry(entry)?;
        }

        Ok(())
    }

    fn add_entry_values(&self, entry: &mut Entry, csv_record: &StringRecord) {
        self.standard_fields.iter().for_each(|(name, i)| {
            if let Some(value) = csv_record.get(*i) {
                let kv = KeyValue::from(name.into(), value.into(), name == PASSWORD);
                entry.entry_field.insert_key_value(kv);
            }
        });

        self.custom_fields.iter().for_each(|(name, i)| {
            if let Some(value) = csv_record.get(*i) {
                let kv = KeyValue::from(name.into(), value.into(), false);
                entry.entry_field.insert_key_value(kv);
            }
        });
    }

    fn create_group(&mut self, csv_record: &StringRecord) -> Result<Uuid> {
        let root_uuid = self.keepass_file.root.root_uuid();

        let g_uuid = if let Some(name) = self
            .other_fields
            .get(GROUP)
            .and_then(|i| csv_record.get(*i))
        {
            // Gets any previously generated group for this name
            if let Some(group) = self.keepass_file.root.group_by_name(name) {
                group.get_uuid()
            } else {
                // No group is found with this name and a new one is created
                let mut group = Group::with_parent(&root_uuid);
                group.set_name(name);
                let uuid = group.get_uuid();
                self.keepass_file.root.insert_group(group)?;
                uuid
            }
        } else {
            // No group in the mapping. So we create a custom group and use this group as parent for the entries

            if let Some(group) = self.keepass_file.root.group_by_name(IMPORT_DEFAULT_GROUP) {
                group.get_uuid()
            } else {
                let mut group = Group::with_parent(&root_uuid);
                group.set_name(IMPORT_DEFAULT_GROUP);
                let uuid = group.get_uuid();
                self.keepass_file.root.insert_group(group)?;
                uuid
            }
        };

        Ok(g_uuid)
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
static NON_HEADER_RECORDS: std::sync::OnceLock<Mutex<Vec<StringRecord>>> =
    std::sync::OnceLock::new();

#[derive(Debug, Serialize)]
pub struct CvsHeaderInfo {
    headers: Vec<String>,
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
            CvsHeaderInfo { headers: v }
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
            CvsHeaderInfo { headers: v }
        };

        let rows = csv_rdr
            .records()
            .map(|r| r.ok())
            .flatten()
            .collect::<Vec<_>>();

        // let mut v = RECORDS.lock().unwrap();
        // v.clear();
        // v.extend(rows);

        let mut mv = NON_HEADER_RECORDS
            .get_or_init(|| Default::default())
            .lock()
            .unwrap();
        mv.clear();
        mv.extend(rows);

        Ok(header_row)
    }

    // pub(crate) fn data_records() -> std::sync::MutexGuard<'static, Vec<StringRecord>> {
    //     NON_HEADER_RECORDS
    //         .get_or_init(|| Default::default())
    //         .lock()
    //         .unwrap()
    // }

    fn apply_data_records(csv_lookup: &mut CsvLookup) -> Result<()> {
        if let Some(mtx) = NON_HEADER_RECORDS.get() {
            let records = mtx.lock().unwrap();
            csv_lookup.apply_csv_data(&records)?;
        }

        Ok(())
    }

    pub fn clear_stored_records() {
        // let mut v = RECORDS.lock().unwrap();
        // v.clear();

        if let Some(m) = NON_HEADER_RECORDS.get() {
            let mut v = m.lock().unwrap();
            v.clear();
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

/*
impl CsvImportMapping {
    pub fn create_kdbx_with_imported_csv(&self, new_db: NewDatabase) -> Result<()> {
        let mut kdbx_file = create_new_db(new_db)?;

        let kp = kdbx_file.keepass_main_content_mut();

        let CsvImportMapping {
            headers,
            mapped_fields,
            not_mapped_headers,
            unmapped_custom_field,
        } = self;

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

        let custom_field_section = if *unmapped_custom_field && !not_mapped_headers.is_empty() {
            let field_names: Vec<&str> = not_mapped_headers.iter().map(|s| s.as_str()).collect();
            Some(Section::new_custom_field_section(field_names))
        } else {
            None
        };

        let mut csv_lookup = CsvLookup {
            other_fields: field_to_index.0,
            standard_fields: field_to_index.1,
            custom_fields: field_to_index.2,
            custom_field_section,
            keepass_file: kp,
        };

        csv_lookup.apply_csv_data()?;

        Ok(())
    }
}
*/

/*
    let v: HashMap<String, usize> =
        headers
            .iter()
            .enumerate()
            .fold(HashMap::default(), |mut acc, (idx, header_item)| {
                if let Some(mapped_field_found) = mapped_fields
                    .iter()
                    .find(|mapped_field_item| &mapped_field_item.mapped_name == header_item)
                {
                    // Standard entry fields (optionally Group) to index of 'StringRecord'
                    acc.insert(mapped_field_found.field_name.clone(), idx);
                    acc
                } else if unmapped_custom_field && not_mapped_headers.contains(header_item) {
                    // Custom fields to index of 'StringRecord'
                    // The custom field name will be the same as header name
                    acc.insert(header_item.to_string(), idx);
                    acc
                } else {
                    acc
                }
            });
*/

#[cfg(test)]
mod tests {
    use super::{CsvImport, CsvImportOptions};

    #[test]
    fn verify1() {
        let cfile = "/Users/jeyasankar/Downloads/test1_kdbx2.csv";
        let cfile = "/Users/jeyasankar/Downloads/bitwarden_export_20250510132618.csv";
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

/*
impl CsvImport {
    pub(crate) fn import_from_path<P: AsRef<Path>>(
        path: P,
        import_options: CsvImportOptions,
    ) -> Result<()> {
        let mut csv_rdr = import_options.reader_builder().from_path(path.as_ref())?;

        if csv_rdr.has_headers() {
            let headers = csv_rdr.headers()?;
            let v = headers.iter().map(|r| r).collect::<Vec<_>>();
            println!(" headers in v is {:?}", &v);
        } else {
            let headers = csv_rdr.headers()?;
            println!(" headers len is {:?}",headers.len());
        }

        // {
        //     let headers = csv_rdr.headers()?;
        //     println!("headers 1 {:?}", headers);
        // }



        for record in csv_rdr.records() {
            let sr: StringRecord = record?;
            println!("sr is {:?}", &sr);
            println!("Field1 of sr is {:?}", &sr.get(0));
        }

        Ok(())
    }
}

*/
