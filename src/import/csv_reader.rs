use std::{path::Path, sync::Mutex};

use csv::{ReaderBuilder, StringRecord};
use serde::{Deserialize, Serialize};

use crate::error::Result;

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

    pub fn clear_stored_records() {
        // let mut v = RECORDS.lock().unwrap();
        // v.clear();

        if let Some(m) = NON_HEADER_RECORDS.get() {
            let mut v = m.lock().unwrap();
            v.clear();
        }
    }

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
