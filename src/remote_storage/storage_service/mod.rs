mod calls;
mod macros;
mod server_connection_config;
pub mod sftp;
pub mod webdav;

pub use server_connection_config::{
    read_configs, set_config_reader_writer, ConnectionConfigReaderWriter,
    ConnectionConfigReaderWriterType, ConnectionConfigs, RemoteStorageTypeConfig,
    RemoteStorageTypeConfigs, SftpConnectionConfig, WebdavConnectionConfig,
};

pub use calls::{RemoteStorageOperation,RemoteStorageOperationType};

use crate::db_service::error::{self, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub struct ParsedDbKey<'a> {
    pub rs_type_name: &'a str,
    pub connection_id: &'a str,
    pub file_path_part: &'a str,
    pub file_name: &'a str,
}

// Db-key format used by both mobile and desktop:
//   "Sftp-<uuid>-<file/path>"  or  "Webdav-<uuid>-<file/path>"
//
// e.g. Sftp-264226dc-be96-462a-a386-79adb6291ad7-/dav/db1/Test1.kdbx
pub fn parse_db_key(db_key: &str) -> Result<ParsedDbKey<'_>> {
    use nom::bytes::complete::{tag, take_while_m_n};
    use nom::character::{complete::alpha1, is_hex_digit};
    use nom::combinator::rest;
    use nom::sequence::tuple;

    let (remaining, (rs_type_name, _, connection_id, _, file_path_part)): (
        &str,
        (&str, &str, &str, &str, &str),
    ) = tuple((
        alpha1,
        tag("-"),
        take_while_m_n(36, 36, |c| is_hex_digit(c as u8) || c == '-'),
        tag("-"),
        rest,
    ))(db_key)
    .map_err(|e: nom::Err<nom::error::Error<&str>>| {
        error::Error::UnexpectedError(format!("Remote db_key parsing failed: {}", e))
    })?;

    if !remaining.is_empty() {
        return Err(error::Error::UnexpectedError(format!(
            "Remote db_key parsing left an unparsed remainder: {}",
            remaining
        )));
    }

    let file_name = file_path_part
        .rsplit_once('/')
        .map(|p| p.1)
        .unwrap_or("");

    Ok(ParsedDbKey {
        rs_type_name,
        connection_id,
        file_path_part,
        file_name,
    })
}

// Convenience: parse a db_key string straight to the dispatch enum used by
// the storage_service calls. Both desktop and mobile callers want this.
pub fn rs_type_from_db_key(db_key: &str) -> Result<RemoteStorageOperationType> {
    RemoteStorageOperationType::try_from_parsed_db_key(parse_db_key(db_key)?)
}

#[derive(Serialize, Deserialize)]
pub struct ServerDirEntry {
    // e.g "/" , "/dav"
    parent_dir: String,
    sub_dirs: Vec<String>,
    files: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ConnectStatus {
    pub connection_id: Uuid,
    pub dir_entries: Option<ServerDirEntry>,
}

#[derive(Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub enum RemoteStorageType {
    Sftp,
    Webdav,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RemoteFileMetadata {
    connection_id: Uuid,
    storage_type: RemoteStorageType,
    // Should we add file_name here?
    //file_name:String,
    full_file_name: String,
    pub size: Option<u64>,
    pub created: Option<u64>,
    pub modified: Option<u64>,
    pub accessed: Option<u64>,
}

impl RemoteFileMetadata {
    // This is used as db_key
    pub fn prefixed_full_file_name(&self) -> String {
        match self.storage_type {
            RemoteStorageType::Sftp => {
                format!("Sftp:{}", &self.full_file_name)
            }
            RemoteStorageType::Webdav => {
                format!("Webdav:{}", &self.full_file_name)
            }
        }
    }
}

pub struct RemoteReadData {
    pub data: Vec<u8>,
    pub meta: RemoteFileMetadata,
}

fn string_tuple3(a: &[&str]) -> (String, String, String) {
    (a[0].to_string(), a[1].to_string(), a[2].to_string())
}

fn string_tuple2(a: &[&str]) -> (String, String) {
    (a[0].to_string(), a[1].to_string())
}

fn filter_entry(name: &str) -> bool {
    !name.is_empty() && !name.starts_with("._") && !name.starts_with(".DS_Store")
}

// fn _tuple2<T>(a: &[T]) -> (&T, &T) {
//     (&a[0], &a[1])
// }

// fn _string_tuple2(a: &[&str]) -> (String, String) {
//     (a[0].to_string(), a[1].to_string())
// }

// fn extract_file_name(remote_full_path: &str) -> Option<String> {
//     remote_full_path.split("/").last().map(|s| s.into())
//     //remote_full_path.split("/").last().map_or_else(|| "No file".into(), |s| s.into())
// }

///////////

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use url::Url;

    fn extract_file_name(remote_full_path: &str) -> Option<String> {
        remote_full_path.split("/").last().map(|s| s.into())
        //remote_full_path.split("/").last().map_or_else(|| "No file".into(), |s| s.into())
    }

    #[test]
    fn verify_extract_file_name() {
        let fn1 = extract_file_name("https://192.168.1.4/dav/Test-OTP1.kdbx");
        println!("File name 1 is {:?}", &fn1);

        let fn2 = extract_file_name("/dav/Test-OTP1.kdbx");
        println!("File name 1 is {:?}", &fn2);

        let url = Url::parse("https://192.168.1.4:8080/Doc:Amm/").unwrap();

        let url = url.join("dav/").unwrap(); // should be "dav/" and not "dav"
        let url = url.join("Test-OTP1.kdbx").unwrap();

        println!("url is {}", &url);

        let mut p = PathBuf::from("https://192.168.1.4:8080/Doc:mm");
        p.push("dav");
        p.push("Test-OTP1.kdbx");

        println!("path is {:?}", &p.as_path());
        println!(
            "Encoded url {:?}",
            &urlencoding::encode(&p.as_os_str().to_str().unwrap())
        );
        println!(
            "Encoded2 url {:?}",
            &urlencoding::encode("https://192.168.1.4:8080/Doc:mm")
        );
    }
}
