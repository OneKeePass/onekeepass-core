use std::{
    env,
    fs::File,
    io::{Read, Write},
    path::Path,
};

use log::debug;
use serde::{Deserialize, Serialize};

use crate::{db_content::AttachmentHashValue, db_service::call_kdbx_context_action, util};

use super::{call_kdbx_context_mut_action, KdbxContext};

pub use crate::error::{Error, Result};

#[derive(Serialize, Deserialize, Debug)]
pub struct AttachmentUploadInfo {
    pub name: String,
    #[serde(with = "util::from_or_to::string")]
    pub data_hash: AttachmentHashValue,
    pub data_size: usize,
}

/// Called to upload an attachment.  
/// On successful loading the file content, the attachment name and hash for the file data are returned
/// The caller need to connect these info with the an entry as this uploading of the binary data is done only to the
/// inner header structure and yet to be linked with an Entry
pub fn upload_entry_attachment(db_key: &str, full_file_name: &str) -> Result<AttachmentUploadInfo> {
    //Load the file from file system
    let mut file = File::open(full_file_name)?;
    // let mut buf_reader = BufReader::new(file);
    let name = Path::new(full_file_name)
        .file_name()
        .and_then(|x| x.to_str())
        .unwrap_or("No Attachment Name");

    read_entry_attachment(db_key, &name, &mut file)

    // call_kdbx_context_mut_action(db_key, |ctx: &mut KdbxContext| {
    //     let mut buf = vec![];
    //     buf_reader.read_to_end(&mut buf)?;
    //     let size = buf.len();
    //     let data_hash = ctx.kdbx_file.upload_entry_attachment(buf);
    //     Ok(AttachmentUploadInfo {
    //         name: name.into(),
    //         data_hash,
    //         data_size: size,
    //     })
    // })
}

// Mobile
pub fn read_entry_attachment<R: Read>(
    db_key: &str,
    file_name: &str,
    reader: &mut R,
) -> Result<AttachmentUploadInfo> {
    call_kdbx_context_mut_action(db_key, |ctx: &mut KdbxContext| {
        let mut buf = vec![];
        reader.read_to_end(&mut buf)?;
        let size = buf.len();
        let data_hash = ctx.kdbx_file.upload_entry_attachment(buf);
        Ok(AttachmentUploadInfo {
            name: file_name.into(), // Just the file name
            data_hash,
            data_size: size,
        })
    })
}

/// Saves the bytes content of an entry attachment as file to temp dir
/// The file name is based on 'name' and valid data hash handle is required to get the bytes data
pub fn save_attachment_as_temp_file(
    db_key: &str,
    name: &str,
    data_hash: &AttachmentHashValue,
) -> Result<String> {
    let mut path = env::temp_dir();

    debug!("The current directory is {}", path.display());

    // The app temp dir
    path.push("okp_cache");
    if !path.exists() {
        std::fs::create_dir(path.clone())?;
    }

    // Push the file name wanted and create the file with full name
    // TODO: Generate some random file name ?
    path.push(name);

    debug!("Temp file for attachment is {:?}", &path);

    let mut file = std::fs::File::create(path.clone())?;

    let data = call_kdbx_context_action(db_key, |ctx: &KdbxContext| {
        Ok(ctx.kdbx_file.get_bytes_content(data_hash))
    })?;

    if let Some(v) = data {
        file.write_all(&v)?;
        debug!("Wrote the attachment file..");
        path.to_str()
            .ok_or_else(|| "Invalid temp file".into())
            .map(|s| s.into())
    } else {
        Err(Error::Other("No valid data found".into()))
    }
}

pub fn save_attachment_as(
    db_key: &str,
    full_file_name: &str,
    data_hash: &AttachmentHashValue,
) -> Result<()> {
    let mut file = std::fs::File::create(full_file_name)?;

    save_attachment_to_writter(db_key, data_hash, &mut file)

    // let data = call_kdbx_context_action(db_key, |ctx: &KdbxContext| {
    //     Ok(ctx.kdbx_file.get_bytes_content(data_hash))
    // })?;

    // if let Some(v) = data {
    //     file.write_all(&v)?;
    //     return Ok(());
    // } else {
    //     return Err(Error::Other("No valid data found".into()));
    // }
}

pub fn save_attachment_to_writter<W: Write>(
    db_key: &str,
    data_hash: &AttachmentHashValue,
    writer: &mut W,
) -> Result<()> {
    let data = call_kdbx_context_action(db_key, |ctx: &KdbxContext| {
        Ok(ctx.kdbx_file.get_bytes_content(data_hash))
    })?;

    if let Some(v) = data {
        writer.write_all(&v)?;
        return Ok(());
    } else {
        return Err(Error::Other("No valid data found".into()));
    }
}

/// Removes all contents of the app's temp dir
pub fn remove_app_temp_dir_content() -> Result<()> {
    let mut path = env::temp_dir();
    path.push("okp_cache");
    let r = util::remove_dir_contents(&path);
    log::info!("Removed the cache dir {:?}", &path.to_string_lossy());
    r
}
