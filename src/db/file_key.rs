use std::{
    fs::{File, OpenOptions},
    io::{BufReader, Read, Write},
    path::Path,
};

use log::debug;

use crate::{
    crypto,
    error::{Error, Result},
    xml_parse::{FileKeyXmlReader, FileKeyXmlWriter},
};

/// Used when user selects to use any file as a key for the db
#[derive(Clone)]
pub struct FileKey {
    pub(crate) file_name: String,
    // This is the hash of the whole content of a file or hash key from a keyx file
    content_hash: Vec<u8>,
}

impl FileKey {
    // Opens the file and calculates the hash based on the content of this file
    pub(crate) fn open(key_file_name: &str) -> Result<FileKey> {
        debug!(
            "File Key open is called with key file name {}",
            key_file_name
        );
        if !key_file_name.trim().is_empty() & !Path::new(key_file_name).exists() {
            return Err(Error::NotFound(format!(
                "The key file {} is not valid one",
                key_file_name
            )));
        }
        let file = File::open(key_file_name)?;

        Ok(Self {
            file_name: key_file_name.into(),
            content_hash: Self::calculate_hash(file)?,
        })
    }

    // Need to return Result so that the invalid file name error can be propagated to caller
    pub(crate) fn from(key_file_name: Option<&str>) -> Result<Option<FileKey>> {
        let key_file: Result<Option<FileKey>> = match key_file_name {
            Some(n) if !n.trim().is_empty() => Ok(Some(FileKey::open(n)?)),
            Some(_) => Ok(None),
            None => Ok(None),
        };
        key_file
    }

    pub(crate) fn content_hash(&self) -> Vec<u8> {
        self.content_hash.clone()
    }

    pub fn create_xml_key_file(key_file_name: &str) -> Result<()> {
        let mut file_buf = OpenOptions::new()
            .write(true)
            .create(true)
            .open(key_file_name)?;

        Self::write_xml(&mut file_buf)
    }

    pub fn write_xml<W: Write>(buf: &mut W) -> Result<()> {
        let mut xml_writer = FileKeyXmlWriter::new_with_indent(buf);
        let key_file_data = KeyFileData::generate_key_data()?;
        xml_writer.write(&key_file_data)
    }

    // Called to read a keyx xml and extract the hash from <Data> ...</Data> element or 
    // reads the whole bytes content of  the file and caluclates the hash 
    fn calculate_hash(file: File) -> Result<Vec<u8>> {
        let mut reader = BufReader::new(file);
        let mut buf = vec![];
        debug!("Starting reading the file key content in calculate_hash");
        reader.read_to_end(&mut buf)?;

        let content_hash: Vec<u8> = match Self::try_parse_xml(&buf) {
            Ok(key_file_data) => {
                // We find the hash key in the v2 xml file
                debug!("Found xml key file and verifying the checksum");
                key_file_data.verify_checksum()?
            }
            Err(Error::NotXmlKeyFile) => {
                // Hash of the file content is the key
                debug!(
                    "Key file is not xml based one and calculating the hash of content of the file"
                );
                crypto::do_slice_sha256_hash(&buf)?
            }

            Err(e) => return Err(e),
        };
        debug!("Returning File key hash");
        Ok(content_hash)
    }

    fn try_parse_xml(buf: &Vec<u8>) -> Result<KeyFileData> {
        let mut reader = FileKeyXmlReader::new(buf as &[u8]);
        let r = reader.parse()?;
        Ok(r)
    } 
}

#[derive(Default, Debug)]
pub struct KeyFileData {
    pub version: Option<String>,
    pub hash: Option<String>,
    pub data: Option<String>,
}

impl KeyFileData {
    // Gets the key hash after verifying the checksum
    pub fn verify_checksum(&self) -> Result<Vec<u8>> {
        if let (Some(data), Some(hash)) = (&self.data, &self.hash) {
            // Move this joining logic to xml_reading side
            // let d = data
            //     .split_whitespace()
            //     .map(|s| s)
            //     .collect::<Vec<_>>()
            //     .join("");
            let data_vec = hex::decode(&data)?;
            let d = crypto::do_slice_sha256_hash(&data_vec)?;
            let h = hex::decode(hash)?;
            // First 4 bytes of hash of the decoded key data should match the checksum hash bytes
            if &d[..4] != &h {
                return Err(Error::DataError("Key file checksum failed"));
            }
            debug!(
                "File key verify_checksum is called for xml based file key and found valid hash"
            );
            return Ok(data_vec);
        } else {
            return Err(Error::DataError("Key file invalid key data"));
        }
    }

    pub fn generate_key_data() -> Result<Self> {
        let data_vec = crypto::get_random_bytes::<32>();
        let data_vec_hash = crypto::do_slice_sha256_hash(&data_vec)?;
        let check_sum_hash = hex::encode_upper(&data_vec_hash[..4]);
        //let check_sum_hash =
        let data_hex = hex::encode_upper(&data_vec);

        Ok(Self {
            version: Some("2.0".into()),
            data: Some(data_hex),
            hash: Some(check_sum_hash),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::FileKey;

    #[test]
    fn verify_xml_key_file() {
        let path = "/Users/jeyasankar/Documents/OneKeePass/f1/mytestkey.keyx";
        let final_hash = vec![
            171, 166, 129, 178, 198, 225, 156, 116, 230, 113, 237, 236, 65, 213, 172, 9, 144, 137,
            244, 180, 96, 89, 55, 181, 179, 226, 17, 173, 0, 86, 179, 37,
        ];
        let fk = FileKey::open(path).unwrap();

        let h = fk.content_hash();

        println!("h is {:?}", h);

        assert!(final_hash == h)
    }

    #[test]
    fn verify_any_key_file() {
        let path = "/Users/jeyasankar/Documents/OneKeePass/test_key_file";
        let fk = FileKey::open(path).unwrap();
        let h = fk.content_hash();
        println!("h is {:?}", h);
    }
}
