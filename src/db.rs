use std::cmp;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::hash::Hasher;
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom, Write};
use std::path::Path;

use log::{debug, error, info};
use serde::{Deserialize, Serialize};

use crate::constants::{self, EMPTY_STR};
use crate::constants::{header_type, inner_header_type, vd_type, PAYLOAD_BLOCK_SIZE};
use crate::crypto;
use crate::crypto::kdf::Kdf;
use crate::crypto::ContentCipher;
use crate::crypto::ProtectedContentStreamCipher;
use crate::db_content::*;
use crate::error::{Error, Result};
use crate::util;
use crate::xml_parse;

#[allow(dead_code)]
#[derive(Debug)]
enum VariantDict {
    UINT32(String, u32),
    UINT64(String, u64),
    BOOL(String, bool),
    INT32(String, i32),
    INT64(String, i64),
    STRING(String, String),
    BYTEARRAY(String, Vec<u8>),
}

#[derive(Default)]
struct MainHeader {
    cipher_id: Vec<u8>,
    master_seed: Vec<u8>,
    /// Formed from 4 LE bytes [1, 0, 0, 0]  
    compression_flag: i32,
    encryption_iv: Vec<u8>,
    public_custom_data: Vec<u8>,
    comment: Vec<u8>,
    unknown_data: (u8, Vec<u8>),
    kdf_algorithm: KdfAlgorithm,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum KdfAlgorithm {
    Argon2(crypto::kdf::Argon2Kdf),
    NoValidKdfAvailable,
}

impl Default for KdfAlgorithm {
    fn default() -> Self {
        KdfAlgorithm::NoValidKdfAvailable
    }
}

/// Writes the header type byte and header data of Vec<u8> type with size le bytes as prefix
/// This macro is used for both MainHeader and InnerHeader Vec<u8> data writing
macro_rules! write_header_with_size {
    ($writer:tt,$id:expr,$data:expr) => {
        $writer.write(&[$id])?; //header type or inner header type
        let size = $data.len() as u32;
        $writer.write(&size.to_le_bytes())?;
        $writer.write($data)?;
    };
}

impl MainHeader {
    /// Reads VariantDict which has Key Value pairs from the given bytes data.
    ///
    /// From given bytes sequence variant dict key and value pairs are extracted.
    /// First byte determines the type of value.
    /// Next 4 bytes determine the length of 'name' field and after that next 4 bytes determine the value length
    /// From https://keepass.info/help/kb/kdbx_4.html
    ///  [1 byte] Value type, can be one of the following:
    ///      0x00:None  --- To mark the end of variant dict stream
    ///      0x04: UInt32.
    ///      0x05: UInt64.
    ///      0x08: Bool.
    ///      0x0C: Int32.
    ///      0x0D: Int64.
    ///      0x18: String (UTF-8, without BOM, without null terminator).
    ///      0x42: Byte array.
    ///  [4 bytes] Length k of the key name in bytes, Int32, little-endian.
    ///  [k bytes] Key name (string, UTF-8, without BOM, without null terminator).
    ///  [4 bytes] Length v of the value in bytes, Int32, little-endian.
    ///  [v bytes] Value. Integers are stored in little-endian encoding, and a Bool is one byte (false = 0, true = 1); the other types are clear.
    fn extract_kdf_parameters(&mut self, data: &[u8]) -> Result<()> {
        let mut buf = Cursor::new(Vec::<u8>::new());
        buf.write(data)?;
        buf.seek(SeekFrom::Start(0))?;
        //variant dict version (little endian) expected [0 1] rather the high byte  is critical
        //and the loading code should refuse to load the data if the high byte is too high
        let mut vd_ver = [0u8; 2];
        buf.read_exact(&mut vd_ver)?;
        //TODO: Verify the variant dict version here
        let mut kdf = KdfAlgorithm::NoValidKdfAvailable;
        let mut vds = Vec::new();
        let mut vd_t = [0u8; 1];
        loop {
            buf.read_exact(&mut vd_t)?;
            if vd_t[0] == vd_type::NONE {
                break;
            }
            let mut size_buf = [0u8; 4];
            buf.read_exact(&mut size_buf)?;
            let mut bytes_to_read = u32::from_le_bytes(size_buf);
            let mut bytes_buf = Vec::new();
            Read::by_ref(&mut buf)
                .take(bytes_to_read as u64)
                .read_to_end(&mut bytes_buf)?;
            let name = std::str::from_utf8(&bytes_buf)?.to_string();

            buf.read_exact(&mut size_buf)?;
            bytes_to_read = u32::from_le_bytes(size_buf);
            bytes_buf = Vec::new();
            Read::by_ref(&mut buf)
                .take(bytes_to_read as u64)
                .read_to_end(&mut bytes_buf)?;

            match vd_t[0] {
                vd_type::UINT64 => {
                    vds.push(VariantDict::UINT64(name, util::to_u64(&bytes_buf)?));
                }
                vd_type::UINT32 => {
                    vds.push(VariantDict::UINT32(name, util::to_u32(&bytes_buf)?));
                }
                vd_type::BYTEARRAY => {
                    if name.as_str() == "$UUID" {
                        if bytes_buf == constants::uuid::ARGON2_KDF {
                            kdf = KdfAlgorithm::Argon2(crypto::kdf::Argon2Kdf::default());
                        }
                    } else {
                        vds.push(VariantDict::BYTEARRAY(name, bytes_buf.clone()));
                    }
                }
                _ => {
                    // We are skipping vd_type::BOOL,vd_type::STRING,vd_type::INT32, vd_type::INT64 as
                    // there are not used currently in the supported KDF
                    //Should not reach here!
                    error!("bytes_buf is {:?}", bytes_buf);
                    //TODO: Need to return Err if we encounter unknow variant dict data type
                }
            }
        }
        // Do validation to verify the supported KDF algorithm
        if let KdfAlgorithm::Argon2(k) = kdf {
            //println!("kdf is {:?}", k);
            let kf = vds.iter().fold(k, |mut acc, vd| {
                match vd {
                    VariantDict::UINT64(name, val) if *name == "I".to_string() => {
                        acc.iterations = *val
                    }
                    VariantDict::UINT64(name, val) if *name == "M".to_string() => acc.memory = *val,
                    VariantDict::UINT32(name, val) if *name == "P".to_string() => {
                        acc.parallelism = *val
                    }
                    VariantDict::UINT32(name, val) if *name == "V".to_string() => {
                        acc.version = *val
                    }
                    VariantDict::BYTEARRAY(name, val) if *name == "S".to_string() => {
                        acc.salt = val.clone()
                    }
                    _ => (),
                }
                acc
            });
            //println!("kdf is {:?}", kf);
            self.kdf_algorithm = KdfAlgorithm::Argon2(kf);
            //Ok(KdfAlgorithm::Argon2(kf))
            Ok(())
        } else {
            return Err(Error::SupportedOnlyArgon2dKdfAlgorithm);
        }
    }

    fn kdf_parameters_to_bytes(&mut self) -> Result<Vec<u8>> {
        let mut writer = Cursor::new(Vec::<u8>::new());
        //[0 1] variant dict version (little endian) expected [0 1] rather the high byte  is critical
        //See extract_variant_dict above

        writer.write(&[0u8, 1])?;

        let mut write = |vd_type: u8, name: &str, val_bytes: &[u8]| -> Result<()> {
            //Type
            writer.write(&[vd_type])?;
            //Name prefixed with size represented as LE bytes
            let name_bytes = name.as_bytes();
            let name_bytes_size = (name_bytes.len() as u32).to_le_bytes();
            writer.write(&name_bytes_size)?;
            writer.write(name_bytes)?;
            //Value prefixed with size represented as LE bytes
            let val_bytes_size = (val_bytes.len() as u32).to_le_bytes();
            writer.write(&val_bytes_size)?;
            writer.write(val_bytes)?;
            Ok(())
        };

        if let KdfAlgorithm::Argon2(kdf) = &self.kdf_algorithm {
            write(vd_type::BYTEARRAY, "$UUID", constants::uuid::ARGON2_KDF)?;
            write(vd_type::UINT64, "I", &kdf.iterations.to_le_bytes())?;
            write(vd_type::UINT64, "M", &kdf.memory.to_le_bytes())?;
            write(vd_type::UINT32, "P", &kdf.parallelism.to_le_bytes())?;
            write(vd_type::BYTEARRAY, "S", &kdf.salt)?;
            write(vd_type::UINT32, "V", &kdf.version.to_le_bytes())?;
        }
        //IMPORTANT: Need to mark the end of Variant Dict with just END type byte
        writer.write(&[vd_type::NONE])?;
        Ok(writer.into_inner())
    }

    fn write_bytes<W: Write + Seek>(&mut self, writer: &mut W) -> Result<()> {
        write_header_with_size!(writer, header_type::CIPHER_ID, &self.cipher_id);
        writer.write(&[header_type::COMPRESSION_FLAGS])?;
        writer.write(&(4 as u32).to_le_bytes())?;
        writer.write(&self.compression_flag.to_le_bytes())?;

        write_header_with_size!(writer, header_type::MASTER_SEED, &self.master_seed);
        //write kdf parameters
        //We need to get the raw bytes vec and then pass it to the macro as expr. If we pass the "self.kdf_parameters_to_bytes()"
        //to macro directly, that expr will be called where ever that expr is used which we do not want!
        let b = self.kdf_parameters_to_bytes()?;
        write_header_with_size!(writer, header_type::KDF_PARAMETERS, &b);
        write_header_with_size!(writer, header_type::ENCRYPTION_IV, &self.encryption_iv);

        //Need to add COMMENT and PUBLIC_CUSTOM_DATA if we use it
        if !self.comment.is_empty() {
            write_header_with_size!(writer, header_type::COMMENT, &self.comment);
        };

        if !self.public_custom_data.is_empty() {
            // NOTE:
            // At this time public_custom_data is just Vec<u8> and the following will work. But if we use something like
            // VariantDictionary type, we need to deserialize that type to bytes then write it
            write_header_with_size!(
                writer,
                header_type::PUBLIC_CUSTOM_DATA,
                &self.public_custom_data
            );
        };

        //End of header [13, 10, 13, 10]
        writer.write(&[header_type::END_OF_HEADER])?;
        writer.write(&(4 as u32).to_le_bytes())?;
        writer.write(&vec![13, 10, 13, 10])?; //End Data

        Ok(())
    }
}

#[derive(Debug, Default)]
struct AttachmentSet {
    /// All attachments bytes data accessible by its hash.
    attachments: HashMap<AttachmentHashValue, Vec<u8>>,
    /// Read time hash look up is populated while reading the xml content and
    /// it is used to set the hash values to BinaryKeyValue of entries' binary_key_values
    index_ref_hash: HashMap<i32, (AttachmentHashValue, usize)>,
    /// Write time look up and it is used to set the index refs to entries based on the
    /// hash value found in 'BinaryKeyValue'
    hash_index_ref: HashMap<AttachmentHashValue, i32>,
}

impl AttachmentSet {
    /// Called to add the bytes data while reading the db content
    fn add(&mut self, data: Vec<u8>) {
        let key = AttachmentSet::to_hash(&data);
        let size = data.len();
        self.attachments.insert(key, data);
        //The index look up
        let index = self.attachments.len() as i32;
        self.index_ref_hash.insert(index - 1, (key, size));
    }

    /// Gets the bytes content of attachment for view
    fn get_bytes_content(&self, data_hash: &AttachmentHashValue) -> Option<Vec<u8>> {
        match self.attachments.get(data_hash) {
            Some(data) => {
                // The first byte is a flag to indicate whether the data needs protection or not
                // This byte is removed to get the actual bytes content
                let b: &[u8] = &data[1..];
                Some(b.to_vec())
            }
            None => None,
        }
    }

    /// Called when a new document is uploaded
    fn insert(&mut self, mut data: Vec<u8>) -> AttachmentHashValue {
        // Nothing is done to index_ref_hash or hash_index_ref

        // 1 byte with value 1 added as prefix to data.
        // The first byte is a flag to indicate whether the data needs protection or not
        let mut prefixed_data = vec![1u8; 1];
        prefixed_data.append(&mut data);
        let key = AttachmentSet::to_hash(&prefixed_data);
        // If the uploaded attachment content is same as any previously loaded one, only single content is kept
        self.attachments.insert(key, prefixed_data);
        key
    }

    /// Generates a hash key based on the attachment bytes data
    fn to_hash(data: &[u8]) -> AttachmentHashValue {
        let mut hasher = DefaultHasher::new();
        hasher.write(data);
        hasher.finish()
    }

    pub fn attachments_index_ref_to_hash(&self) -> &HashMap<i32, (AttachmentHashValue, usize)> {
        &self.index_ref_hash
    }

    pub fn attachment_hash_to_index_ref(&self) -> &HashMap<AttachmentHashValue, i32> {
        &self.hash_index_ref
    }
}

#[derive(Debug, Default)]
struct InnerHeader {
    //Id dereived from the LE bytes stored in inner_stream_id
    stream_cipher_id: u32,
    inner_stream_key: Vec<u8>,
    // All attachemnt binaries are in the same order as they are in the db
    // They are referred by "index_ref" (from "Ref" attribute of XML db) field of "BinaryKeyValue"
    // The attachement vec's first byte is a flag to indicate whether the data needs protection and remaining bytes are the actual
    // attachment
    // Attachments data are stored in AttachmentSet for easy lookup as well as for uploading new ones
    pub(crate) entry_attachments: AttachmentSet,
}

impl InnerHeader {
    fn add_binary_data(&mut self, data: Vec<u8>) {
        self.entry_attachments.add(data);
    }

    fn get_bytes_content(&self, data_hash: &AttachmentHashValue) -> Option<Vec<u8>> {
        self.entry_attachments.get_bytes_content(data_hash)
    }

    fn write_all_bytes<W: Write>(
        &mut self,
        attachment_hashes: Vec<AttachmentHashValue>,
        writer: &mut W,
    ) -> Result<()> {
        writer.write(&[inner_header_type::STREAM_ID])?;
        writer.write(&(4 as u32).to_le_bytes())?;
        writer.write(&self.stream_cipher_id.to_le_bytes())?;

        write_header_with_size!(
            writer,
            inner_header_type::STREAM_KEY,
            &self.inner_stream_key
        );

        // The index at which the attachment binary data written
        let mut writen_index = 0;
        // Need to reset the map before writing so that we can pass the correct hash to index mapping while writing xml content
        self.entry_attachments.hash_index_ref.clear();
        for h in attachment_hashes {
            let hidx = self.entry_attachments.hash_index_ref.get(&h);
            if hidx.is_none() {
                if let Some(data) = self.entry_attachments.attachments.get(&h) {
                    write_header_with_size!(writer, inner_header_type::BINARY, &data);
                }
                self.entry_attachments
                    .hash_index_ref
                    .insert(h, writen_index);
                writen_index = writen_index + 1;
            }
            // else {
            //     println!("Hash {} is already found at index {:?} and skipping writing to binary data", &h, hidx);
            // }
        }

        //End of header - 0 size
        writer.write(&[inner_header_type::END_OF_HEADER])?;
        writer.write(&vec![0u8; 4])?; //[0, 0, 0, 0] => 0 byte size
                                      //No inner header end Data

        Ok(())
    }
}

#[derive(Debug, Default)]
struct DbKey {
    composite_key: Vec<u8>,
    transformed_key: Vec<u8>,
    hmac_part_key: Vec<u8>,
    hmac_key: Vec<u8>,
    master_key: Vec<u8>,
}

impl DbKey {
    //TODO: Add composite_key and transformed_key computation here

    // Hash the password and key file content if any.
    // First hash password and keyfile content separately and
    // the final hash is the result of these concated hashes

    fn form_composite_key(password: &Vec<u8>, file_key: &Option<FileKey>) -> Result<Vec<u8>> {
        if let Some(fk) = file_key {
            // Final hash is sha256(sha256(password) + sha256(keyfile-content))
            let phash = crypto::do_slice_sha256_hash(password)?;
            let fhash = crypto::do_slice_sha256_hash(&fk.content)?;

            let p = phash.to_vec();
            let f = fhash.to_vec();
            let data = vec![&p, &f];
            let final_hash = crypto::do_vecs_sha256_hash(&data)?;
            Ok(final_hash.to_vec())
        } else {
            // Final hash is sha256(sha256(password))
            let phash = crypto::do_slice_sha256_hash(password)?;
            let final_hash = crypto::do_slice_sha256_hash(phash.as_ref())?;
            Ok(final_hash.to_vec())
        }
    }

    fn compute_composite_key(
        &mut self,
        password: &Vec<u8>,
        file_key: &Option<FileKey>,
    ) -> Result<()> {
        self.composite_key = DbKey::form_composite_key(password, file_key)?;
        Ok(())
    }

    fn compute_keys(&mut self, master_seed: &Vec<u8>, transformed_key: Vec<u8>) -> Result<()> {
        self.transformed_key = transformed_key;
        let suffix = vec![1u8; 1]; // 1 byte with value 1 added as suffix
        self.hmac_part_key =
            crypto::do_sha512_hash(&[master_seed, &self.transformed_key, &suffix])?;

        let prefix = vec![255u8; 8]; //8 bytes of value 255 prefixed ; -1 in i8
        self.hmac_key = crypto::do_sha512_hash(&[&prefix, &self.hmac_part_key])?;
        self.master_key = crypto::do_sha256_hash(&[master_seed, &self.transformed_key])?;

        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum ContentCipherId {
    ChaCha20,
    Aes256,
    UnKnownCipher,
}

impl ContentCipherId {
    fn to_uuid_id(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut rng = crypto::SecureRandom::new();
        match self {
            ContentCipherId::Aes256 => {
                Ok((constants::uuid::AES256.to_vec(), rng.get_bytes::<16>()))
            }
            ContentCipherId::ChaCha20 => {
                Ok((constants::uuid::CHACHA20.to_vec(), rng.get_bytes::<12>()))
            }
            _ => return Err(Error::UnsupportedCipher(vec![])),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NewDatabase {
    pub(crate) database_name: String,
    pub(crate) database_description: Option<String>,
    pub database_file_name: String,
    pub(crate) kdf: KdfAlgorithm,
    pub(crate) cipher_id: ContentCipherId,
    pub(crate) password: String,
    pub(crate) key_file_name: Option<String>,
}

impl NewDatabase {
    pub fn new(db_file_name: &str, password: &str) -> Self {
        let mut n = Self::default();
        n.password = password.into();
        n.database_file_name = db_file_name.into();
        n
    }
}

impl Default for NewDatabase {
    fn default() -> Self {
        Self {
            database_name: "NewDatabase".into(),
            database_description: Some("New Database".into()),
            database_file_name: "NO_NAME".into(),
            kdf: KdfAlgorithm::Argon2(crypto::kdf::Argon2Kdf::default()),
            cipher_id: ContentCipherId::Aes256,
            password: "ThisIsTest".into(),
            key_file_name: None,
        }
    }
}

impl NewDatabase {
    /// Creates a blank database with some intial values. The database is not yet saved
    pub fn create(&self) -> Result<KdbxFile> {
        let file_key = match &self.key_file_name {
            Some(n) if !n.trim().is_empty() => Some(FileKey::open(&n)?),
            Some(_) | None => None,
        };

        let (cid, eiv) = self.cipher_id.to_uuid_id()?;
        let mut rng = crypto::SecureRandom::new();

        let mh = MainHeader {
            cipher_id: cid,
            master_seed: rng.get_bytes::<32>(),
            compression_flag: 1, // 0 => no compression
            encryption_iv: eiv,  //rng.get_bytes::<16>() for AES,rng.get_bytes::<12>() for CHACHA20
            public_custom_data: vec![],
            comment: vec![],
            unknown_data: (0, vec![]),
            kdf_algorithm: self.kdf.clone(),
        };

        let mut ih = InnerHeader::default();
        ih.stream_cipher_id = inner_header_type::CHACHA20_STREAM;
        ih.inner_stream_key = rng.get_bytes::<64>();
        let mut kc = KeepassFile::new();
        kc.meta.generator = "OneKeePass".into();
        kc.meta.database_name = self.database_name.clone();
        kc.meta.database_description = self
            .database_description
            .as_ref()
            .unwrap_or(&"New Database".into())
            .to_string();
        let mut root_g = Group::new();
        root_g.uuid = uuid::Uuid::new_v4();
        root_g.name = kc.meta.database_name.clone();
        kc.root.root_uuid = root_g.uuid.clone();
        kc.root.all_groups.insert(root_g.uuid, root_g);
        let k = KdbxFile {
            database_file_name: self.database_file_name.clone(),
            password: self.password.as_bytes().to_vec(),
            //key_file_data: kb,
            file_key,
            main_header: mh,
            inner_header: ih,
            db_key: DbKey::default(),
            keepass_main_content: Some(kc),
        };

        Ok(k)
    }
}

#[derive(Default)]
pub struct KdbxFile {
    database_file_name: String,
    password: Vec<u8>,
    //key_file_data: Option<Vec<u8>>,
    file_key: Option<FileKey>,
    main_header: MainHeader,
    inner_header: InnerHeader,
    db_key: DbKey,
    pub(crate) keepass_main_content: Option<KeepassFile>,
}

impl KdbxFile {
    fn compute_all_keys(&mut self) -> Result<()> {
        if let KdfAlgorithm::Argon2(kdf) = &self.main_header.kdf_algorithm {
            //First determine the composite key from password
            self.db_key
                .compute_composite_key(&self.password, &self.file_key)?;
            //Then transform the composite key using KDF
            let transformed_key = kdf.transform_key(self.db_key.composite_key.clone())?;
            //Determine the HMAC and Payload Encryption/Decryption Key
            self.db_key
                .compute_keys(&self.main_header.master_seed, transformed_key)?;
        } else {
            return Err(Error::SupportedOnlyArgon2dKdfAlgorithm);
        }
        Ok(())
    }

    pub fn compare_key(&self, password: &str, key_file_name: Option<&str>) -> Result<bool> {
        let file_key = FileKey::from(key_file_name)?;
        let key = DbKey::form_composite_key(password.as_bytes().to_vec().as_ref(), &file_key)?;
        Ok(self.db_key.composite_key == key)
    }

    pub fn get_database_name(&self) -> &str {
        if let Some(kp) = self.keepass_main_content.as_ref() {
            kp.meta.database_name.as_str()
        } else {
            // This should not happen ?
            log::error!("Database is empty as Keepass content is empty");
            EMPTY_STR
        }
    }

    pub fn get_key_file_name(&self) -> Option<String> {
        // Need to get ref FileKey to avoid move
        self.file_key.as_ref().map(|f| f.file_name.clone())
    }

    /// Opens the named file, reads and uses its content while computing key
    pub fn set_file_key(&mut self, key_file_name: Option<&str>) -> Result<()> {
        self.file_key = match key_file_name {
            Some(s) => Some(FileKey::open(s)?), // key file should exists or opening error will happen
            None => None,
        };
        Ok(())
    }

    pub fn set_database_file_name(&mut self, database_file_name: &str) -> &mut Self {
        self.database_file_name = database_file_name.into();
        self
    }

    pub fn get_database_file_name(&self) -> &str {
        &self.database_file_name
    }

    pub fn set_password(&mut self, password: &str) -> &mut Self {
        self.password = password.as_bytes().to_vec();
        self
    }

    /// Called when user uploads an attachment in UI
    /// Returns the attachment content's hash for later reference
    pub fn upload_entry_attachment(&mut self, data: Vec<u8>) -> AttachmentHashValue {
        self.inner_header.entry_attachments.insert(data)
    }

    pub fn get_bytes_content(&self, data_hash: &AttachmentHashValue) -> Option<Vec<u8>> {
        self.inner_header.get_bytes_content(data_hash)
    }

    pub fn get_content_cipher_id(&self) -> ContentCipherId {
        match self.main_header.cipher_id.as_slice() {
            constants::uuid::AES256 => ContentCipherId::Aes256,
            constants::uuid::CHACHA20 => ContentCipherId::ChaCha20,
            _ => ContentCipherId::UnKnownCipher,
        }
    }

    pub fn set_content_cipher_id(&mut self, content_cipher_id: ContentCipherId) -> Result<()> {
        let (cid, eiv) = content_cipher_id.to_uuid_id()?;
        self.main_header.cipher_id = cid;
        self.main_header.encryption_iv = eiv;

        Ok(())
    }

    pub fn get_kdf_algorithm(&self) -> KdfAlgorithm {
        self.main_header.kdf_algorithm.clone()
    }

    pub fn set_kdf_algorithm(&mut self, other_kdf: KdfAlgorithm) -> Result<()> {
        if let KdfAlgorithm::Argon2(ref _other) = other_kdf {
            // The incoming other_kdf is expected to have all valid values in KdfAlgorithm::Argon2(crypto::kdf::Argon2Kdf)
            self.main_header.kdf_algorithm = other_kdf;
            Ok(())
        } else {
            Err(Error::UnsupportedKdfAlgorithm(
                "Invalid Kdf algorithm is passed while updating in the setting".into(),
            ))
        }
    }
}

pub struct KdbxFileReader<'a, T>
where
    T: Read + Seek,
{
    reader: &'a mut T,
    kdbx_file: KdbxFile,
    header_data_start_position: u64,
    header_data_end_position: u64,
}

#[allow(dead_code)]
impl<'a, T: Read + Seek> KdbxFileReader<'a, T> {
    fn new(reader: &'a mut T, kdbx_file: KdbxFile) -> KdbxFileReader<'a, T> {
        KdbxFileReader {
            reader,
            kdbx_file,
            header_data_start_position: 0,
            header_data_end_position: 0,
        }
    }

    fn read(&mut self) -> Result<()> {
        self.read_file_signature()?;
        self.read_header()?;
        self.verify_stored_hash()?;
        self.kdbx_file.compute_all_keys()?; //Uses password and key file content
        self.verify_header_hmac()?;
        let mut buf = self.read_hmac_data_blocks()?;
        buf = self.decrypt_data(&buf)?;
        buf = self.split_inner_header_xml_content(&buf)?;
        // buf now has the xml bytes data
        self.read_xml_content(&buf)?;

        Ok(())
    }

    /// Reads the signatures and version of the kbdx file and verifies that they are valid
    fn read_file_signature(&mut self) -> Result<()> {
        let mut buffer = [0; 4];
        self.reader.read_exact(&mut buffer)?; // 4 bytes
        let sig1 = u32::from_le_bytes(buffer); // u32 value 2594363651
        self.reader.read_exact(&mut buffer)?; // 4 bytes
        let sig2 = u32::from_le_bytes(buffer); // u32 value  3041655655
        self.reader.read_exact(&mut buffer)?; // 4 bytes
        let ver = u32::from_le_bytes(buffer); // u32 value 262144,hex 40000  (for 4.1 the values are 262145, 40001)

        // TODO: Need to modifiy to verify (using higher 4 bytes ?) ver as any 4.x instead of the specific 4.0 or 4.1
        match (sig1, sig2, ver) {
            (constants::SIG1, constants::SIG2, constants::VERSION_40) => (),
            (constants::SIG1, constants::SIG2, constants::VERSION_41) => (),
            _ => {
                return Err(Error::InvalidKeePassFile);
            }
        };

        //We should have read 12 bytes from start at this point
        //Need to include these 12 bytes to calculate the header hash later and accordingly we
        //reset the stream postion to 0 and hash(12byes+header data) verification is done after reading the header data
        self.header_data_start_position = 0;
        Ok(())
    }

    fn read_header(&mut self) -> Result<()> {
        let mut header_end = true;
        while header_end {
            let mut buf = [0; 1];
            self.reader.read_exact(&mut buf)?;
            let entry_type = buf[0];
            match entry_type {
                header_type::END_OF_HEADER => {
                    //We need to read the Header end marker which is [13, 10, 13, 10]
                    //so that stream position is correct.
                    self.read_header_field()?; //Just discard these 4 bytes
                    header_end = false;
                }
                header_type::CIPHER_ID => {
                    self.kdbx_file.main_header.cipher_id = self.read_header_field()?;
                }
                header_type::COMPRESSION_FLAGS => {
                    self.kdbx_file.main_header.compression_flag =
                        util::to_i32(&self.read_header_field()?)?;
                }
                header_type::MASTER_SEED => {
                    self.kdbx_file.main_header.master_seed = self.read_header_field()?;
                }
                header_type::ENCRYPTION_IV => {
                    self.kdbx_file.main_header.encryption_iv = self.read_header_field()?;
                }
                header_type::KDF_PARAMETERS => {
                    //self.kdbx_file.main_header.kdf_parameters_raw = self.read_header_field()?;
                    //cannot borrow `*self` as mutable more than once at a time
                    //self.kdbx_file.main_header.extract_kdf_parameters(&self.read_header_field()?)?;
                    let v = &self.read_header_field()?;
                    self.kdbx_file.main_header.extract_kdf_parameters(&v)?;
                }
                header_type::COMMENT => {
                    self.kdbx_file.main_header.comment = self.read_header_field()?;
                }
                header_type::PUBLIC_CUSTOM_DATA => {
                    //The data read for the PublicCustomData is a VariantDictionary similar to KDF parameters.
                    //At this time, as OneKeePass (OKP) does not require any public custom data and no plugins are supported by OKP
                    //So the complete PublicCustomData byetes are just read and stored in a vec. If we need to use this field any time in future,
                    //we need to deserilaize and serilalize similar to KDF parameters to extract individual {Key,Object} values from these bytes
                    self.kdbx_file.main_header.public_custom_data = self.read_header_field()?;
                }
                _ => {
                    error!(
                        "Unknown type code {} found while reading the main header",
                        entry_type
                    );
                    self.kdbx_file.main_header.unknown_data =
                        (entry_type, self.read_header_field()?);
                }
            }
        }
        // Keep the end position of the header data
        self.header_data_end_position = self.reader.stream_position()?;
        Ok(())
    }

    fn read_header_field(&mut self) -> Result<Vec<u8>> {
        let mut buf = [0; 4];
        self.reader.read_exact(&mut buf).unwrap();
        let size = u32::from_le_bytes(buf);
        let mut buffer = Vec::new();
        let r = self.reader.by_ref();
        r.take(size as u64).read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    fn verify_stored_hash(&mut self) -> Result<()> {
        //Following header data we can find the hash data
        let mut stored_hash = [0; 32];
        self.reader.read_exact(&mut stored_hash).unwrap();
        //at this point, the stream is 32 bytes after the header data

        let header_data = read_stream_data(
            self.reader,
            self.header_data_start_position,
            self.header_data_end_position,
        )?;
        let cal_hash = crypto::do_sha256_hash(&[&header_data])?;
        if cal_hash.to_vec() != stored_hash {
            return Err(Error::HeaderHashCheckFailed);
        }
        Ok(())
    }

    fn verify_header_hmac(&mut self) -> Result<()> {
        let mut stored_hmac_hash = [0; 32];
        self.reader.read_exact(&mut stored_hmac_hash)?;

        let header_data = read_stream_data(
            self.reader,
            self.header_data_start_position,
            self.header_data_end_position,
        )?;
        let r = crypto::verify_hmac_sha256(
            &self.kdbx_file.db_key.hmac_key,
            &[&header_data],
            &stored_hmac_hash,
        )?;

        if r {
            Ok(())
        } else {
            Err(Error::HeaderHmacHashCheckFailed)
        }
    }

    // Reads the encrypted payload content of the database that comes after header info and verifies
    // after extracting hmac blocks and the verification of each block of ecrypted data.
    // Returns the encrypted data blocks combined as the final payload.
    fn read_hmac_data_blocks(&mut self) -> Result<Vec<u8>> {
        let mut acc: Vec<u8> = Vec::new();
        // block index is a 64 bit number and used in block hmac key
        let mut blk_idx = 0u64;
        loop {
            //Extract the hmac hash is stored in the begining of a block data
            let mut stored_blk_hmac_hash = [0; 32];
            self.reader.read_exact(&mut stored_blk_hmac_hash)?;
            //Next 4 bytes are the size of the actual encrypted block
            let mut size_buffer = [0; 4];
            // The 4 bytes that gives the block size in bytes number
            self.reader.read_exact(&mut size_buffer)?;
            let blk_size = u32::from_le_bytes(size_buffer);

            if blk_size == 0 {
                // No more blocks
                break;
            }
            // Block data
            let mut data_buffer = Vec::new();
            self.reader
                .by_ref()
                .take(blk_size as u64)
                .read_to_end(&mut data_buffer)?;

            // Each Block's hmac key is based on the block index (LE number) which is a 64 bit number
            // and the previously computed hmac_part_key
            let blk_idx_bytes = blk_idx.to_le_bytes();
            let block_key = crypto::do_sha512_hash(&[
                &blk_idx_bytes.to_vec(),
                &self.kdbx_file.db_key.hmac_part_key,
            ])?;
            // Verify the stored block hmac to the calculated one
            // The data for hmac calc is blk_index + blk_size + blk_data
            // All are in little endian bytes
            let r = crypto::verify_hmac_sha256(
                &block_key,
                &[&blk_idx_bytes, &size_buffer, &data_buffer],
                &stored_blk_hmac_hash,
            )?;
            if !r {
                return Err(Error::BlockHashCheckFailed);
            }
            // Accumulate the verified blocks of data
            acc.append(&mut data_buffer);
            // Next block
            blk_idx += 1;
        }
        Ok(acc)
    }

    fn decrypt_data(&mut self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        let cipher = ContentCipher::try_from(
            &self.kdbx_file.main_header.cipher_id,
            &self.kdbx_file.main_header.encryption_iv,
        )?;
        let mut payload = cipher.decrypt(&encrypted_data, &self.kdbx_file.db_key.master_key)?;

        if self.kdbx_file.main_header.compression_flag == 1 {
            payload = util::decompress(&payload[..])?
        };
        Ok(payload)
    }

    // Splits the inner header and the actual xml content bytes
    fn split_inner_header_xml_content(&mut self, decrypted_data: &[u8]) -> Result<Vec<u8>> {
        let mut buf = Cursor::new(Vec::<u8>::new());
        buf.write(decrypted_data)?;
        buf.seek(SeekFrom::Start(0))?;
        let mut hd_t = [0u8; 1];
        loop {
            // Read one byte that represents the inner header type
            buf.read_exact(&mut hd_t)?;
            // Read next 4 LE bytes that represent how many bytes to read for the data
            let mut size_buf = [0u8; 4];
            buf.read_exact(&mut size_buf)?;
            let bytes_to_read = u32::from_le_bytes(size_buf);
            // Next read the data based on bytes_to_read calculated
            let mut bytes_buf = Vec::new();
            if bytes_to_read != 0 {
                Read::by_ref(&mut buf)
                    .take(bytes_to_read as u64)
                    .read_to_end(&mut bytes_buf)?;
            }
            match hd_t[0] {
                inner_header_type::END_OF_HEADER => {
                    break;
                }
                inner_header_type::STREAM_ID => {
                    self.kdbx_file.inner_header.stream_cipher_id = util::to_u32(&bytes_buf)?;
                    //TODO: Verify that stream_cipher_id is for CHACHA20 only
                }
                inner_header_type::STREAM_KEY => {
                    self.kdbx_file.inner_header.inner_stream_key = bytes_buf;
                }
                inner_header_type::BINARY => {
                    self.kdbx_file.inner_header.add_binary_data(bytes_buf);
                }
                // Should come here?
                _ => {
                    return Err(Error::DataError("Unknown inner header type is found"));
                }
            }
        }
        let mut remaining_bytes: Vec<u8> = Vec::new();
        buf.read_to_end(&mut remaining_bytes)?;
        // remaining_bytes are the xml content as bytes data
        Ok(remaining_bytes)
    }

    fn read_xml_content(&mut self, xml_bytes: &[u8]) -> Result<()> {
        // TODO:
        // Following are used for any debugging to see the XML content during development.
        // This should be removed after making some commnad line program
        // write_xml_to_file("xml-dump/test_read.xml", xml_bytes)?;
        // println!("xml_bytes size {}", std::str::from_utf8(xml_bytes).expect("utf conversion failed"));

        let cipher = ProtectedContentStreamCipher::try_from(
            self.kdbx_file.inner_header.stream_cipher_id,
            &self.kdbx_file.inner_header.inner_stream_key,
        )
        .unwrap();
        let mut r = xml_parse::parse(xml_bytes, Some(cipher))?;
        // IMPORTANT:We need to set attachment hashes in all entries read from xml
        r.after_xml_reading(
            self.kdbx_file
                .inner_header
                .entry_attachments
                .attachments_index_ref_to_hash(),
        );
        self.kdbx_file.keepass_main_content = Some(r);
        Ok(())
    }
}

/////

fn read_stream_data<R: Read + Seek>(reader: &mut R, start: u64, end: u64) -> Result<Vec<u8>> {
    let current_reader_position = reader.stream_position()?;

    //Sets the offset to the provided number of bytes from start
    reader.seek(SeekFrom::Start(start))?;
    let size = end - start;
    let mut buffer = Vec::new();

    //Creates a "by reference" adaptor for this instance of Read.
    //The returned adaptor also implements Read and will simply borrow this current reader
    //self.reader.take(...) will not work as that requires move of Reader
    reader.by_ref().take(size as u64).read_to_end(&mut buffer)?;

    // Resets the stream's position to its original position
    reader.seek(SeekFrom::Start(current_reader_position))?;

    Ok(buffer)
}

pub struct KdbxFileWriter<'a, W>
where
    W: Read + Write + Seek,
{
    writer: &'a mut W,
    kdbx_file: &'a mut KdbxFile,
}

impl<'a, W: Read + Write + Seek> KdbxFileWriter<'a, W> {
    fn new(writer: &'a mut W, kdbx_file: &'a mut KdbxFile) -> KdbxFileWriter<'a, W> {
        KdbxFileWriter { writer, kdbx_file }
    }

    fn write(&mut self) -> Result<()> {
        //IMPORATNT: we need to recompute the keys for encryption so that any changes in main header fields (seed, iv, cipher id etc) are taken care of.
        self.kdbx_file.compute_all_keys()?;

        self.write_file_signature()?;
        self.kdbx_file.main_header.write_bytes(&mut self.writer)?;
        self.write_header_hash()?;

        let mut buf = self.write_compressed_encrypted_payload()?;
        self.write_hmac_data_blocks(&mut buf)?;

        self.writer.flush()?;

        Ok(())
    }

    fn write_file_signature(&mut self) -> Result<()> {
        self.writer.write(&constants::SIG1.to_le_bytes())?;
        self.writer.write(&constants::SIG2.to_le_bytes())?;
        self.writer.write(&constants::VERSION_41.to_le_bytes())?;
        Ok(())
    }

    fn write_header_hash(&mut self) -> Result<()> {
        let header_end = self.writer.stream_position()?;
        let header_data = read_stream_data(&mut self.writer, 0, header_end)?;
        let cal_hash = crypto::do_sha256_hash(&[&header_data])?;
        self.writer.write(&cal_hash)?;

        let header_hmac_hash =
            crypto::do_hmac_sha256(&self.kdbx_file.db_key.hmac_key, &[&header_data])?;
        self.writer.write(&header_hmac_hash)?;

        Ok(())
    }

    fn write_compressed_encrypted_payload(&mut self) -> Result<Vec<u8>> {
        let mut buf = Cursor::new(Vec::<u8>::new());

        if let Some(kp) = &mut self.kdbx_file.keepass_main_content {
            let hashes = kp.root.get_attachment_hashes();
            self.kdbx_file
                .inner_header
                .write_all_bytes(hashes, &mut buf)?;

            // Need to set the new index_refs of all attachments after writing the binaries to inner header
            kp.before_xml_writing(
                self.kdbx_file
                    .inner_header
                    .entry_attachments
                    .attachment_hash_to_index_ref(),
            );
            // Need to get the cipher algorithm used to protect in memory data
            let cipher = ProtectedContentStreamCipher::try_from(
                self.kdbx_file.inner_header.stream_cipher_id,
                &self.kdbx_file.inner_header.inner_stream_key,
            )
            .unwrap();

            let v = xml_parse::write_xml(kp, Some(cipher))?;

            // Need to use {} and not the debug one {:?} to avoid \" in the print
            // println!("In db writing: XML content is \n {}", std::str::from_utf8(&v).unwrap());

            buf.write(&v)?;
        }

        let v = buf.into_inner();
        let mut payload = if self.kdbx_file.main_header.compression_flag == 1 {
            util::compress(&v)?
        } else {
            v
        };

        let cipher = ContentCipher::try_from(
            &self.kdbx_file.main_header.cipher_id,
            &self.kdbx_file.main_header.encryption_iv,
        )?;
        // payload is not encrypted
        payload = cipher.encrypt(&payload, &self.kdbx_file.db_key.master_key)?;
        // Returns the encrypted payload
        Ok(payload)
    }

    fn write_hmac_data_blocks(&mut self, payload_data: &[u8]) -> Result<()> {
        let mut payload_data_buf = Cursor::new(Vec::<u8>::new());
        payload_data_buf.write(payload_data)?;
        payload_data_buf.seek(SeekFrom::End(0))?;
        let mut remaining_bytes = payload_data_buf.stream_position()?;

        let mut blk_idx = 0u64;
        let mut blk_size = cmp::min(PAYLOAD_BLOCK_SIZE, remaining_bytes);
        payload_data_buf.seek(SeekFrom::Start(0))?;
        loop {
            // Read blk size data from payload_data_buf
            let mut data_buffer = Vec::new();
            let data_read = Read::by_ref(&mut payload_data_buf)
                .take(blk_size)
                .read_to_end(&mut data_buffer)?;

            // Find hmac of this block
            // block hmac key is based on block index (LE number) which is a 64 bit number
            let blk_idx_bytes = blk_idx.to_le_bytes();
            let block_key = crypto::do_sha512_hash(&[
                &blk_idx_bytes.to_vec(),
                &self.kdbx_file.db_key.hmac_part_key,
            ])?;

            let blk_size_in_bytes = (data_read as u32).to_le_bytes();
            let blk_hmac_hash = crypto::do_hmac_sha256(
                &block_key,
                &[&blk_idx_bytes, &blk_size_in_bytes, &data_buffer],
            )?;

            // Write the hmac hash
            self.writer.write(&blk_hmac_hash)?;

            // Calculate LE 4 bytes of the size of the actual encrypted block
            // And Write the blk size
            self.writer.write(&blk_size_in_bytes)?;

            if blk_size == 0 {
                break;
            }
            // Write the data_buffer of blk_size data
            self.writer.write(&data_buffer)?;

            remaining_bytes = remaining_bytes - blk_size;
            blk_size = cmp::min(PAYLOAD_BLOCK_SIZE, remaining_bytes);

            // Next block
            blk_idx += 1;
        }
        Ok(())
    }
}

/// Used when user selects to use any file as a key for the db
pub struct FileKey {
    pub(crate) file_name: String,
    pub(crate) content: Vec<u8>,
}

impl FileKey {
    fn open(key_file_name: &str) -> Result<FileKey> {
        if !key_file_name.trim().is_empty() & !Path::new(key_file_name).exists() {
            return Err(Error::NotFound(format!(
                "The key file {} is not valid one",
                key_file_name
            )));
        }
        let file = File::open(key_file_name)?;
        let mut reader = BufReader::new(file);
        let mut buf = vec![];
        reader.read_to_end(&mut buf)?;
        Ok(Self {
            file_name: key_file_name.into(),
            content: buf,
        })
    }

    // Need to return Result so that the invalid file name error can be propagated to caller
    fn from(key_file_name: Option<&str>) -> Result<Option<FileKey>> {
        let key_file: Result<Option<FileKey>> = match key_file_name {
            Some(n) if !n.trim().is_empty() => Ok(Some(FileKey::open(n)?)),
            Some(_) => Ok(None),
            None => Ok(None),
        };
        key_file
    }
}

pub fn open_db_file(db_file_name: &str) -> Result<BufReader<File>> {
    let file = match File::open(&db_file_name) {
        Ok(f) => f,
        Err(e) => {
            return Err(Error::DbFileIoError(
                "Database file opening failed".into(),
                e,
            ));
        }
    };
    Ok(BufReader::new(file))
}

/// Opens a KeePass db file
pub fn open_and_read(
    db_file_name: &str,
    password: &str,
    key_file_name: Option<&str>,
) -> Result<KdbxFile> {
    let file = match File::open(&db_file_name) {
        Ok(f) => f,
        Err(e) => {
            return Err(Error::DbFileIoError(
                "Database file opening failed".into(),
                e,
            ));
        }
    };
    let mut reader = BufReader::new(file);
    read_db_from_reader(&mut reader, db_file_name, password, key_file_name)
}

pub fn read_db_from_reader<R: Read + Seek>(
    reader: &mut R,
    db_file_name: &str,
    password: &str,
    key_file_name: Option<&str>,
) -> Result<KdbxFile> {
    let file_key = FileKey::from(key_file_name)?;
    let pb = password.as_bytes().to_vec();
    //let kb = file_key.map(|k| k.content); //converts Option<FileKey> to Option<Vec<u8>>
    let kdbx = KdbxFile {
        database_file_name: db_file_name.into(),
        password: pb,
        //key_file_data: kb,
        file_key,
        main_header: MainHeader::default(),
        inner_header: InnerHeader::default(),
        db_key: DbKey::default(),
        keepass_main_content: None,
    };

    read_db(reader, kdbx)
}

fn read_db<R: Read + Seek>(buff: &mut R, kdbx_file: KdbxFile) -> Result<KdbxFile> {
    let mut db_reader = KdbxFileReader::new(buff, kdbx_file);
    db_reader.read()?;
    Ok(db_reader.kdbx_file)
}

pub fn write_db<W: Write + Read + Seek>(buff: &mut W, kdbx_file: &mut KdbxFile) -> Result<()> {
    let mut w = KdbxFileWriter::new(buff, kdbx_file);
    let _wr = w.write()?;
    Ok(())
}

/// Writes the KDBX content to a db file found in 'kdbx_file.db_file_name'
pub fn write_kdbx_file(kdbx_file: &mut KdbxFile) -> Result<()> {
    debug!(
        "Going to write to the KDBX file {}",
        &kdbx_file.database_file_name
    );

    // Ensure that the parent dir exists
    if let Some(p) = Path::new(&kdbx_file.database_file_name).parent() {
        if !p.exists() {
            std::fs::create_dir_all(p)?;
        }
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&kdbx_file.database_file_name)?;

    write_db(&mut file, kdbx_file)?;
    file.sync_all()?;

    debug!(
        "Writing to KDBX file {} completed",
        &kdbx_file.database_file_name
    );

    Ok(())
}

pub fn write_kdbx_file_with_backup_file(
    kdbx_file: &mut KdbxFile,
    backup_file_name: Option<&str>,
) -> Result<()> {
    if let Some(b) = backup_file_name {
        let mut backup_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(b)?;

        debug!("Going to save the backup file {}", b);
        write_db(&mut backup_file, kdbx_file)?;
        backup_file.sync_all()?;
        debug!("Saving the backup file done");
        debug!(
            "Going to save the database file {}",
            kdbx_file.database_file_name
        );
        std::fs::copy(&b, &kdbx_file.database_file_name)?;
        debug!("Saving the database file done");
        Ok(())
    } else {
        log::error!("Backup file name is not available and saving directly to the databae file without any backup");
        write_kdbx_file(kdbx_file)
    }
}

// See comment in KdbxFileReader::read_xml_content to use this function to dump the raw xml
// obtained after decrypting the database. Useful for debugging
// when read the database file created by other programs

/// Writes the xml bytes data to a file as xml
fn write_xml_to_file(xml_file_name: &str, xml_bytes: &[u8]) -> Result<()> {
    let mut file = File::create(xml_file_name)?;
    file.write_all(xml_bytes)?;
    info!("Xml content is written to the file {}", xml_file_name);
    Ok(())
}

// TODO:
// Expose export_as_xml and import_from_xml to UI through db_service module and/or through
// some CLI

/// Exports the keepass database content as xml using the same format used in KeePass's xml content
/// All protected field values are decrypted and are in plain text format. No attachments data will be exported
#[allow(dead_code)]
pub fn export_as_xml(kdbx_file: &mut KdbxFile, xml_file_name: Option<&str>) -> Result<()> {
    let fname = xml_file_name.unwrap_or("xml_dump.xml");
    if let Some(ref mut kp) = kdbx_file.keepass_main_content {
        kp.before_xml_writing(
            kdbx_file
                .inner_header
                .entry_attachments
                .attachment_hash_to_index_ref(),
        );
        let data = xml_parse::write_xml_with_indent(kp, None)?;
        write_xml_to_file(fname, &data)?;
    }
    Ok(())
}

pub fn export_db_main_content_as_xml(
    keepass_main_content: &KeepassFile,
    xml_file_name: &str,
) -> Result<()> {
    let data = xml_parse::write_xml_with_indent(keepass_main_content, None)?;
    write_xml_to_file(xml_file_name, &data)?;
    Ok(())
}

/// Imports any previously exported keepass xml content into a new database
#[allow(dead_code)]
pub fn import_from_xml(
    xml_file_name: &str,
    db_file_name: &str,
    password: &str,
    key_file_name: Option<&str>,
) -> Result<KdbxFile> {
    let file = File::open(xml_file_name)?;
    let mut reader = BufReader::new(file);
    let mut buf = vec![];
    reader.read_to_end(&mut buf)?;

    let kp = xml_parse::parse(&buf, None)?;
    //println!("KeePassContet is {:?}", r);

    let mut ndb = NewDatabase::default();
    ndb.database_file_name = db_file_name.into();
    ndb.password = password.into();
    ndb.key_file_name = key_file_name.map(|s| s.into());

    let mut kdbx_file = ndb.create()?;
    kdbx_file.keepass_main_content = Some(kp);

    Ok(kdbx_file)
}
