mod file_key;
mod kdbx_file;
mod key_secure;
mod new_db;
mod reader_writer;

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::hash::Hasher;
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom, Write};
use std::path::Path;

use log::{debug, error, info};
use serde::{Deserialize, Serialize};

use self::kdbx_file::InnerHeader;

use self::reader_writer::{KdbxFileReader, KdbxFileWriter};
use crate::constants::{self, EMPTY_STR};
use crate::constants::{header_type, inner_header_type, vd_type};
use crate::crypto::kdf::Kdf;
use crate::{crypto, error};

use crate::db_content::*;
use crate::error::{Error, Result};
use crate::util;
use crate::xml_parse;
use kdbx_file::MainHeader;

// Reexports
pub(crate) use self::file_key::{FileKey, KeyFileData};
pub use crypto::ContentCipherId;
pub use kdbx_file::KdbxFile;
pub use key_secure::{KeyStoreOperation, KeyStoreService, KeyStoreServiceType};
pub use new_db::NewDatabase;

/// Writes the header type byte and header data of Vec<u8> type with size le bytes as prefix
/// This macro is used for both MainHeader and InnerHeader Vec<u8> data writing
#[macro_export]
macro_rules! write_header_with_size {
    ($writer:tt,$id:expr,$data:expr) => {
        $writer.write(&[$id])?; //header type or inner header type
        let size = $data.len() as u32;
        $writer.write(&size.to_le_bytes())?;
        $writer.write($data)?;
    };
}

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

impl KdfAlgorithm {
    pub fn default_argon2() -> Self {
        KdfAlgorithm::Argon2(crypto::kdf::Argon2Kdf::default())
    }

    // Creates argon2 with specific parameters values
    // The arg 'memory' size is in bytes
    pub fn as_argon2(memory: u64, iterations: u64, parallelism: u32) -> Self {
        // The incoming memory bytes size needs to be converted to size in Mb
        let mem = memory * 1024 * 1024;
        KdfAlgorithm::Argon2(crypto::kdf::Argon2Kdf::from(mem, iterations, parallelism))
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct AttachmentSet {
    // All attachments bytes data accessible by its hash.
    attachments: HashMap<AttachmentHashValue, Vec<u8>>,

    // Read time hash look up is populated while reading the xml content and
    // it is used to set the hash values to BinaryKeyValue of entries' binary_key_values
    index_ref_hash: HashMap<i32, (AttachmentHashValue, usize)>,

    // Write time look up and it is used to set the index refs in entries that have attachments based on the
    // hash value found in 'BinaryKeyValue'
    hash_index_ref: HashMap<AttachmentHashValue, i32>,
}

impl AttachmentSet {
    // Called to add the bytes data while reading the db content
    fn add(&mut self, data: Vec<u8>) {
        let key = AttachmentSet::to_hash(&data);

        // The first byte is a flag to indicate whether the data needs protection or not
        // and we need to exclude it from the content
        let size = data.len() - 1;

        self.attachments.insert(key, data);

        // Index is the value used in Ref attribute
        let index = self.attachments.len() as i32;

        // The index look up
        self.index_ref_hash.insert(index - 1, (key, size));
    }

    // Gets the bytes content of attachment for view or saving
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

    // Called when a new document is uploaded
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

    // Generates a hash key based on the attachment bytes data
    fn to_hash(data: &[u8]) -> AttachmentHashValue {
        let mut hasher = DefaultHasher::new();
        hasher.write(data);
        hasher.finish()
    }

    // Provides the the Ref to Hash (of attachment) value for all attachments and it is used
    // to set in the BinaryKeyValue struct of the entries during reading
    pub fn attachments_index_ref_to_hash(&self) -> &HashMap<i32, (AttachmentHashValue, usize)> {
        &self.index_ref_hash
    }

    pub fn attachment_hash_to_index_ref(&self) -> &HashMap<AttachmentHashValue, i32> {
        &self.hash_index_ref
    }
}

#[derive(Clone)]
pub(crate) struct SecuredDatabaseKeys {
    // 32 bytes formed using sha256_hash
    password_hash: Option<Vec<u8>>,
    // 32 bytes formed using sha256_hash
    key_file_data_hash: Option<Vec<u8>>,
    // 32 bytes formed using sha256_hash of password_hash and key_file_data_hash
    composite_key: Vec<u8>,
    // 32 bytes see KDF call
    transformed_key: Vec<u8>,
    // 64 bytes formed using sha512_hash - see compute_keys
    hmac_part_key: Vec<u8>,
    // 64 bytes formed using sha512_hash  - see compute_keys
    hmac_key: Vec<u8>,
    // 32 bytes formed using sha256_hash  - see compute_keys
    master_key: Vec<u8>,
    encrypted: bool,
}

impl Default for SecuredDatabaseKeys {
    fn default() -> Self {
        Self {
            password_hash: None,
            key_file_data_hash: None,
            composite_key: vec![],
            transformed_key: vec![],
            hmac_part_key: vec![],
            hmac_key: vec![],
            master_key: vec![],
            encrypted: false,
        }
    }
}

impl SecuredDatabaseKeys {
    fn from_keys(password: Option<&str>, file_key: &Option<FileKey>) -> Result<Self> {
        let (p, f, c) = match (password, file_key) {
            (Some(p), Some(f)) => {
                // Final hash is sha256(sha256(password) + keyfile_content)
                let phash = crypto::sha256_hash_from_slice(p.as_bytes())?;
                let fhash = f.content_hash();
                let data = vec![&phash, &fhash];
                let final_hash = crypto::sha256_hash_vec_vecs(&data)?;

                (Some(phash), Some(fhash), final_hash)
            }
            (Some(p), None) => {
                // Final hash is sha256(sha256(password))
                let phash = crypto::sha256_hash_from_slice(p.as_bytes())?;
                let final_hash = crypto::sha256_hash_from_slice(phash.as_ref())?;

                (Some(phash), None, final_hash)
            }
            (None, Some(f)) => {
                // Final hash is sha256(keyfile_content)
                let fhash = f.content_hash();
                let final_hash = crypto::sha256_hash_from_slice(&fhash)?;

                (None, Some(fhash), final_hash)
            }
            (None, None) => {
                return Err(error::Error::InSufficientCredentials);
            }
        };

        let sk = Self {
            password_hash: p,
            key_file_data_hash: f,
            composite_key: c,
            transformed_key: vec![],
            hmac_part_key: vec![],
            hmac_key: vec![],
            master_key: vec![],
            encrypted: false,
        };

        Ok(sk)
    }

    // IMPORTANT: Need to call this to encrypt the keys and store it in a secure store
    pub(crate) fn secure_keys(&mut self, db_key: &str) -> Result<()> {
        let kc = crypto::KeyCipher::new();

        // Encrypt all previously calculated hashes

        if let Some(pw) = &self.password_hash {
            self.password_hash = Some(kc.encrypt(&pw)?);
        }

        if let Some(file_data) = &self.key_file_data_hash {
            self.key_file_data_hash = Some(kc.encrypt(file_data)?);
        }

        self.composite_key = kc.encrypt(&self.composite_key)?;

        let mut data = kc.key.clone();
        data.extend_from_slice(&kc.nonce);

        // Need to store the encryption key for future use
        KeyStoreOperation::store_key(db_key, data)?;

        self.encrypted = true;

        Ok(())
    }

    fn compute_keys(&mut self, master_seed: &Vec<u8>, transformed_key: Vec<u8>) -> Result<()> {
        self.transformed_key = transformed_key;
        // 1 byte with value 1 added as suffix
        let suffix = vec![1u8; 1];
        self.hmac_part_key =
            crypto::sha512_hash_from_slice_vecs(&[master_seed, &self.transformed_key, &suffix])?;

        // 8 bytes of value 255 prefixed (value 255 repeated 8 times) ; -1 in i8
        let prefix = vec![255u8; 8];

        self.hmac_key = crypto::sha512_hash_from_slice_vecs(&[&prefix, &self.hmac_part_key])?;
        self.master_key =
            crypto::sha256_hash_from_slice_vecs(&[master_seed, &self.transformed_key])?;

        Ok(())
    }

    fn compute_all_keys(
        &mut self,
        db_key: &str,
        kdf_algorithm: &KdfAlgorithm,
        master_seed: &Vec<u8>,
    ) -> Result<()> {
        if let KdfAlgorithm::Argon2(kdf) = &kdf_algorithm {
            let ck = self.get_composite_key(db_key)?;
            //Then transform the composite key using KDF
            let transformed_key = kdf.transform_key(ck)?;

            //Determine the HMAC and Payload Encryption/Decryption Key
            self.compute_keys(&master_seed, transformed_key)?;
        } else {
            return Err(Error::SupportedOnlyArgon2dKdfAlgorithm);
        }
        Ok(())
    }

    // Gets the composite key; This decrypts the key if required
    fn get_composite_key(&self, db_key: &str) -> Result<Vec<u8>> {
        if self.encrypted {
            self.decrypt_composite_key(db_key)
        } else {
            Ok(self.composite_key.clone())
        }
    }

    fn decrypt_key(&self, db_key: &str, data: &[u8]) -> Result<Vec<u8>> {
        if let Some(keydata) = KeyStoreOperation::get_key(db_key) {
            let keyinfo = SecureKeyInfo::from_key_nonce(keydata);
            let kc = crypto::KeyCipher::from(&keyinfo.key, &keyinfo.nonce);
            kc.decrypt(data)
        } else {
            Err(Error::UnexpectedError(format!(
                "No key is available for the decryption of data for db key {}",
                db_key
            )))
        }
    }

    fn encrypt_key(&self, db_key: &str, data: &[u8]) -> Result<Vec<u8>> {
        if let Some(keydata) = KeyStoreOperation::get_key(db_key) {
            let keyinfo = SecureKeyInfo::from_key_nonce(keydata);
            let kc = crypto::KeyCipher::from(&keyinfo.key, &keyinfo.nonce);
            kc.encrypt(data)
        } else {
            Err(Error::UnexpectedError(format!(
                "No key is available for the encryption of data for db key {}",
                db_key
            )))
        }
    }

    // Called before saving the database
    // composite_key is required to create other keys
    fn decrypt_composite_key(&self, db_key: &str) -> Result<Vec<u8>> {
        self.decrypt_key(db_key, &self.composite_key)
    }

    // Called for quick unlock when user uses credentials
    // Assumed that we will be able to get the encryption key
    fn compare_keys(
        &self,
        db_key: &str,
        password: Option<&str>,
        file_key: &Option<FileKey>,
    ) -> Result<bool> {
        let chash = match (password, file_key) {
            (Some(p), Some(f)) => {
                let phash = crypto::sha256_hash_from_slice(p.as_bytes())?;
                let fhash = f.content_hash();
                let data = vec![&phash, &fhash];
                let final_hash = crypto::sha256_hash_vec_vecs(&data)?;
                final_hash
            }
            (Some(p), None) => {
                let phash = crypto::sha256_hash_from_slice(p.as_bytes())?;
                crypto::sha256_hash_from_slice(&phash)?
            }
            (None, Some(f)) => {
                let fhash = f.content_hash();
                crypto::sha256_hash_from_slice(&fhash)?
            }
            (None, None) => {
                return Err(error::Error::InSufficientCredentials);
            }
        };

        let existing_chash = self.decrypt_composite_key(db_key)?;

        Ok(chash == existing_chash)
    }

    // Called whenever user changes the password
    pub(crate) fn set_password(&mut self, db_key: &str, password: Option<&str>) -> Result<()> {
        let (pw_hash, chash) = match (password, &self.key_file_data_hash) {
            (Some(p), Some(key_file_hash)) => {
                // User changed the password, but retained the current key file
                let phash = crypto::sha256_hash_from_slice(p.as_bytes())?;
                // Need to get the previous key file hash
                let fhash = self.decrypt_key(db_key, key_file_hash)?;
                let data = vec![&phash, &fhash];
                let final_hash = crypto::sha256_hash_vec_vecs(&data)?;
                (Some(phash), final_hash)
            }
            (Some(p), None) => {
                // User changed the password and currently no key file is used
                let phash = crypto::sha256_hash_from_slice(p.as_bytes())?;
                let final_hash = crypto::sha256_hash_from_slice(&phash)?;
                (Some(phash), final_hash)
            }
            (None, Some(key_file_hash)) => {
                // User has removed the use of password and only the currently used key file is kept
                let fhash = self.decrypt_key(db_key, key_file_hash)?;
                let final_hash = crypto::sha256_hash_from_slice(&fhash)?;
                (None, final_hash)
            }

            (None, None) => {
                return Err(error::Error::InSufficientCredentials);
            }
        };

        // Set the newly encrypted hashes
        if let Some(h) = pw_hash {
            self.password_hash = Some(self.encrypt_key(db_key, &h)?);
        } else {
            self.password_hash = None
        }
        self.composite_key = self.encrypt_key(db_key, &chash)?;

        Ok(())
    }

    // Called whenever user changes the key file usage
    pub(crate) fn set_file_key(
        &mut self,
        db_key: &str,
        file_key_opt: Option<&FileKey>,
    ) -> Result<()> {
        let (file_hash_opt, chash) = match (&self.password_hash, file_key_opt) {
            (Some(p), Some(file_key)) => {
                // User changed the key file and retains the same password
                let file_hash = file_key.content_hash();
                let phash = self.decrypt_key(db_key, p)?;
                // phash is already the sha256_hash of original password str
                let data = vec![&phash, &file_hash];
                let chash = crypto::sha256_hash_vec_vecs(&data)?;
                (Some(file_hash), chash)
            }
            (Some(p), None) => {
                // User removed the use of key file
                let phash = self.decrypt_key(db_key, p)?;
                let chash = crypto::sha256_hash_from_slice(&phash)?;
                (None, chash)
            }
            (None, Some(file_key)) => {
                // User changed the key file and no password is used as before
                let file_hash = file_key.content_hash();
                let chash = crypto::sha256_hash_from_slice(&file_hash)?;
                (Some(file_hash), chash)
            }
            (None, None) => {
                return Err(error::Error::InSufficientCredentials);
            }
        };

        // Need to encrypt the changed hahses
        if let Some(fhash) = file_hash_opt {
            self.key_file_data_hash = Some(self.encrypt_key(db_key, &fhash)?);
        } else {
            self.key_file_data_hash = None;
        }
        self.composite_key = self.encrypt_key(db_key, &chash)?;

        Ok(())
    }

    pub(crate) fn credentials_used_state(&self) -> (bool, bool) {
        (
            self.password_hash.is_some(),
            self.key_file_data_hash.is_some(),
        )
    }
}

#[derive(Debug, Default, Clone)]
pub struct SecureKeyInfo {
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
}

impl SecureKeyInfo {
    pub fn from_key_nonce(key_nonce: Vec<u8>) -> Self {
        let mut key = key_nonce;
        // key_nonce is 44 bytes = 32 bytes key + 12 bytes nonce
        // 0 to 31 bytes for key, 32 to 43 for nonce
        let nonce = key.split_off(32);
        Self { key, nonce }
    }

    pub fn combine_key_nonce(&self) -> Vec<u8> {
        let mut data = self.key.clone();
        data.extend_from_slice(&self.nonce);
        data
    }
}

// #[derive(Clone, Serialize, Deserialize, Debug)]
// pub enum ContentCipherId {
//     ChaCha20,
//     Aes256,
//     UnKnownCipher,
// }

// impl ContentCipherId {
//     fn to_uuid_id(&self) -> Result<(Vec<u8>, Vec<u8>)> {
//         let mut rng = crypto::SecureRandom::new();
//         match self {
//             ContentCipherId::Aes256 => {
//                 Ok((constants::uuid::AES256.to_vec(), rng.get_bytes::<16>()))
//             }
//             ContentCipherId::ChaCha20 => {
//                 Ok((constants::uuid::CHACHA20.to_vec(), rng.get_bytes::<12>()))
//             }
//             _ => return Err(Error::UnsupportedCipher(vec![])),
//         }
//     }

//     fn generate_master_seed_iv(&self) -> Result<(Vec<u8>, Vec<u8>)> {
//         let mut rng = crypto::SecureRandom::new();
//         match self {
//             ContentCipherId::Aes256 => Ok((rng.get_bytes::<32>(), rng.get_bytes::<16>())),
//             ContentCipherId::ChaCha20 => Ok((rng.get_bytes::<32>(), rng.get_bytes::<12>())),
//             _ => return Err(Error::UnsupportedCipher(vec![])),
//         }
//     }
// }

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

// Used for both desktop and mobile
pub fn read_db_from_reader<R: Read + Seek>(
    reader: &mut R,
    db_file_name: &str,
    password: Option<&str>,
    key_file_name: Option<&str>,
) -> Result<KdbxFile> {
    let file_key = FileKey::from(key_file_name)?;
    let secured_database_keys = SecuredDatabaseKeys::from_keys(password, &file_key)?;
    //let kb = file_key.map(|k| k.content); //converts Option<FileKey> to Option<Vec<u8>>
    let kdbx = KdbxFile {
        // database_file_name is full uri and used as db_key in all subsequent calls
        // See db_service::read_kdbx
        database_file_name: db_file_name.into(),
        file_key,
        main_header: MainHeader::default(),
        inner_header: InnerHeader::default(),
        secured_database_keys,
        keepass_main_content: None,
        checksum_hash: vec![],
    };

    // Need to get the checksum to track db file content changes outside the application if any
    let mut updated_kdbx = read_db(reader, kdbx)?;
    let cs = calculate_db_file_checksum(reader)?;

    updated_kdbx.checksum_hash = cs;

    updated_kdbx
        .secured_database_keys
        .secure_keys(db_file_name)?;

    Ok(updated_kdbx)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows",))]
pub fn reload<R: Read + Seek>(reader: &mut R, kdbx_file: &KdbxFile) -> Result<KdbxFile> {
    let kdbx = kdbx_file.clone();
    let mut updated_kdbx = read_db(reader, kdbx)?;
    let cs = calculate_db_file_checksum(reader)?;
    updated_kdbx.checksum_hash = cs;
    Ok(updated_kdbx)
}

fn read_db<R: Read + Seek>(buff: &mut R, kdbx_file: KdbxFile) -> Result<KdbxFile> {
    let mut db_reader = KdbxFileReader::new(buff, kdbx_file);

    crypto::print_crypto_lib_info();

    db_reader.read()?;
    Ok(db_reader.kdbx_file)
}

pub fn write_db<W: Write + Read + Seek>(buff: &mut W, kdbx_file: &mut KdbxFile) -> Result<()> {
    let mut w = KdbxFileWriter::new(buff, kdbx_file);
    let _wr = w.write()?;
    Ok(())
}

// Calculates checksum for later verification before saving
pub fn calculate_db_file_checksum<R: Read + Seek>(reader: &mut R) -> Result<Vec<u8>> {
    let pos = reader.stream_position()?;
    reader.rewind()?;
    // For now, we just consider the first 1000 samples as sample checksum
    let mut buffer = [0; 1000];
    // read up to 1000 bytes

    let _n = reader.read(&mut buffer[..])?;
    let cs = crypto::sha256_hash_from_slice(&buffer);

    reader.seek(SeekFrom::Start(pos))?;
    Ok(cs?.to_vec())
}

// Reads the db file and check whether the file content is modified externally
pub fn read_and_verify_db_file(kdbx_file: &mut KdbxFile) -> Result<()> {
    let mut db_file_read = OpenOptions::new()
        .read(true)
        .open(kdbx_file.get_database_file_name())?;
    verify_db_file_checksum(kdbx_file, &mut db_file_read)
}

// Reads data from the reader formed from the db file to compute the checksum and compares
// with the previously calculated one
pub fn verify_db_file_checksum<R: Read + Seek>(
    kdbx_file: &mut KdbxFile,
    reader: &mut R,
) -> Result<()> {
    let cs = calculate_db_file_checksum(reader)?;
    if cs.eq(&kdbx_file.checksum_hash) {
        Ok(())
    } else {
        Err(Error::DbFileContentChangeDetected)
    }
}

// Writes the KDBX content to a db file found in 'kdbx_file.db_file_name'
// Typically overwrite is true when this fn is called when we save a new db or when we call 'Save As'
pub fn write_kdbx_file(kdbx_file: &mut KdbxFile, overwrite: bool) -> Result<()> {
    // Ensure that the parent dir exists
    if let Some(p) = Path::new(kdbx_file.get_database_file_name()).parent() {
        if !p.exists() {
            std::fs::create_dir_all(p)?;
        }
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(kdbx_file.get_database_file_name())?;

    if !overwrite {
        // Need to ensure that file is not changed outside our app
        verify_db_file_checksum(kdbx_file, &mut file)?;
        // file stream position is reset to the start. Is it required?
        file.rewind()?;
    }

    write_db(&mut file, kdbx_file)?;
    file.sync_all()?;

    // New checksum for the next time use
    kdbx_file.checksum_hash = calculate_db_file_checksum(&mut file)?;

    debug!(
        "New checksum is calculated and writing to KDBX file {} completed",
        kdbx_file.get_database_file_name()
    );

    Ok(())
}

// iOS - Autofill
// Desktop
// Called to save the current database content to a given file
pub fn write_kdbx_content_to_file(kdbx_file: &mut KdbxFile, full_file_name: &str) -> Result<()> {
    // Ensure that the parent dir exists
    if let Some(p) = Path::new(full_file_name).parent() {
        if !p.exists() {
            std::fs::create_dir_all(p)?;
        }
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(full_file_name)?;

    write_db(&mut file, kdbx_file)?;
    file.sync_all()?;

    Ok(())
}

// Called to save first to a backup file and then copied from that backup to the actual db file
pub fn write_kdbx_file_with_backup_file(
    kdbx_file: &mut KdbxFile,
    backup_file_name: Option<&str>,
    overwrite: bool,
) -> Result<()> {
    if let Some(b) = backup_file_name {
        let mut backup_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(b)?;

        write_db(&mut backup_file, kdbx_file)?;
        backup_file.sync_all()?;

        if !overwrite {
            // Need to ensure that file is not changed outside our app
            read_and_verify_db_file(kdbx_file)?;
        }

        std::fs::copy(&b, kdbx_file.get_database_file_name())?;

        // New checksum for the next time use
        kdbx_file.checksum_hash = calculate_db_file_checksum(&mut backup_file)?;

        Ok(())
    } else {
        log::error!("Backup file name is not available and saving directly to the databae file without any backup");
        write_kdbx_file(kdbx_file, overwrite)
    }
}

// See comment in KdbxFileReader::read_xml_content to use this function to dump the raw xml
// obtained after decrypting the database. Useful for debugging
// when read the database file created by other programs

// Writes the xml bytes data to a file as xml
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
    password: Option<&str>,
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
    ndb.password = password.map(|s| s.to_string());
    ndb.key_file_name = key_file_name.map(|s| s.into());

    let mut kdbx_file = ndb.create()?;
    kdbx_file.keepass_main_content = Some(kp);

    Ok(kdbx_file)
}

#[inline]
pub fn create_key_file(key_file_name: &str) -> Result<()> {
    FileKey::create_xml_key_file(key_file_name)
}
