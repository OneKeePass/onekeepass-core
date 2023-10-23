use crate::write_header_with_size;

use super::*;

#[derive(Default, Clone)]
pub struct KdbxFile {
    // database_file_name is full uri and used as db_key in all subsequent calls
    // See db_service::read_kdbx
    pub(crate) database_file_name: String,
    pub(crate) file_key: Option<FileKey>,
    pub(crate) main_header: MainHeader,
    pub(crate) inner_header: InnerHeader,
    pub(crate) secured_database_keys: SecuredDatabaseKeys,
    pub(crate) keepass_main_content: Option<KeepassFile>,
    pub(crate) checksum_hash: Vec<u8>,
}

impl KdbxFile {
    #[inline]
    pub fn hmac_part_key(&self) -> &Vec<u8> {
        &self.secured_database_keys.hmac_part_key
    }

    #[inline]
    pub fn hmac_key(&self) -> &Vec<u8> {
        &self.secured_database_keys.hmac_key
    }

    #[inline]
    pub fn master_key(&self) -> &Vec<u8> {
        &self.secured_database_keys.master_key
    }

    pub fn compute_all_keys(&mut self, seed_reset: bool) -> Result<()> {
        if seed_reset {
            // Before the next save, we need to reset the master seed and encryption iv to new set of values
            let _r = self.main_header.reset_master_seed_iv()?;
        }
        self.secured_database_keys.compute_all_keys(
            &self.database_file_name,
            &self.main_header.kdf_algorithm,
            &self.main_header.master_seed,
        )
    }

    // #[inline]
    // pub fn reset_master_seed_iv(&mut self) -> Result<(Vec<u8>,Vec<u8>)> {
    //     self.main_header.reset_master_seed_iv()
    // }

    pub fn compare_key(&self, password: Option<&str>, key_file_name: Option<&str>) -> Result<bool> {
        let file_key = FileKey::from(key_file_name)?;
        self.secured_database_keys
            .compare_keys(&self.database_file_name, password, &file_key)
    }

    //----------------------------
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

    // Called to set a new key file use.
    // Opens the named file, reads and uses its content while computing key
    pub fn set_file_key(&mut self, key_file_name: Option<&str>) -> Result<()> {
        
        // We need not do anything if the current db does not use key file and the no file name is selected
        // for 'key_file_name'
        if self.file_key.is_none() && key_file_name.is_none() {
            return Ok(());
        }
        // If the incoming key_file_name is the same name as the currently used file key name
        // We can skip updating.
        // TODO:
        // Need to add some flag in DbSettings so that we can avoid calling 'set_file_key' with the same
        // key file in 'db_service::set_db_settings'
        if let (Some(fk), Some(s)) = (&self.file_key, key_file_name) {
            if fk.file_name == s {
                return Ok(());
            }
        }

        self.file_key = match key_file_name {
            Some(s) => Some(FileKey::open(s)?), // key file should exists or opening error will happen
            None => None,
        };

        //self.db_key.secured_db_keys.set_file_key(&self.database_file_name, self.file_key.as_ref())?;

        self.secured_database_keys
            .set_file_key(&self.database_file_name, self.file_key.as_ref())?;

        Ok(())
    }

    // Called when both password and key file are changed in settings
    pub fn set_credentials(&mut self, db_key: &str, password: Option<&str>,key_file_name: Option<&str>) -> Result<()> {
        
        let file_key = FileKey::from(key_file_name)?;
        let mut keys = SecuredDatabaseKeys::from_keys(password, &file_key)?;
        keys.secure_keys(db_key)?;
        self.secured_database_keys = keys;
        
        Ok(())
    }

    pub fn set_password(&mut self, password: Option<&str>) -> Result<()> {
        self.secured_database_keys
            .set_password(&self.database_file_name, password)
    }

    // Gets whether pasword or/and key file are used in master key or not
    pub fn credentials_used_state(&self) -> (bool,bool) {
        self.secured_database_keys.credentials_used_state()
    }

    pub fn set_database_file_name(&mut self, database_file_name: &str) -> &mut Self {
        self.database_file_name = database_file_name.into();
        self
    }

    pub fn get_database_file_name(&self) -> &str {
        &self.database_file_name
    }

    /// Called when user uploads an attachment in UI
    /// Returns the attachment content's hash for later reference
    pub fn upload_entry_attachment(&mut self, data: Vec<u8>) -> AttachmentHashValue {
        self.inner_header.entry_attachments.insert(data)
    }

    // Provides the stored attachment bytes data for viewing or saving by user
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
        let (cid, eiv) = content_cipher_id.uuid_with_iv()?;
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

#[derive(Default, Clone)]
pub(crate) struct MainHeader {
    pub(crate) cipher_id: Vec<u8>,
    // Required in determining various keys
    pub(crate) master_seed: Vec<u8>,
    /// Formed from 4 LE bytes [1, 0, 0, 0]  
    pub(crate) compression_flag: i32,
    // Required to use with a cryptographic primitive to provide the initial state
    pub(crate) encryption_iv: Vec<u8>,
    pub(crate) public_custom_data: Vec<u8>,
    pub(crate) comment: Vec<u8>,
    pub(crate) unknown_data: (u8, Vec<u8>),
    pub(crate) kdf_algorithm: KdfAlgorithm,
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
    pub(crate) fn extract_kdf_parameters(&mut self, data: &[u8]) -> Result<()> {
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

    pub(crate) fn write_bytes<W: Write + Seek>(&mut self, writer: &mut W) -> Result<()> {
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

    // Reset the master seed and encryption iv for the next saving
    pub(crate) fn reset_master_seed_iv(&mut self) -> Result<()> {
        let cid = match self.cipher_id.as_slice() {
            constants::uuid::AES256 => ContentCipherId::Aes256,
            constants::uuid::CHACHA20 => ContentCipherId::ChaCha20,
            _ => ContentCipherId::UnKnownCipher,
        };
        let (ms, iv) = cid.generate_master_seed_iv()?;
        self.master_seed = ms;
        self.encryption_iv = iv;
        debug!("Master seed and encryption IV are reset");
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct InnerHeader {
    // Id dereived from the LE bytes stored in inner_stream_id
    pub(crate) stream_cipher_id: u32,
    pub(crate) inner_stream_key: Vec<u8>,

    // All attachemnt binaries are in the same order as they are in the db
    // They are referred by "index_ref" (from "Ref" attribute of XML db) field of "BinaryKeyValue" struct
    // The attachement vec's first byte is a flag to indicate whether the data needs protection
    // and remaining bytes are the actual attachment
    // Such attachments data are stored in AttachmentSet for easy lookup as well as for uploading new ones
    pub(crate) entry_attachments: AttachmentSet,
}

impl InnerHeader {
    // Called to keep the attachment bytes data for later use
    pub(crate) fn add_binary_data(&mut self, data: Vec<u8>) {
        self.entry_attachments.add(data);
    }

    // Provides the stored attachment bytes data for viewing or saving by user
    fn get_bytes_content(&self, data_hash: &AttachmentHashValue) -> Option<Vec<u8>> {
        self.entry_attachments.get_bytes_content(data_hash)
    }

    // Called to write all attachment binaries identified by the hashes
    // The arg 'attachment_hashes' is created in root.get_attachment_hashes
    pub(crate) fn write_all_bytes<W: Write>(
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

            // None means the hash to 'index_ref' is not yet done and binary data for this hash is not yet written
            if hidx.is_none() {
                if let Some(data) = self.entry_attachments.attachments.get(&h) {
                    write_header_with_size!(writer, inner_header_type::BINARY, &data);
                }
                // Recreate the 'hash_index_ref' entry 
                // This index will be used to set in "Ref" attribute of an entry's BinaryKeyValue tag
                self.entry_attachments
                    .hash_index_ref
                    .insert(h, writen_index);
                writen_index = writen_index + 1;
            }
            // else {
            //     println!("Hash {} is already found at index {:?} and skipping writing to binary data", &h, hidx);
            // }
        }

        // End of header - 0 size data
        writer.write(&[inner_header_type::END_OF_HEADER])?;

        // [0, 0, 0, 0] => 0 bytes size - No inner header data for end marker
        writer.write(&vec![0u8; 4])?;

        Ok(())
    }
}
