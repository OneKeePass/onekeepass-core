use crate::write_header_with_size;

use super::*;

#[derive(Default, Clone)]
pub struct KdbxFile {
    // database_file_name is full uri and used as db_key in all subsequent calls
    // See db_service::read_kdbx
    // In desktop (and also in mobile?), this is the actual full file path
    pub(crate) database_file_name: String,

    pub(crate) file_key: Option<FileKey>,

    pub(crate) main_header: MainHeader,
    pub(crate) inner_header: InnerHeader,
    pub(crate) secured_database_keys: SecuredDatabaseKeys,

    // keepass_main_content is an Option type as it will be set to some value only after xml content extraction is completed
    pub(crate) keepass_main_content: Option<KeepassFile>,

    pub(crate) checksum_hash: Vec<u8>,
}

impl KdbxFile {
    // For now used in unit tests
    #[allow(unused)]
    #[cfg(test)]
    pub(crate) fn keepass_main_content(&self) -> &KeepassFile {
        // CAUTION: This unwrap may Panic
        self.keepass_main_content.as_ref().unwrap()
    }

    // For now used in unit tests
    #[allow(unused)]
    pub(crate) fn keepass_main_content_mut(&mut self) -> &mut KeepassFile {
        // CAUTION: This unwrap may Panic
        self.keepass_main_content.as_mut().unwrap()
    }

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
        debug!(
            "set_file_key is called with key_file_name: {:?}",
            &key_file_name
        );

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

        if let Some(k) = self.keepass_main_content.as_mut() {
            k.meta.master_key_changed = util::now_utc();
        }

        Ok(())
    }

    // Called when both password and key file are changed in settings
    pub fn set_credentials(
        &mut self,
        db_key: &str,
        password: Option<&str>,
        key_file_name: Option<&str>,
    ) -> Result<()> {
        debug!(
            "set_credentials is called with password nil?: {}, key_file_name: {:?}",
            password.is_none(),
            &key_file_name
        );

        self.file_key = FileKey::from(key_file_name)?;
        let mut keys = SecuredDatabaseKeys::from_keys(password, &self.file_key)?;
        keys.secure_keys(db_key)?;
        self.secured_database_keys = keys;

        if let Some(k) = self.keepass_main_content.as_mut() {
            k.meta.master_key_changed = util::now_utc();
        }

        Ok(())
    }

    pub fn set_password(&mut self, password: Option<&str>) -> Result<()> {
        debug!(
            "set_password called with password nil?: {}",
            password.is_none()
        );
        if let Some(k) = self.keepass_main_content.as_mut() {
            k.meta.master_key_changed = util::now_utc();
        }
        self.secured_database_keys
            .set_password(&self.database_file_name, password)
    }

    // Gets whether pasword or/and key file are used in master key or not
    pub fn credentials_used_state(&self) -> (bool, bool) {
        self.secured_database_keys.credentials_used_state()
    }

    pub fn set_database_file_name(&mut self, database_file_name: &str) -> &mut Self {
        self.database_file_name = database_file_name.into();
        self
    }

    // Gets the full file path in desktop app and may be in mobile app
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

    pub(crate) fn attachmentset(&self) -> &AttachmentSet {
        &self.inner_header.entry_attachments
    }

    pub(crate) fn insert_or_update_with_attachmentset(&mut self, other: &AttachmentSet) {
        self.inner_header
            .entry_attachments
            .insert_or_update_with_attachmentset(other);
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
        match other_kdf {
            KdfAlgorithm::Argon2d(ref _other) | KdfAlgorithm::Argon2id(ref _other) => {
                // The incoming other_kdf is expected to have all valid values in KdfAlgorithm::Argon2(crypto::kdf::Argon2Kdf)
                self.main_header.kdf_algorithm = other_kdf;
                Ok(())
            }

            _ => Err(Error::UnsupportedKdfAlgorithm(
                "Invalid Kdf algorithm is passed while updating in the setting".into(),
            )),
        }
    }

    pub(crate) fn checksum_hash(&self) -> &Vec<u8> {
        &self.checksum_hash
    }

    // Memory-security lock: serialize + encrypt the decrypted content
    // (`keepass_main_content`) AND the attachment byte blobs so only ciphertext
    // remains in RAM while locked, then wipe the plaintext. Returns the encrypted
    // blob to hold in the KdbxContext until unlock, or Ok(None) if no content loaded.
    //
    // The content tree and the attachment bytes are framed into one plaintext buffer
    // and encrypted together with the session enc key + a fresh nonce. The inner
    // header's attachment *index* maps are kept (needed to relink entries on unlock);
    // only the byte blobs are moved out and encrypted. `secured_database_keys` is
    // already encrypted in RAM and is left untouched (needed to save).
    pub(crate) fn lock_content(&mut self, db_key: &str) -> Result<Option<Vec<u8>>> {
        use zeroize::Zeroize;

        if let Some(mut kp) = self.keepass_main_content.take() {
            // None cipher: protected values are serialized as plaintext *inside* the
            // blob, which is then AES-GCM encrypted as a whole. Entries keep the
            // `index_ref` set at load, so write_xml emits correct Binary Refs.
            let mut xml_bytes = crate::xml_parse::write_xml(&kp, None)?;

            // Move attachment byte blobs out (index maps stay for relink on unlock).
            let mut attachments = self.inner_header.entry_attachments.take_attachment_bytes();

            let mut framed = frame_locked_content(&xml_bytes, &attachments);
            let blob = encrypt_content_blob(db_key, &framed)?;

            // Make the wipe real: volatile-zero every transient plaintext buffer and
            // the dropped object graph (Rust does not zero on drop).
            framed.zeroize();
            xml_bytes.zeroize();
            for (_h, data) in attachments.iter_mut() {
                data.zeroize();
            }
            kp.zeroize_sensitive_content();
            // `attachments` (zeroed) and `kp` (scrubbed) drop here;
            // keepass_main_content is already None via take().

            Ok(Some(blob))
        } else {
            Ok(None)
        }
    }

    // Reverse of `lock_content`: decrypt + unframe the blob, restore attachment bytes
    // and the parsed content, relinking attachment hashes from the preserved
    // inner-header index (mirrors the load path's `after_xml_reading`).
    pub(crate) fn unlock_content(&mut self, db_key: &str, blob: &[u8]) -> Result<()> {
        use zeroize::Zeroize;

        let mut framed = decrypt_content_blob(db_key, blob)?;
        let (mut xml_bytes, attachments) = unframe_locked_content(&framed)?;

        // Restore attachment bytes BEFORE parse/after_xml_reading so the ssh-agent
        // closure can read attachment content during relinking.
        self.inner_header
            .entry_attachments
            .restore_attachment_bytes(attachments);

        let mut kp = crate::xml_parse::parse(&xml_bytes, None)?;

        // Mirror reader_writer.rs read_xml_content post-parse linking.
        cfg_if::cfg_if! {
            if #[cfg(any(feature = "desktop-ssh-agent", rust_analyzer))] {
                kp.after_xml_reading(
                    self.inner_header
                        .entry_attachments
                        .attachments_index_ref_to_hash(),
                    &|data_hash| self.get_bytes_content(data_hash),
                );
            } else {
                kp.after_xml_reading(
                    self.inner_header
                        .entry_attachments
                        .attachments_index_ref_to_hash(),
                );
            }
        }

        self.keepass_main_content = Some(kp);

        // Wipe the transient plaintext buffers.
        xml_bytes.zeroize();
        framed.zeroize();
        Ok(())
    }
}

// Encrypts a locked-content blob with the database's existing per-session enc key
// (fetched from the OS key store), using AES-256/GCM with a FRESH random nonce and
// returning `nonce || ciphertext`. Reuses the enc key that already protects the
// composite key (no new DEK); the per-call random nonce avoids the fixed-nonce
// reuse of the composite-key path. The full KeyCipher nonce hardening remains a separate task for the composite-key path.
fn encrypt_content_blob(db_key: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let keydata = KeyStoreOperation::get_key(db_key).ok_or_else(|| {
        Error::UnexpectedError(format!(
            "No enc key available to encrypt locked content for db key {}",
            db_key
        ))
    })?;
    let keyinfo = SecureKeyInfo::from_key_nonce(keydata);
    let nonce = crypto::get_random_bytes::<12>();
    let kc = crypto::KeyCipher::from(&keyinfo.key, &nonce);
    let ciphertext = kc.encrypt(plaintext)?;

    let mut blob = nonce;
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

fn decrypt_content_blob(db_key: &str, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 12 {
        return Err(Error::UnexpectedError(
            "Locked content blob is too short to contain a nonce".into(),
        ));
    }
    let keydata = KeyStoreOperation::get_key(db_key).ok_or_else(|| {
        Error::UnexpectedError(format!(
            "No enc key available to decrypt locked content for db key {}",
            db_key
        ))
    })?;
    let keyinfo = SecureKeyInfo::from_key_nonce(keydata);
    let (nonce, ciphertext) = blob.split_at(12);
    let kc = crypto::KeyCipher::from(&keyinfo.key, nonce);
    kc.decrypt(ciphertext)
}

// Frames the content XML and the attachment byte blobs into a single plaintext
// buffer (all lengths are little-endian u64), to be encrypted as one blob:
//   [content_len][content_xml][count]( [hash][data_len][data] )*
fn frame_locked_content(
    content_xml: &[u8],
    attachments: &HashMap<AttachmentHashValue, Vec<u8>>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(content_xml.len() + 16);
    buf.extend_from_slice(&(content_xml.len() as u64).to_le_bytes());
    buf.extend_from_slice(content_xml);
    buf.extend_from_slice(&(attachments.len() as u64).to_le_bytes());
    for (hash, data) in attachments {
        buf.extend_from_slice(&hash.to_le_bytes());
        buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
        buf.extend_from_slice(data);
    }
    buf
}

fn unframe_locked_content(
    framed: &[u8],
) -> Result<(Vec<u8>, HashMap<AttachmentHashValue, Vec<u8>>)> {
    let corrupt = || Error::UnexpectedError("Corrupt locked content frame".into());

    let mut pos = 0usize;
    let read_u64 = |framed: &[u8], pos: &mut usize| -> Result<u64> {
        let end = pos.checked_add(8).ok_or_else(corrupt)?;
        let slice = framed.get(*pos..end).ok_or_else(corrupt)?;
        *pos = end;
        Ok(u64::from_le_bytes(slice.try_into().map_err(|_| corrupt())?))
    };
    let read_bytes = |framed: &[u8], pos: &mut usize, len: usize| -> Result<Vec<u8>> {
        let end = pos.checked_add(len).ok_or_else(corrupt)?;
        let slice = framed.get(*pos..end).ok_or_else(corrupt)?;
        *pos = end;
        Ok(slice.to_vec())
    };

    let content_len = read_u64(framed, &mut pos)? as usize;
    let content_xml = read_bytes(framed, &mut pos, content_len)?;

    let count = read_u64(framed, &mut pos)? as usize;
    let mut attachments = HashMap::with_capacity(count);
    for _ in 0..count {
        let hash = read_u64(framed, &mut pos)? as AttachmentHashValue;
        let data_len = read_u64(framed, &mut pos)? as usize;
        let data = read_bytes(framed, &mut pos, data_len)?;
        attachments.insert(hash, data);
    }

    Ok((content_xml, attachments))
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
        // variant dict version (little endian) expected [0 1] rather the high byte is critical
        // and the loading code should refuse to load the data if the high byte is too high
        let mut vd_ver = [0u8; 2];
        buf.read_exact(&mut vd_ver)?;
        // TODO: Verify the variant dict version here
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
                        if bytes_buf == constants::uuid::ARGON2_D_KDF {
                            kdf = KdfAlgorithm::Argon2d(crypto::kdf::Argon2Kdf::variant_2d());
                        } else if bytes_buf == constants::uuid::ARGON2_ID_KDF {
                            kdf = KdfAlgorithm::Argon2id(crypto::kdf::Argon2Kdf::variant_2id());
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

        match kdf {
            KdfAlgorithm::Argon2d(k) => {
                self.kdf_algorithm = KdfAlgorithm::Argon2d(self.update_argon2_with_vds(&vds, k));
                Ok(())
            }

            KdfAlgorithm::Argon2id(k) => {
                self.kdf_algorithm = KdfAlgorithm::Argon2id(self.update_argon2_with_vds(&vds, k));
                Ok(())
            }

            _ => Err(Error::SupportedOnlyArgon2dKdfAlgorithm),
        }
    }

    fn update_argon2_with_vds(
        &self,
        vds: &Vec<VariantDict>,
        argon2_kdf: crypto::kdf::Argon2Kdf,
    ) -> crypto::kdf::Argon2Kdf {
        let kf = vds.iter().fold(argon2_kdf, |mut acc, vd| {
            match vd {
                VariantDict::UINT64(name, val) if *name == "I".to_string() => acc.iterations = *val,
                VariantDict::UINT64(name, val) if *name == "M".to_string() => acc.memory = *val,
                VariantDict::UINT32(name, val) if *name == "P".to_string() => {
                    acc.parallelism = *val
                }
                VariantDict::UINT32(name, val) if *name == "V".to_string() => acc.version = *val,
                VariantDict::BYTEARRAY(name, val) if *name == "S".to_string() => {
                    acc.salt = val.clone()
                }
                _ => (),
            }
            acc
        });

        kf
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

        match &self.kdf_algorithm {
            // Both Argon2 variants have the same parameters
            KdfAlgorithm::Argon2d(kdf) | KdfAlgorithm::Argon2id(kdf) => {
                write(vd_type::BYTEARRAY, "$UUID", kdf.uuid_bytes())?;
                write(vd_type::UINT64, "I", &kdf.iterations.to_le_bytes())?;
                write(vd_type::UINT64, "M", &kdf.memory.to_le_bytes())?;
                write(vd_type::UINT32, "P", &kdf.parallelism.to_le_bytes())?;
                write(vd_type::BYTEARRAY, "S", &kdf.salt)?;
                write(vd_type::UINT32, "V", &kdf.version.to_le_bytes())?;
            }

            _ => {
                return Err(Error::UnsupportedKdfAlgorithm(format!(
                    "Found invalid KdfAlgorithm during writing"
                )));
            }
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

#[cfg(test)]
mod phase2_frame_tests {
    use super::*;

    #[test]
    fn frame_unframe_round_trip_with_attachments() {
        let content = b"<KeePassFile>...</KeePassFile>".to_vec();
        let mut attachments: HashMap<AttachmentHashValue, Vec<u8>> = HashMap::new();
        attachments.insert(11u64, vec![1, 2, 3, 4, 5]);
        attachments.insert(22u64, (0u8..200).collect());
        attachments.insert(33u64, vec![]); // empty attachment

        let framed = frame_locked_content(&content, &attachments);
        let (content_out, attachments_out) = unframe_locked_content(&framed).unwrap();

        assert_eq!(content, content_out);
        assert_eq!(attachments, attachments_out);
    }

    #[test]
    fn frame_unframe_round_trip_no_attachments() {
        let content = b"only-content".to_vec();
        let attachments: HashMap<AttachmentHashValue, Vec<u8>> = HashMap::new();
        let framed = frame_locked_content(&content, &attachments);
        let (content_out, attachments_out) = unframe_locked_content(&framed).unwrap();
        assert_eq!(content, content_out);
        assert!(attachments_out.is_empty());
    }

    #[test]
    fn unframe_rejects_truncated_frame() {
        let content = b"abc".to_vec();
        let mut attachments: HashMap<AttachmentHashValue, Vec<u8>> = HashMap::new();
        attachments.insert(1u64, vec![9, 9, 9]);
        let framed = frame_locked_content(&content, &attachments);
        // Truncating anywhere must be rejected, never panic.
        assert!(unframe_locked_content(&framed[..framed.len() - 1]).is_err());
        assert!(unframe_locked_content(&framed[..4]).is_err());
        assert!(unframe_locked_content(&[]).is_err());
    }
}
