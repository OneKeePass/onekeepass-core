use log::debug;
use serde::{Deserialize, Serialize};

use super::{
    kdbx_file::{InnerHeader, MainHeader},
    ContentCipherId, FileKey, KdbxFile, KdfAlgorithm, SecuredDatabaseKeys,
};
use crate::error::Result;
use crate::{
    constants::inner_header_type,
    crypto,
    db_content::{Group, KeepassFile},
};
use crate::{constants::GENERATOR_NAME, crypto::get_random_bytes_2};

#[derive(Serialize, Deserialize, Debug)]
pub struct NewDatabase {
    pub(crate) database_name: String,
    pub(crate) database_description: Option<String>,
    // This is the full uri and used as db_key
    pub database_file_name: String,
    // This is the just the file name part derived from the full uri (used in mobile)
    pub file_name: Option<String>,
    pub(crate) kdf: KdfAlgorithm,
    pub(crate) cipher_id: ContentCipherId,
    pub(crate) password: Option<String>,
    pub(crate) key_file_name: Option<String>,
}

impl Default for NewDatabase {
    fn default() -> Self {
        Self {
            database_name: "NewDatabase".into(),
            database_description: Some("New Database".into()),
            database_file_name: "NO_NAME".into(),
            file_name: None,
            kdf: KdfAlgorithm::Argon2(crypto::kdf::Argon2Kdf::default()),
            cipher_id: ContentCipherId::Aes256,
            password: Some("ss".into()),
            key_file_name: None,
        }
    }
}

impl NewDatabase {

    // Creates a blank database with some intial values. The database is not yet saved
    pub fn create(&self) -> Result<KdbxFile> {

        let file_key = match &self.key_file_name {
            Some(n) if !n.trim().is_empty() => Some(FileKey::open(&n)?),
            Some(_) | None => None,
        };

        let (cid, eiv) = self.cipher_id.uuid_with_iv()?;

        let (rn64, rn32) = get_random_bytes_2::<64, 32>();

        let mh = MainHeader {
            cipher_id: cid,
            master_seed: rn32,
            compression_flag: 1, // 0 => no compression
            encryption_iv: eiv,  //rng.get_bytes::<16>() for AES,rng.get_bytes::<12>() for CHACHA20
            public_custom_data: vec![],
            comment: vec![],
            unknown_data: (0, vec![]),
            kdf_algorithm: self.kdf.clone(),
        };

        let mut ih = InnerHeader::default();
        ih.stream_cipher_id = inner_header_type::CHACHA20_STREAM;
        ih.inner_stream_key = rn64;
        let mut kc = KeepassFile::new();
        kc.meta.generator = GENERATOR_NAME.into();
        kc.meta.database_name = self.database_name.clone();
        kc.meta.database_description = self
            .database_description
            .as_ref()
            .unwrap_or(&"New Database".into())
            .to_string();
        let mut root_g = Group::new_with_id();
        //root_g.uuid = uuid::Uuid::new_v4();
        root_g.name = kc.meta.database_name.clone();
        //kc.root.root_uuid = root_g.uuid.clone();
        kc.root.set_root_uuid(root_g.uuid);
        kc.root.insert_to_all_groups(root_g);

        debug!(
            "New database create: password nil? {}, file name {:?}",
            self.password.is_none(),
            &self.key_file_name
        );

        let mut secured_database_keys =
            SecuredDatabaseKeys::from_keys(self.password.as_deref(), &file_key)?;
        // Call to secure the keys and use in subsequent calls
        secured_database_keys.secure_keys(&self.database_file_name)?;

        let k = KdbxFile {
            database_file_name: self.database_file_name.clone(),
            file_key,
            main_header: mh,
            inner_header: ih,
            secured_database_keys,
            keepass_main_content: Some(kc),
            checksum_hash: vec![],
        };

        Ok(k)
    }
}
