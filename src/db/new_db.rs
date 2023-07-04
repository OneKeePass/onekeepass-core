use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::{crypto, constants::inner_header_type, db_content::{KeepassFile, Group}};
use super::{KdfAlgorithm, ContentCipherId, KdbxFile, FileKey, kdbx_file::{MainHeader, InnerHeader}, SecuredDatabaseKeys};

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
            file_name:None,
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


        let mut secured_database_keys = SecuredDatabaseKeys::from_keys(&self.password, &file_key)?;
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
