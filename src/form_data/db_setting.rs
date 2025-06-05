use serde::{Deserialize, Serialize};

use crate::db::{ContentCipherId, KdfAlgorithm};

use super::MetaFormData;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DbSettings {
    pub(crate) kdf: KdfAlgorithm,
    pub(crate) cipher_id: ContentCipherId,
    pub(crate) password: Option<String>,
    pub(crate) key_file_name: Option<String>,
    // Used for both reading and setting from UI side
    pub(crate) password_used: bool,
    pub(crate) key_file_used: bool,
    // Set when changed from the UI side
    pub(crate) password_changed: bool,
    pub(crate) key_file_changed: bool,

    // Just the file name component of the full key file name 'key_file_name'
    // Used in mobile mainly
    pub(crate) key_file_name_part: Option<String>,
    pub(crate) database_file_name: String,
    pub(crate) meta: MetaFormData,
}

// Used in integration test
// #[allow(unused)]
impl DbSettings {
    pub fn get_database_name(&self) -> &str {
        &self.meta.database_name
    }

    pub fn set_database_name(&mut self, name: &str) -> &mut Self {
        self.meta.database_name = name.into();
        self
    }
}

// Used in integration test
// #[allow(unused)]
// impl MetaFormData {
//     pub fn get_database_name(&self) -> &str {
//         &self.database_name
//     }

//     pub fn set_database_name(&mut self, name: &str) -> &mut Self {
//         self.database_name = name.into();
//         self
//     }
// }
