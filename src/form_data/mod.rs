mod categories;
mod entry;
mod parsing;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    db::{ContentCipherId, KdfAlgorithm},
    db_content::Meta,
};

pub use self::categories::*;
pub use self::entry::*;

// Following way can be used in case we want to export types from 'entry' under some
// other module name.
// The calleer can use the following
// pub use crate::form_data::entry_form_data::{EntryFormData, EntrySummary, EntryTypeNames};
// pub mod entry_form_data {
//     pub use super::entry::*;
// }

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MetaFormData {
    pub(crate) database_name: String,
    pub(crate) database_description: String,
    pub(crate) history_max_items: i32,
    pub(crate) history_max_size: i32,
}

impl From<&Meta> for MetaFormData {
    fn from(meta: &Meta) -> Self {
        Self {
            database_name: meta.database_name.clone(),
            database_description: meta.database_description.clone(),
            history_max_items: meta.meta_share.history_max_items(),
            history_max_size: meta.meta_share.history_max_items(),
        }
    }
}

impl From<&MetaFormData> for Meta {
    fn from(form_data: &MetaFormData) -> Self {
        let mut meta = Meta::new();

        meta.database_name = form_data.database_name.clone();
        meta.database_description = form_data.database_description.clone();
        meta.meta_share
            .set_history_max_items(form_data.history_max_items);

        meta
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DbSettings {
    pub kdf: KdfAlgorithm,
    pub cipher_id: ContentCipherId,
    pub password: Option<String>,
    pub key_file_name: Option<String>,
    // Used for both reading and setting from UI side
    pub password_used: bool,
    pub key_file_used: bool,
    // Set when changed from the UI side
    pub password_changed: bool,
    pub key_file_changed: bool,

    // Just the file name component of the full key file name 'key_file_name'
    // Used in mobile mainly
    pub key_file_name_part: Option<String>,
    pub database_file_name: String,
    pub meta: MetaFormData,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct KdbxLoaded {
    // Full database uri
    pub db_key: String,
    // Just the database name
    pub database_name: String,
    // The file name part of full database uri
    pub file_name: Option<String>,
    // Full key file uri
    pub key_file_name: Option<String>,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct KdbxSaved {
    pub db_key: String,
    // This is the database name from the meta data of kdbx content
    pub database_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GroupSummary {
    pub uuid: Uuid,
    pub parent_group_uuid: Uuid,
    pub name: String,
    pub icon_id: i32,
    pub group_uuids: Vec<String>,
    pub entry_uuids: Vec<String>,
}
