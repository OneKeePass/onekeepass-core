mod custom_data;
mod entry;
mod entry_type;
mod group;
mod keepass;
mod meta;
mod root;
mod standard_entry_types;

pub(crate) use self::custom_data::{CustomData, Item};
pub use self::entry::{BinaryKeyValue, Entry, EntryField, History, KeyValue};
pub use self::entry_type::{EntryType, FieldDataType, FieldDef, Section};
pub use self::group::Group;
pub use self::keepass::KeepassFile;
pub use self::meta::Meta;

pub use self::root::{join_tags, split_tags, AllTags, GroupVisitor, Root};
pub use self::standard_entry_types::{
    standard_type_uuids_names_ordered_by_id, standard_types_ordered_by_id,
};

use chrono::NaiveDateTime;

use serde::{Deserialize, Serialize};
use uuid::Uuid; //info, warn

use crate::util;

pub type AttachmentHashValue = u64;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryProtection {
    pub(crate) protect_title: bool,
    pub(crate) protect_notes: bool,
    pub(crate) protect_url: bool,
    pub(crate) protect_username: bool,
    pub(crate) protect_password: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CustomIcons {
    pub(crate) icons: Vec<Icon>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Icon {
    pub(crate) uuid: Uuid,
    pub(crate) data: Vec<u8>,
    pub(crate) name: Option<String>, //KDBX 4.1
}

// Used to verify a given entry or group uuid is set to valid value and also it is
// a key either in all_groups or all_entries map
macro_rules! verify_uuid {
    ($self:ident, $uuid:expr, $collection_name:tt) => {
        if $uuid == uuid::Uuid::default() {
            let msg = format!("Uuid {} is not valid", $uuid);
            return Err(Error::NotFound(msg));
        }

        if !$self.$collection_name.contains_key(&$uuid) {
            let msg = format!(
                "Uuid {} is not found in {} map",
                $uuid,
                stringify!($collection_name)
            );
            return Err(Error::NotFound(msg));
        }
    };
}
pub(crate) use verify_uuid;

macro_rules! move_to_recycle_bin {
    ($self:ident,$call_method:tt,$uuid:expr ) => {{
        let parent_id = $self
            .recycle_bin_group()
            .ok_or("No recycle bin group")?
            .uuid;
        $self.$call_method($uuid, parent_id)?;
        Ok(())
    }};
}

pub(crate) use move_to_recycle_bin;

// NaiveDateTime is ISO 8601 combined date and time without timezone.
// All times of db are formed from util::now_utc() or UTC time string from UI
// and thus in UTC timezone and represented as NaiveDateTime.
// NaiveDateTime just has year,month,day,hour,minute,second and milliseconds
// The UI side is responbile to know the timezone and convert the NaiveDateTime accordingly to display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Times {
    pub(crate) last_modification_time: NaiveDateTime,
    pub(crate) creation_time: NaiveDateTime,
    pub(crate) last_access_time: NaiveDateTime,
    pub(crate) expires: bool,
    pub(crate) expiry_time: NaiveDateTime,
    // This is not written back to xml. Not sure at this time how this is used
    pub(crate) location_changed: NaiveDateTime,
    pub(crate) usage_count: i32,
}

impl Times {
    pub fn new() -> Self {
        let n = util::now_utc();
        Times {
            last_modification_time: n,
            creation_time: n,
            last_access_time: n,
            expires: false,
            expiry_time: n,      //TODO: Need to determine the default expiry time
            location_changed: n, //Should it be Option type ?
            usage_count: i32::default(),
        }
    }
}
