mod custom_data;
mod entry;
mod entry_type;
mod group;
mod keepass;
mod meta;
mod otp;
mod root;
mod standard_entry_types;

pub(crate) use self::custom_data::{CustomData, Item};
pub(crate) use self::otp::OtpData;

pub use self::entry::{
    Association, AutoType, BinaryKeyValue, Entry, EntryField, History, KeyValue,
};
pub use self::entry_type::{EntryType, FieldDataType, FieldDef, Section};
pub use self::group::Group;
pub use self::keepass::KeepassFile;
pub use self::meta::Meta;
pub use self::otp::{CurrentOtpTokenData, OtpAlgorithm, OtpSettings};

pub(crate) use self::root::DeletedObject;
pub use self::root::{AllTags, EntryCloneOption, GroupSortCriteria, Root};
pub use self::standard_entry_types::{
    standard_type_uuid_by_name, standard_type_uuids_names_ordered_by_id,
    standard_types_ordered_by_id,
};

use chrono::NaiveDateTime;

use serde::{Deserialize, Serialize};
use uuid::Uuid; //info, warn

use crate::util;

pub type AttachmentHashValue = u64;

const TAGS_SEPARATORS: [char; 2] = [';', ','];

// Splits tags string into vector of tags
pub fn split_tags(tags: &str) -> Vec<String> {
    let splits = tags.split(&TAGS_SEPARATORS[..]);
    splits
        .filter(|w| !w.is_empty())
        .map(|w| w.trim().into())
        .collect::<Vec<String>>()
}

pub fn join_tags(tag_vec: &Vec<String>) -> String {
    tag_vec.join(";")
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MemoryProtection {
    pub(crate) protect_title: bool,
    pub(crate) protect_notes: bool,
    pub(crate) protect_url: bool,
    pub(crate) protect_username: bool,
    pub(crate) protect_password: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CustomIcons {
    pub(crate) icons: Vec<Icon>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Icon {
    pub(crate) uuid: Uuid,
    pub(crate) data: Vec<u8>,
    pub(crate) name: Option<String>, //KDBX 4.1
    pub(crate) last_modification_time: NaiveDateTime,
}

// Called to verify a given entry's or group's uuid is a valid value (i.e not default one) and this
// uuid is found either in all_groups or all_entries map
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct Times {
    // The modification time is changed whenever an entry or a group fileds are changed
    // KeepassXC changes modification time of group/entry and its parent group when an entry or group is moved in addition to
    // location_changed
    pub(crate) last_modification_time: NaiveDateTime,

    // Only when an entry or group is first time created
    pub(crate) creation_time: NaiveDateTime,

    // KeePass changes access time when an entry or group is moved
    // in addition to location_changed
    // KeePass may also change access time when an entry or group is accessed (check this?)
    pub(crate) last_access_time: NaiveDateTime,

    pub(crate) expires: bool,
    pub(crate) expiry_time: NaiveDateTime,

    // location_changed was not used in earlier versions.
    // Only in v0.18.0 both reading and writing added. This datetime is updated
    // whenever an entry or a group is moved one parent group to another parent group
    // This helps while merging two databases
    pub(crate) location_changed: NaiveDateTime,

    pub(crate) usage_count: i32,
}

impl Times {
    pub(crate) fn new() -> Self {
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

    pub(crate) fn update_modification_time_now(&mut self) {
        let n = util::now_utc();
        self.last_modification_time = n;
        self.last_access_time = n;
    }

    pub(crate) fn update_modification_time(&mut self, modification_time: NaiveDateTime) {
        self.last_modification_time = modification_time;
        self.last_access_time = modification_time;
    }
}
