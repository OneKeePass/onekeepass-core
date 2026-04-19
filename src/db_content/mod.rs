mod cross_db_move;
mod custom_data;
mod entry;
mod entry_type;
mod group;
mod keepass;
mod meta;
mod otp;
mod root;
mod standard_entry_types;

pub(crate) use self::cross_db_move::{
    clone_entry_to_other_db, move_entry_between_keepass_files, move_group_between_keepass_files,
    CrossDbMoveResult,
};

pub(crate) use self::custom_data::{CustomData, Item};
pub(crate) use self::otp::OtpData;
pub(crate) use self::keepass::KeepassFile;
pub(crate) use self::meta::Meta;
pub(crate) use self::root::Root;
pub(crate) use self::root::DeletedObject;


pub use self::entry::{
    Association, AutoType, BinaryKeyValue, Entry, EntryField, History, KeyValue,
};

pub use self::entry_type::{EntryType, FieldDataType, FieldDef, Section};
pub use self::group::Group;

pub use self::otp::{CurrentOtpTokenData, OtpAlgorithm, OtpSettings};

pub use self::root::{AllTags, EntryCloneOption, GroupSortCriteria, };

pub use self::standard_entry_types::{
    standard_type_uuid_by_name, standard_type_uuids_names_ordered_by_id,
    standard_types_ordered_by_id,
};

pub type AttachmentHashValue = u64;

use chrono::NaiveDateTime;

use serde::{Deserialize, Serialize};
use uuid::Uuid; //info, warn

use crate::util;

const TAGS_SEPARATORS: [char; 2] = [';', ','];

// Splits tags string into vector of tags
pub(crate) fn split_tags(tags: &str) -> Vec<String> {
    let splits = tags.split(&TAGS_SEPARATORS[..]);
    splits
        .filter(|w| !w.is_empty())
        .map(|w| w.trim().into())
        .collect::<Vec<String>>()
}

pub(crate) fn join_tags(tag_vec: &Vec<String>) -> String {
    tag_vec.join(";")
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub(crate) struct MemoryProtection {
    pub(crate) protect_title: bool,
    pub(crate) protect_notes: bool,
    pub(crate) protect_url: bool,
    pub(crate) protect_username: bool,
    pub(crate) protect_password: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub(crate) struct CustomIcons {
    pub(crate) icons: Vec<Icon>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub(crate) struct Icon {
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

#[cfg(test)]
mod tests {
    use super::{join_tags, split_tags, Times};

    #[test]
    fn split_tags_semicolon_separated() {
        let result = split_tags("Work;Personal;Finance");
        assert_eq!(result, vec!["Work", "Personal", "Finance"]);
    }

    #[test]
    fn split_tags_comma_separated() {
        let result = split_tags("Work,Personal,Finance");
        assert_eq!(result, vec!["Work", "Personal", "Finance"]);
    }

    #[test]
    fn split_tags_mixed_separators() {
        let result = split_tags("Work;Personal,Finance");
        assert_eq!(result, vec!["Work", "Personal", "Finance"]);
    }

    #[test]
    fn split_tags_empty_string() {
        let result = split_tags("");
        assert!(result.is_empty());
    }

    #[test]
    fn split_tags_whitespace_trimmed() {
        let result = split_tags("Work; Personal ; Finance");
        assert_eq!(result, vec!["Work", "Personal", "Finance"]);
    }

    #[test]
    fn split_tags_trailing_separator() {
        let result = split_tags("Work;Personal;");
        assert_eq!(result, vec!["Work", "Personal"]);
    }

    #[test]
    fn join_tags_multiple() {
        let tags = vec!["Work".to_string(), "Personal".to_string(), "Finance".to_string()];
        assert_eq!(join_tags(&tags), "Work;Personal;Finance");
    }

    #[test]
    fn join_tags_empty_vec() {
        let tags: Vec<String> = vec![];
        assert_eq!(join_tags(&tags), "");
    }

    #[test]
    fn join_tags_single() {
        let tags = vec!["Work".to_string()];
        assert_eq!(join_tags(&tags), "Work");
    }

    #[test]
    fn split_join_roundtrip() {
        let original = "Alpha;Beta;Gamma";
        let split = split_tags(original);
        let joined = join_tags(&split);
        assert_eq!(joined, original);
    }

    #[test]
    fn times_new_expires_is_false() {
        let t = Times::new();
        assert!(!t.expires);
    }

    #[test]
    fn times_new_usage_count_is_zero() {
        let t = Times::new();
        assert_eq!(t.usage_count, 0);
    }

    #[test]
    fn times_new_timestamps_are_equal() {
        let t = Times::new();
        // creation, modification and access should all be set to the same instant
        assert_eq!(t.creation_time, t.last_modification_time);
        assert_eq!(t.creation_time, t.last_access_time);
    }

    #[test]
    fn times_update_modification_changes_times() {
        use crate::util::test_clock;
        test_clock::init_datetime(2024, 1, 1, 0, 0, 0);
        let mut t = Times::new();
        let original = t.last_modification_time;

        test_clock::advance_by(60);
        t.update_modification_time_now();

        assert!(t.last_modification_time > original);
        assert_eq!(t.last_modification_time, t.last_access_time);
        // creation_time must not change
        assert_eq!(t.creation_time, original);
    }

    #[test]
    fn times_update_modification_explicit() {
        use chrono::NaiveDate;
        let fixed = NaiveDate::from_ymd_opt(2023, 6, 15)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap();
        let mut t = Times::new();
        t.update_modification_time(fixed);
        assert_eq!(t.last_modification_time, fixed);
        assert_eq!(t.last_access_time, fixed);
    }
}

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
