use crate::constants::{custom_data_key::*, INTERNAL_VERSION};

use crate::util;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, str::FromStr};

#[derive(Debug, Default, Clone, Serialize, Deserialize,PartialEq)]
pub struct CustomData {
    items: HashMap<String, Item>,
    //pub(crate) items: Vec<Item>,
}

// Common custom data fns
// Mostly used in entry struct fns
impl CustomData {
    #[inline]
    pub fn get_item_value(&self, key: &str) -> Option<&str> {
        // &*x.value is the same as x.value.as_str()
        // x.value is String ; *x.value uses deref to get str and finally &str
        self.items.get(key).map(|x| &*x.value)
    }

    pub fn insert_item(&mut self, item: Item) -> &mut Self {
        self.items.insert(item.key.clone(), item);
        self
    }

    pub fn update_item_value(&mut self, key: &str, value: &str) -> &mut Self {
        self.remove_item(key);
        self.insert_item(Item::from_kv(key, value));
        self
    }

    // Returns the removed item or None
    pub fn remove_item(&mut self, key: &str) -> Option<Item> {
        self.items.remove(key)
    }

    fn _insert_items(&mut self, items: Vec<Item>) {
        // self.items.extend(items.iter().map( |i| (i.key.clone(),i.clone())) );
        // The above extend call based also will work
        for item in items {
            self.items.insert(item.key.clone(), item);
        }
    }

    pub fn get_items(&self) -> Vec<&Item> {
        self.items.values().collect()
    }

    fn _get(&self, key: &str) -> Option<&Item> {
        self.items.get(key)
    }
}

// All Meta related custom data
// TODO: Use Trait ?
impl CustomData {
    // Sets the internal version and overrides any previous version
    pub fn set_internal_version(&mut self, version: &str) {
        self.items.insert(
            OKP_INTERNAL_VERSION.to_string(),
            Item::from_kv(OKP_INTERNAL_VERSION, version),
        );
    }

    // Not yet used
    // Sets the internal version if not set previously
    fn _check_and_set_internal_version(&mut self, version: &str) {
        if self.get_item_value(OKP_INTERNAL_VERSION).is_none() {
            self.items.insert(
                OKP_INTERNAL_VERSION.to_string(),
                Item::from_kv(OKP_GROUP_AS_CATEGORY, version),
            );
        }
    }

    // Not yet used
    // Gets the version from custom data and returns the current FORMAT_VERSION if this is the first time
    fn _internal_version(&self) -> i32 {
        self.get_item_value(OKP_INTERNAL_VERSION).map_or_else(
            || INTERNAL_VERSION,
            |s| i32::from_str(s).unwrap_or(INTERNAL_VERSION),
        )
    }
}

// All Group related custom data
// TODO: Use Trait
impl CustomData {
    // pub fn mark_as_category(&mut self) {
    //     self.items.insert(
    //         OKP_GROUP_AS_CATEGORY.to_string(),
    //         Item {
    //             key: OKP_GROUP_AS_CATEGORY.to_string(),
    //             value: "Yes".to_string(),
    //             last_modification_time: Some(util::now_utc()),
    //         },
    //     );
    // }

    pub fn unmark_as_category(&mut self) {
        self.items.insert(
            OKP_GROUP_AS_CATEGORY.to_string(),
            Item {
                key: OKP_GROUP_AS_CATEGORY.to_string(),
                value: "No".to_string(),
                last_modification_time: Some(util::now_utc()),
            },
        );
    }

    pub fn remove_category_marking(&mut self) {
        self.items.remove(OKP_GROUP_AS_CATEGORY);
    }

    // pub fn is_category(&self) -> bool {
    //     self.items.contains_key(OKP_GROUP_AS_CATEGORY)
    // }

    /// A group is considered category when we do not find the custom data OKP_GROUP_AS_CATEGORY or
    /// when the value is No. So the default behaviour is, all groups are considered as categories except those
    /// that have OKP_GROUP_AS_CATEGORY entry with value "No"
    pub fn is_category(&self) -> bool {
        self.items
            .get(OKP_GROUP_AS_CATEGORY)
            .map_or(true, |v| v.value == "No")
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize,PartialEq)]
pub struct Item {
    pub(crate) key: String,
    pub(crate) value: String,
    pub(crate) last_modification_time: Option<NaiveDateTime>,
}

impl Item {
    pub fn from_kv(key: &str, value: &str) -> Self {
        Self {
            key: key.to_string(),
            value: value.to_string(),
            last_modification_time: None,
        }
    }
}
