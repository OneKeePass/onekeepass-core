use crate::{
    db_content::{CustomData, Times},
    util,
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub(crate) uuid: Uuid,
    // TODO: Should we add parent group uuid as it is done for Entry?
    pub parent_group_uuid: Uuid,
    pub name: String,
    #[serde(default)]
    pub icon_id: i32,
    pub notes: String,
    pub tags: String,
    #[serde(default)]
    pub(crate) is_expanded: bool,
    #[serde(default = "Times::new")]
    pub(crate) times: Times,
    #[serde(skip)]
    pub custom_data: CustomData,
    #[serde(skip)]
    pub(crate) last_top_visible_group: Uuid,
    pub(crate) marked_category: bool,

    pub(crate) default_auto_type_sequence: Option<String>,
    pub(crate) enable_auto_type: Option<bool>,

    pub(crate) custom_icon_uuid: Option<Uuid>,

    // Only the child group uuids are kept here and used to do lookup in 'root.all_groups'
    #[serde(default)]
    pub(crate) group_uuids: Vec<Uuid>,
    // Only the child entry uuids are kept here and used to do lookup in 'root.all_entries'
    #[serde(default)]
    pub(crate) entry_uuids: Vec<Uuid>,
}

// Mainly used for testing at this time
impl Group {
    pub fn name(&self) -> &String {
        &self.name
    }

    pub fn set_name(&mut self, name: &str) -> &mut Self {
        self.name = name.to_string();
        self
    }

    pub fn notes(&self) -> &String {
        &self.notes
    }

    pub fn set_notes(&mut self, notes: &str) -> &mut Self {
        self.notes = notes.to_string();
        self
    }

    pub fn set_icon_id(&mut self, icon_id: i32) -> &mut Self {
        self.icon_id = icon_id;
        self
    }

    pub fn update_modification_time(&mut self) -> &mut Self {
        self.times.update_modification_time();
        self
    }
}

impl Group {
    // Creates a new group without uuid
    pub fn new() -> Self {
        Group {
            uuid: Uuid::default(),
            parent_group_uuid: Uuid::default(),
            name: String::default(),
            icon_id: 48, //i32::default(), folder icon
            tags: String::default(),
            notes: String::default(),
            is_expanded: false,
            times: Times::new(),
            custom_data: CustomData::default(),
            custom_icon_uuid: None,
            last_top_visible_group: Uuid::default(),
            marked_category: true,

            // Not sure these are used by keepass at all and it looks like mostly used whatever set in entries
            // None means inherit from parent settings for all entries
            // False if auto type is disabled for entries for this group
            // True if auto type is enabled for entries for this group
            enable_auto_type: None,
            default_auto_type_sequence: None,

            group_uuids: vec![],
            entry_uuids: vec![],
        }
    }

    // Creates a new group with uuid set
    pub fn new_with_id() -> Self {
        let mut g = Group::new();
        g.uuid = Uuid::new_v4();
        g
    }

    pub fn with_parent(group_uuid: &Uuid) -> Self {
        let mut g = Group::new_with_id();
        g.parent_group_uuid = *group_uuid;
        g
    }

    pub(crate) fn get_uuid(&self) -> &Uuid {
        &self.uuid
    }

    pub(crate) fn parent_group_uuid(&self) -> &Uuid {
        &self.parent_group_uuid
    }

    pub fn sub_group_uuids(&self) -> &Vec<Uuid> {
        &self.group_uuids
    }

    pub fn entry_uuids(&self) -> &Vec<Uuid> {
        &self.entry_uuids
    }

    pub fn custom_data_to_group(&mut self) {
        self.marked_category = self.custom_data.is_category();
    }

    // pub fn group_to_custom_data(&mut self) {
    //     if self.marked_category {
    //         // Update the mark category custom data only if is not already set
    //         // to maintain the proper last_modification_time of this custom data
    //         if !self.custom_data.is_category() {
    //             self.custom_data.mark_as_category();
    //         }
    //     } else {
    //         // Remove any previous setting when marked_category is false
    //         self.custom_data.remove_category_marking();
    //     }
    // }

    // Called to set the group's custom data field values
    pub fn group_to_custom_data(&mut self) {
        if self.marked_category {
            // Remove any previous setting when marked_category is true
            self.custom_data.remove_category_marking();
        } else {
            // Update the mark category custom data only if is not already set
            // to maintain the proper last_modification_time of this custom data
            if self.custom_data.is_category() {
                self.custom_data.unmark_as_category();
            }
        }
    }

    pub fn mark_as_category(&mut self) {
        self.marked_category = true;
    }

    pub fn is_in_category(&self) -> bool {
        self.marked_category
    }

    pub fn visitor_action(&mut self) {
        println!("name is {}", self.name);
    }
}
