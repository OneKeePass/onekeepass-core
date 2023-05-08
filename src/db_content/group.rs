use crate::db_content::{CustomData, Times};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub(crate) uuid: Uuid,
    //TODO: Should we add parent group uuid as it is done for Entry?
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
    //Only the child group uuids are kept here and used to do lookup in 'root.all_groups'
    #[serde(default)]
    pub(crate) group_uuids: Vec<Uuid>,
    //Only the child entry uuids are kept here and used to do lookup in 'root.all_entries'
    #[serde(default)]
    pub(crate) entry_uuids: Vec<Uuid>,
}

impl Group {
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
            last_top_visible_group: Uuid::default(),
            marked_category: true,
            group_uuids: vec![],
            entry_uuids: vec![],
        }
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
