use crate::db_content::{standard_type_uuids_names_ordered_by_id, Entry, KeepassFile, Meta};

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::GroupSummary;

#[derive(Serialize, Deserialize, Debug)]
pub struct GroupTree {
    //pub root_uuid: String,
    pub root_uuid: Uuid,
    pub recycle_bin_uuid: Uuid,
    pub deleted_group_uuids: Vec<Uuid>,
    pub groups: HashMap<String, GroupSummary>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CategoryDetail {
    pub title: String,
    pub display_title: Option<String>,
    pub entries_count: usize,
    pub groups_count: usize,
    pub icon_id: i32,
    pub icon_name: Option<String>,
    pub entry_type_uuid: Option<Uuid>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GroupCategory {
    pub uuid: String,
    pub category_detail: CategoryDetail,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EntryCategoryInfo {
    pub general_categories: Vec<CategoryDetail>,
    pub group_categories: Vec<GroupCategory>,
    pub type_categories: Vec<CategoryDetail>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EntryCategory {
    AllEntries,
    Favorites,
    Deleted,
    // Deserilaizes as {"group","someuuid"} - in cljs {:group "someuuid"}
    Group(String),
    // Deserilaizes as  {"entryTypeUuid", "someuuid"} - in cljs {:entry-type-uuid "someuuid"}
    EntryTypeUuid(Uuid), //
}

impl EntryCategory {
    
    fn as_title_key(&self) -> (String, Option<String>) {
        match self {
            EntryCategory::AllEntries => ("AllEntries".into(), Some("All Entries".into())),
            EntryCategory::Favorites => ("Favorites".into(), None),
            EntryCategory::Deleted => ("Deleted".into(), None),
            _ => ("NotSupported".into(), None),
        }
    }
}

// Called to get all entries for any given entry category
pub(crate) fn entry_by_category<'a>(
    kp: &'a KeepassFile,
    entry_category: &'a EntryCategory,
) -> Vec<&'a Entry> {
    let mut entries: Vec<&Entry> = vec![];
    match entry_category {
        EntryCategory::AllEntries => kp.collect_all_active_entries(),
        EntryCategory::Favorites => kp.collect_favorite_entries(),
        EntryCategory::Deleted => kp.root.deleted_entries(),
        EntryCategory::Group(uuid) => {
            if let Ok(group_uuid) = Uuid::parse_str(uuid) {
                if let Some(g) = kp.root.all_groups.get(&group_uuid) {
                    for entry_uuid in &g.entry_uuids {
                        if let Some(e) = kp.root.entry_by_id(&entry_uuid) {
                            entries.push(e);
                        }
                    }
                }
            }
            //All entries that are under this group
            entries
        }
        EntryCategory::EntryTypeUuid(uuid) => kp
            .collect_all_active_entries()
            .iter()
            .filter(|e| &e.entry_field.entry_type.uuid == uuid)
            .map(|e| *e)
            .collect::<Vec<_>>(),
    }
}

// Called in 'categories_to_show' fn to get EnteryCategoryInfo from KeePassFile 
impl From<&KeepassFile> for EntryCategoryInfo {
    fn from(k: &KeepassFile) -> Self {
        let all = k.collect_all_active_entries();

        let (title, display_title) = EntryCategory::AllEntries.as_title_key();
        let all_entries = CategoryDetail {
            title,
            display_title,
            entries_count: all.len(), //k.get_all_entries(true).len(),
            groups_count: 0,
            icon_id: 0,
            icon_name: None,
            entry_type_uuid: None,
        };

        let (title, display_title) = EntryCategory::Favorites.as_title_key();
        let favorite_entries = CategoryDetail {
            title,
            display_title,
            entries_count: k.collect_favorite_entries().len(), //k.get_all_entries(true).len(),
            groups_count: 0,
            icon_id: 0,
            icon_name: None,
            entry_type_uuid: None,
        };

        let (title, display_title) = EntryCategory::Deleted.as_title_key();
        let deleted = CategoryDetail {
            title,
            display_title,
            entries_count: k.root.deleted_entries().len(),
            groups_count: 0,
            icon_id: 0,
            icon_name: None,
            entry_type_uuid: None,
        };

        //Group category details
        let mut group_categories: Vec<GroupCategory> = vec![];

        // By calling get_all_groups with true we are excluding recycle bin group from category
        for group in k.root.get_all_groups(true) {
            if group.is_in_category() {
                group_categories.push(GroupCategory {
                    uuid: group.uuid.to_string(),
                    category_detail: CategoryDetail {
                        title: group.name.clone(),
                        display_title: None,
                        entries_count: group.entry_uuids.len(),
                        groups_count: group.group_uuids.len(),
                        icon_id: group.icon_id,
                        icon_name: None,
                        entry_type_uuid: None,
                    },
                })
            }
        }
        // A simple sort by title of these group_categories
        group_categories.sort_by(|a, b| a.category_detail.title.cmp(&b.category_detail.title));

        // All entry type name based categories
        let mut type_categories: Vec<CategoryDetail> =
            type_name_categories(&all, &standard_type_uuids_names_ordered_by_id(), None);

        type_categories.append(&mut type_name_categories(
            &all,
            &k.meta.custom_entry_type_names_by_id(),
            Some(&k.meta),
        ));

        EntryCategoryInfo {
            general_categories: vec![all_entries, favorite_entries, deleted],
            group_categories,
            // For now we send both Standard and Custom entry type names in one list
            type_categories,
        }
    }
}

pub fn tag_categories() {
    
}

fn type_name_categories(
    entries: &Vec<&Entry>,
    type_names: &Vec<(Uuid, String)>,
    meta_opt: Option<&Meta>,
) -> Vec<CategoryDetail> {
    let mut cats: Vec<CategoryDetail> = vec![];
    for (uuid, name) in type_names {
        let cnt = entries
            .iter()
            .filter(|e| &e.entry_field.entry_type.uuid == uuid)
            .count();
        cats.push(CategoryDetail {
            title: name.clone(),
            display_title: None,
            entries_count: cnt,
            groups_count: 0,
            icon_id: 0,
            // Need to get the icon name from EntryType struct - mostly for Custom Entry Types
            icon_name: if let Some(meta) = meta_opt {
                meta.get_custom_entry_type_by_id(&uuid)
                    .map_or(None, |e| e.icon_name)
            } else {
                None
            },
            entry_type_uuid: Some(uuid.clone()),
        })
    }
    cats
}
