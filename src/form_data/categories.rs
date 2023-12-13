use crate::db_content::{
    split_tags, standard_type_uuids_names_ordered_by_id, Entry, KeepassFile, Meta,
};

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::GroupSummary;

use crate::constants::general_category_names::{ALL_ENTRIES,DELETED,FAVORITES};

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
    // Used in case of Entry type based grouping
    pub entry_type_uuid: Option<Uuid>,
    // In case of group tree or group category this is used
    pub group_uuid: Option<Uuid>,
    // Used when tag based grouping is used
    pub tag_id:Option<String>,

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

#[derive(Serialize, Deserialize, Debug,Clone)]
pub enum EntryCategoryGrouping {
    AsGroupCategories,
    AsTypes,
    AsTags,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EntryCategories {
    pub general_categories: Vec<CategoryDetail>,
    pub grouping_kind: EntryCategoryGrouping,
    pub grouped_categories: Vec<CategoryDetail>,
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
    Tag(String),
}

impl EntryCategory {
    fn as_title_key(&self) -> (String, Option<String>) {
        match self {
            EntryCategory::AllEntries => (ALL_ENTRIES.into(), Some(ALL_ENTRIES.into())),
            EntryCategory::Favorites => (FAVORITES.into(), None),
            EntryCategory::Deleted => (DELETED.into(), None),
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

        EntryCategory::Tag(name) => kp
            .collect_all_active_entries()
            .iter()
            .filter(|e| split_tags(&e.tags).contains(&name))
            .map(|e| *e)
            .collect::<Vec<_>>(),
    }
}

// Deprecate
// Need to deprecated once we use 'combined_category_details' in all cases
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
            group_uuid: None,
            tag_id:None,
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
            group_uuid: None,
            tag_id:None,
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
            group_uuid: None,
            tag_id:None,
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
                        group_uuid: None,
                        tag_id:None,
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
            group_uuid: None,
            tag_id:None,
        })
    }
    cats
}

fn general_category_details(keepass_file: &KeepassFile) -> Vec<CategoryDetail> {
    let all = keepass_file.collect_all_active_entries();
    
    //debug!("Loading all cat data with entries count {}", all.len());
    
    let (title, display_title) = EntryCategory::AllEntries.as_title_key();
    let all_entries = CategoryDetail {
        title,
        display_title,
        entries_count: all.len(), //k.get_all_entries(true).len(),
        groups_count: 0,
        icon_id: 0,
        icon_name: None,
        entry_type_uuid: None,
        group_uuid: None,
        tag_id:None,
    };

    let (title, display_title) = EntryCategory::Favorites.as_title_key();
    let favorite_entries = CategoryDetail {
        title,
        display_title,
        entries_count: keepass_file.collect_favorite_entries().len(), //k.get_all_entries(true).len(),
        groups_count: 0,
        icon_id: 0,
        icon_name: None,
        entry_type_uuid: None,
        group_uuid: None,
        tag_id:None,
    };

    let (title, display_title) = EntryCategory::Deleted.as_title_key();
    let deleted = CategoryDetail {
        title,
        display_title,
        entries_count: keepass_file.root.deleted_entries().len(),
        groups_count: 0,
        icon_id: 0,
        icon_name: None,
        entry_type_uuid: None,
        group_uuid: None,
        tag_id:None,
    };

    vec![all_entries, favorite_entries, deleted]
}

fn group_category_details(keepass_file: &KeepassFile) -> Vec<CategoryDetail> {
    let mut group_categories: Vec<CategoryDetail> = vec![];

    // By calling get_all_groups with true we are excluding recycle bin group from category
    for group in keepass_file.root.get_all_groups(true) {
        if group.is_in_category() {
            group_categories.push(CategoryDetail {
                title: group.name.clone(),
                display_title: None,
                entries_count: group.entry_uuids.len(),
                groups_count: group.group_uuids.len(),
                icon_id: group.icon_id,
                icon_name: None,
                entry_type_uuid: None,
                group_uuid: Some(group.uuid.clone()),
                tag_id:None,
            })
        }
    }
    // A simple sort by title of these group_categories
    group_categories.sort_by(|a, b| a.title.cmp(&b.title));

    group_categories
}

fn type_category_details(keepass_file: &KeepassFile) -> Vec<CategoryDetail> {
    let all = keepass_file.collect_all_active_entries();

    let mut type_categories: Vec<CategoryDetail> =
        type_name_categories(&all, &standard_type_uuids_names_ordered_by_id(), None);

    type_categories.append(&mut type_name_categories(
        &all,
        &keepass_file.meta.custom_entry_type_names_by_id(),
        Some(&keepass_file.meta),
    ));

    type_categories
}

fn tag_category_details(keepass_file: &KeepassFile) -> Vec<CategoryDetail> {
    let vals = keepass_file.collect_all_active_entries().iter().fold(
        HashMap::<String, CategoryDetail>::default(),
        |mut acc, e| {
            for t in split_tags(&e.tags) {
                // Exclude the standard Favorites tag
                if t == FAVORITES {
                    continue;
                }
                if let Some(c) = acc.get_mut(&t) {
                    c.entries_count = c.entries_count + 1;
                    //acc.insert(t, c + 1);
                } else {
                    let d = CategoryDetail {
                        // Tag value  is used for both title and tag_id
                        title: t.clone(),
                        display_title: None,
                        entries_count: 1,
                        groups_count: 0,
                        icon_id: 0,
                        icon_name: None,
                        entry_type_uuid: None,
                        group_uuid: None,
                        tag_id:Some(t.clone()),
                    };
                    acc.insert(t, d);
                }
            }
            acc
        },
    );

    // into_values() consumes the map visiting all the values in arbitrary order
    // Need to do required sorting on the UI side
    vals.into_values().collect()
}

// Gets all general category details and a grouped category details for 
// the given grouping_kind
pub fn combined_category_details(
    keepass_file: &KeepassFile,
    grouping_kind: EntryCategoryGrouping,
) -> EntryCategories {
    let general_categories = general_category_details(keepass_file);

    let grouped_categories = match grouping_kind {
        EntryCategoryGrouping::AsGroupCategories => group_category_details(keepass_file),
        EntryCategoryGrouping::AsTypes => type_category_details(keepass_file),
        EntryCategoryGrouping::AsTags => tag_category_details(keepass_file),
    };

    EntryCategories {
        general_categories,
        grouping_kind,
        grouped_categories,
    }
}
