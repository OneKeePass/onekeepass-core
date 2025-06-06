use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::vec;

use crate::constants::entry_keyvalue_key::{PASSWORD, TITLE, USER_NAME};
use crate::constants::general_category_names::FAVORITES;
use crate::constants::AUTO_OPEN_GROUP_UC_NAME;
use crate::db_content::{
    move_to_recycle_bin, verify_uuid, AttachmentHashValue, Entry, Group, KeyValue,
};
use crate::error::{Error, Result};
use crate::util;
use log::{debug, error};
use uuid::Uuid;

pub trait GroupVisitor {
    fn act(&mut self, group: &Group);
}

use std::collections::HashSet;

use super::{split_tags, Meta};

#[derive(Debug, Deserialize)]
pub enum GroupSortCriteria {
    AtoZ,
    ZtoA,
}

#[derive(Debug, Deserialize)]
pub struct EntryCloneOption {
    pub new_title: Option<String>,
    pub parent_group_uuid: Uuid,
    pub keep_histories: bool,
    // The cloned entry's username and password refers to the source entry
    pub link_by_reference: bool,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct AllTags {
    // Unique entry tags set
    entry_tags: HashSet<String>,
    // Unique group tags set
    group_tags: HashSet<String>,
}

impl GroupVisitor for AllTags {
    /// Collects all the tags used at group levels
    fn act(&mut self, group: &Group) {
        //self.group_tags.extend_from_slice(&split_tags(&group.tags));
        for t in split_tags(&group.tags) {
            self.group_tags.insert(t);
        }
    }
}

#[derive(Debug)]
struct InOrderIds {
    entry_ids_wanted: bool,
    ids: Vec<Uuid>,
}

impl GroupVisitor for InOrderIds {
    fn act(&mut self, group: &Group) {
        if self.entry_ids_wanted {
            self.ids.extend_from_slice(&group.entry_uuids);
        } else {
            self.ids.extend_from_slice(&group.group_uuids);
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct DeletedObject {
    pub(crate) uuid: Uuid,
    pub(crate) deletion_time: NaiveDateTime,
}

impl DeletedObject {
    pub(crate) fn with_uuid(uuid: Uuid, deletion_time: Option<NaiveDateTime>) -> Self {
        Self {
            uuid,
            deletion_time: deletion_time.map_or_else(|| util::now_utc(), |d| d),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Root {
    root_uuid: Uuid,
    recycle_bin_uuid: Uuid,
    auto_open_group_uuid: Option<Uuid>,

    deleted_objects: Vec<DeletedObject>,

    // All groups data for easy lookup by uuid
    all_groups: HashMap<Uuid, Group>,

    // All entries data for easy lookup by uuid
    all_entries: HashMap<Uuid, Entry>,
}

impl Root {
    pub fn new() -> Self {
        Root {
            root_uuid: Uuid::default(),
            recycle_bin_uuid: Uuid::default(),
            deleted_objects: vec![],
            auto_open_group_uuid: None,
            all_groups: HashMap::new(),
            all_entries: HashMap::new(),
        }
    }

    // Called during xml read time
    pub(crate) fn add_deleted_object(&mut self, deleted_object: DeletedObject) {
        self.deleted_objects.push(deleted_object);
    }

    pub(crate) fn add_deleted_object_by_id(&mut self, uuid: Uuid) {
        self.deleted_objects.push(DeletedObject {
            uuid,
            deletion_time: util::now_utc(),
        });
    }

    pub(crate) fn deleted_objects(&self) -> &Vec<DeletedObject> {
        self.deleted_objects.as_ref()
    }

    pub(crate) fn set_deleted_objects(&mut self, deleted_objects: Vec<DeletedObject>) {
        self.deleted_objects = deleted_objects;
    }

    pub(crate) fn auto_open_group_uuid(&self) -> Option<Uuid> {
        self.auto_open_group_uuid
    }

    pub(crate) fn _set_auto_open_group_uuid(&mut self, uuid: Uuid) {
        self.auto_open_group_uuid = Some(uuid);
    }

    pub(crate) fn root_uuid(&self) -> Uuid {
        self.root_uuid
    }

    pub(crate) fn set_root_uuid(&mut self, uuid: Uuid) -> &mut Self {
        self.root_uuid = uuid;
        self
    }

    pub(crate) fn recycle_bin_uuid(&self) -> Uuid {
        self.recycle_bin_uuid
    }

    pub(crate) fn set_recycle_bin_uuid(&mut self, uuid: Uuid) -> &mut Self {
        self.recycle_bin_uuid = uuid;
        self
    }

    // Called to add to the collection of all groups HashMap for easy lookup
    // IMPORTANT: This does not verify any data on the passed 'group'
    pub(crate) fn insert_to_all_groups(&mut self, group: Group) {
        self.all_groups.insert(group.uuid, group);
    }

    // Called to add to the collection of all entries HashMap for easy lookup
    // IMPORTANT: This does not verify any data on the passed 'entry'. Caller side reponsible for validata data
    pub(crate) fn all_entries(&self) -> &HashMap<Uuid, Entry> {
        &self.all_entries
    }

    pub(crate) fn insert_to_all_entries(&mut self, entry: Entry) {
        //let a:std::sync::Arc<Root>  =  std::sync::Arc::clone(self);
        self.all_entries.insert(entry.uuid, entry);
    }

    pub fn entry_by_id(&self, entry_uuid: &Uuid) -> Option<&Entry> {
        self.all_entries.get(entry_uuid)
    }

    pub fn history_entry_by_index(&self, entry_uuid: &Uuid, index: i32) -> Option<Entry> {
        self.entry_by_id(entry_uuid)
            .and_then(|e| e.history_entry_by_index(index))
    }

    pub fn delete_history_entry_by_index(&mut self, entry_uuid: &Uuid, index: i32) {
        if let Some(e) = self.entry_by_id_mut(entry_uuid) {
            e.delete_history_entry_by_index(index);
        }
    }

    pub fn delete_history_entries(&mut self, entry_uuid: &Uuid) {
        if let Some(e) = self.entry_by_id_mut(entry_uuid) {
            e.delete_history_entries();
        }
    }

    pub fn delete_all_history_entries(&mut self) {
        for (_, entry) in self.all_entries.iter_mut() {
            entry.delete_history_entries();
        }
    }

    pub fn remove_all_binary_kvs_and_history_entries(&mut self) {
        for (_, entry) in self.all_entries.iter_mut() {
            entry.delete_history_entries();
            entry.binary_key_values = vec![];
        }
    }

    pub fn entry_by_id_mut(&mut self, entry_uuid: &Uuid) -> Option<&mut Entry> {
        self.all_entries.get_mut(entry_uuid)
    }

    // Finds the first entry that has a matching value in a given key field
    pub fn entry_by_matching_kv(&self, key: &str, value: &str) -> Option<&Entry> {
        // First match is returned
        self.all_entries.values().find(|e| {
            if let Some(ref v) = e.find_kv_field_value(key) {
                v == value
            } else {
                false
            }
        })
    }

    pub fn entry_by_matching_kv_mut(&mut self, key: &str, value: &str) -> Option<&mut Entry> {
        // First match is returned
        self.all_entries.values_mut().find(|e| {
            if let Some(ref v) = e.find_kv_field_value(key) {
                v == value
            } else {
                false
            }
        })
    }

    pub fn group_by_id(&self, group_uuid: &Uuid) -> Option<&Group> {
        self.all_groups.get(group_uuid)
    }

    pub fn group_by_id_ok(&self, group_uuid: &Uuid) -> Result<&Group> {
        Ok(self
            .all_groups
            .get(group_uuid)
            .ok_or_else(|| "The group is not found in All groups")?)
    }

    pub fn group_by_id_mut(&mut self, group_uuid: &Uuid) -> Option<&mut Group> {
        self.all_groups.get_mut(group_uuid)
    }

    pub fn group_by_name(&self, name: &str) -> Option<&Group> {
        // Returns the first matching group
        self.all_groups.values().find(|g| g.name == name)
    }

    pub fn group_by_name_mut(&mut self, name: &str) -> Option<&mut Group> {
        // Returns the first matching group
        let g_opt = self
            .all_groups
            .values()
            .find(|g| g.name == name)
            .map(|g| g.uuid);

        g_opt.map(|id| self.all_groups.get_mut(&id)).flatten()
    }

    // pub(crate) fn is_group_empty(&self, group_uuid: &Uuid) -> Result<bool> {
    //     let group = self
    //         .all_groups
    //         .get(&group_uuid)
    //         .ok_or_else(|| "The group is not found in All groups")?;

    //     Ok(group.entry_uuids().is_empty() && group.sub_group_uuids().is_empty())
    // }

    // Gets all entries. The flag exclude determines whether to include or exclude entries from the special groups in the list
    // TODO: intead of 'exclude', accept the list of group ids to exclude. See comments in 'KeepassFile'
    pub(crate) fn get_all_entries<'a>(&'a self, exclude: bool) -> Vec<&'a Entry> {
        //let ids = if exclude {self.deleted_entry_uuids() } else {vec![]};
        self.all_entries
            .values()
            .filter(|x| {
                if exclude {
                    //if ids.contains(&x.uuid) {false} else {true}
                    if &x.parent_group_uuid == &self.recycle_bin_uuid {
                        false
                    } else {
                        true
                    } //For now only entries from recycle group is excluded
                } else {
                    true
                }
            })
            .collect()
    }

    /// Collects all entries that are not in recycle bin
    pub(crate) fn collect_all_active_entries<'a>(
        &'a self,
        recycle_group_uuid: Uuid,
    ) -> Vec<&'a Entry> {
        let mut excluded_group_ids = self.deleted_group_uuids();
        excluded_group_ids.push(recycle_group_uuid);
        let v: Vec<&Entry> = self
            .all_entries
            .values()
            .filter(|x| {
                // Is this entry' parent group is in recycle bin or its parent is recycle bin?
                !excluded_group_ids.contains(&x.parent_group_uuid)
            })
            .collect();
        v
    }

    /// Collects all entries that are not in recycle bin and has tag 'Favorites'
    pub(crate) fn collect_favorite_entries<'a>(
        &'a self,
        recycle_group_uuid: Uuid,
    ) -> Vec<&'a Entry> {
        // TODO: Need to merge commonality between this method and 'collect_all_active_entries'
        let mut excluded_group_ids = self.deleted_group_uuids();
        excluded_group_ids.push(recycle_group_uuid);
        let v: Vec<&Entry> = self
            .all_entries
            .values()
            .filter(|x| {
                // Consider the entries whose  parent group is not in recycle bin or its parent is not in recycle bin and Tag has Favorites
                !excluded_group_ids.contains(&x.parent_group_uuid)
                    && split_tags(&x.tags).contains(&FAVORITES.into())
            })
            //.filter(|e| split_tags(&e.tags).contains(&"Favorites".into()))
            .collect();
        v
    }

    /// Gets all entries whose entry type matches a given custom entry type uuid
    pub(crate) fn custom_entry_type_entries_by_id<'a>(
        &'a self,
        entry_type_uuid: &Uuid,
    ) -> Vec<&'a Entry> {
        // IMPORTANT:
        // It is assumed that all entries have their Entrytype struct is initialized
        // properly with the type, section and field info - see after_xml_reading method of Keepass
        let entries: Vec<&Entry> = self
            .all_entries
            .values()
            .filter(|x| {
                x.entry_field.entry_type.uuid == *entry_type_uuid
                    && x.meta_share.get_entry_type_by_id(entry_type_uuid).is_some()
            })
            .collect();
        entries
    }

    // TODO: Combine set_recycle_bin_group_on_merge and recycle_bin_group

    pub(crate) fn set_recycle_bin_group_on_merge(&mut self, source_recycle_bin_uuid: Uuid) {
        if source_recycle_bin_uuid != Uuid::default() && self.recycle_bin_uuid == Uuid::default() {
            debug!("Recycle bin is set from source db ");

            let mut g = Group::new();
            g.uuid = source_recycle_bin_uuid;
            g.parent_group_uuid = self.root_uuid; // Recycle parent is root group
            g.name = "Recycle Bin".into();
            g.icon_id = 43;
            // This recycle_bin_uuid is copied to Meta while writing the db. See share_root_to_meta method of KeepassFile struct
            self.recycle_bin_uuid = g.uuid;
            // This adds the recycle group to the 'root' group's group_uuids and also inserts to 'all_groups' map
            let _r = self.insert_group(g);
        }
    }

    // Gets an existing recycle bin group referece.
    // If there is no recycle bin group, a new one is created and a ref that group is returned
    // This fn is used in the macro 'move_to_recycle_bin!' while calling move_group or with move_entry
    pub fn recycle_bin_group(&mut self) -> Option<&Group> {
        if self.recycle_bin_uuid == Uuid::default() {
            let mut g = Group::new_with_id();
            // g.uuid = Uuid::new_v4();
            g.parent_group_uuid = self.root_uuid; // Recycle parent is root group
            g.name = "Recycle Bin".into();
            g.icon_id = 43;
            // This recycle_bin_uuid is copied to Meta while writing the db. See share_root_to_meta method of KeepassFile struct
            self.recycle_bin_uuid = g.uuid;
            // This adds the recycle group to the 'root' group's group_uuids and also inserts to 'all_groups' map
            let _r = self.insert_group(g);
        }
        self.all_groups.get(&self.recycle_bin_uuid)
    }

    /// Ensures that the special group such as recycle_bin_uuid is at the end of root's group listing
    pub fn adjust_special_groups_order(&mut self) {
        if let Some(root_grp) = self.all_groups.get_mut(&self.root_uuid) {
            root_grp.group_uuids.retain(|x| x != &self.recycle_bin_uuid);
            if self.recycle_bin_uuid != Uuid::default() {
                root_grp.group_uuids.push(self.recycle_bin_uuid);
            }
        }
    }

    pub fn deleted_entries(&self) -> Vec<&Entry> {
        let ids = self.deleted_entry_uuids();
        self.all_entries
            .iter()
            .filter(|(key, _val)| ids.contains(key))
            .map(|x| x.1)
            .collect()
    }

    /// Gets all entries that are moved to recycle bin
    pub(crate) fn deleted_entry_uuids(&self) -> Vec<Uuid> {
        // true is passed for 'entry_ids_wanted' as we want all deleted entry uuids
        self.deleted_uuids(true)
    }

    /// Gets all groups that are moved to recycle bin
    pub(crate) fn deleted_group_uuids(&self) -> Vec<Uuid> {
        // false is passed for 'entry_ids_wanted' as we want all deleted group uuids
        self.deleted_uuids(false)
    }

    /// Collects all entry (entry_ids_wanted should be true) or group uuids that are put in recycle bin
    fn deleted_uuids(&self, entry_ids_wanted: bool) -> Vec<Uuid> {
        let mut acc = InOrderIds {
            ids: vec![],
            entry_ids_wanted,
        };
        self.group_visitor_action(&self.recycle_bin_uuid, &mut acc);
        acc.ids
    }

    /// Gets all special groups like Recycle Bin Group etc
    pub fn special_group_uuids(&self) -> Vec<Uuid> {
        if self.recycle_bin_uuid != Uuid::default() {
            vec![self.recycle_bin_uuid]
        } else {
            vec![]
        }
    }

    /// Gets all groups. The flag exclude_spl_groups determines whether to include or exclude
    /// the special groups such as Recyscle Bin in the list or not
    pub fn get_all_groups<'a>(&'a self, exclude_spl_groups: bool) -> Vec<&'a Group> {
        self.all_groups
            .values()
            .filter(|x| {
                if exclude_spl_groups {
                    x.uuid != self.recycle_bin_uuid
                } else {
                    true
                }
            })
            .collect()
    }

    #[inline]
    fn _root_group<'a>(&'a self) -> Option<&'a Group> {
        self.all_groups.get(&self.root_uuid)
    }

    #[inline]
    pub(crate) fn root_group_as_mut(&mut self) -> Option<&mut Group> {
        self.all_groups.get_mut(&self.root_uuid)
    }

    // TODO:
    // Should we combine 'insert_*' and 'update_*' ?

    // Called from service layer to insert a newly added group (in UI layer)
    pub fn insert_group(&mut self, group: Group) -> Result<()> {
        if group.parent_group_uuid == Uuid::default() {
            return Err(Error::UnexpectedError(
                "Valid parent group is not set".into(),
            ));
        }

        if !self.all_groups.contains_key(&group.parent_group_uuid) {
            return Err(Error::NotFound(
                "Parent Group is not valid for the group".into(),
            ));
        }

        if self.all_groups.contains_key(&group.uuid) {
            return Err(Error::NotFound(
                "Attempted to insert the same group again".into(),
            ));
        }

        // Adds the new group to its parent
        self.all_groups
            .entry(group.parent_group_uuid.clone())
            .and_modify(|g| g.group_uuids.push(group.uuid));

        //self.adjusted_push_to_parent(group.parent_group_uuid, group.uuid);
        self.all_groups.insert(group.uuid, group);

        Ok(())
    }

    pub fn update_group(&mut self, group: Group, group_modification_time_used: bool) {
        //TODO: Need return error if this group is not present in all_groups map

        if let Some(g) = self.all_groups.get_mut(&group.uuid) {
            if group_modification_time_used {
                g.times = group.times.clone();
            } else {
                g.times.update_modification_time_now();
            }

            g.name = group.name;
            g.notes = group.notes;
            g.tags = group.tags;
            g.icon_id = group.icon_id;
            //g.custom_data = group.custom_data;
            g.marked_category = group.marked_category;

            //TODO: Need to consider other fields from the incoming 'group' if required
        }
    }

    fn group_comparator(
        &self,
        a_group_uuid: &Uuid,
        b_group_uuid: &Uuid,
        criteria: &GroupSortCriteria,
    ) -> core::cmp::Ordering {
        if let (Some(g1), Some(g2)) = (
            self.all_groups.get(a_group_uuid),
            self.all_groups.get(b_group_uuid),
        ) {
            if let GroupSortCriteria::AtoZ = criteria {
                g1.name.cmp(&g2.name)
            } else {
                g2.name.cmp(&g1.name)
            }
        } else {
            // We are assuming 'all_groups' should have groups identified by a_group_uuid and b_group_uuid
            // Expected to get Some(..) and not None values above.
            // This clause is not expected to be called
            log::error!("In group_comparator: The group uuid a_group_uuid {} or b_group_uuid {} or both are not found",a_group_uuid,b_group_uuid);
            core::cmp::Ordering::Equal
        }
    }

    pub fn sort_sub_groups(
        &mut self,
        group_uuid: &Uuid,
        criteria: &GroupSortCriteria,
    ) -> Result<()> {
        if !self.all_groups.contains_key(group_uuid) {
            return Err(Error::NotFound("Group is not valid one".into()));
        }

        if group_uuid == &self.recycle_bin_uuid {
            log::debug!("Skipping the recycle bin's sub groups from sorting");
            return Ok(());
        }

        let mut sub_group_ids: Vec<Uuid> = vec![];

        if let Some(v) = self.all_groups.get(group_uuid) {
            // Get all sub group uuids of this group
            sub_group_ids = v.group_uuids.clone();

            //debug!("Before sub_group_ids {:?} for group_uuid {} ", &sub_group_ids,&group_uuid);

            // Sorts the uuids based on the criteria
            sub_group_ids.sort_by(|a, b| self.group_comparator(a, b, criteria));

            //debug!("After sorting sub_group_ids {:?} for group_uuid {} ", &sub_group_ids,&group_uuid);

            // The group's child group list is updated with the sorted list
            self.all_groups
                .entry(group_uuid.clone())
                .and_modify(|g| g.group_uuids = sub_group_ids.clone());
        }

        // Recursively call this sorting for each of this group's sub groups
        for sub_group_id in sub_group_ids {
            self.sort_sub_groups(&sub_group_id, criteria)?;
        }

        // adjust_special_groups_order should be called after this in service layer
        // to keep the Recycle Bin in the end. See db_service::adjust_special_groups_order
        // call in db_service::create_groups_summary_data

        Ok(())
    }

    /// Moves a group to the recycle bin group when user deletes a group
    pub fn move_group_to_recycle_bin(&mut self, group_uuid: Uuid) -> Result<()> {
        move_to_recycle_bin!(self, move_group, group_uuid)

        // // First we need to find the recycle group and it will be the new parent for this group
        // let parent_id = self.recycle_bin_group().ok_or("No recycle bin group")?.uuid;
        // self.move_group(group_uuid,parent_id)?;
        // Ok(())
    }

    /// Deletes all entries and groups permanently
    pub(crate) fn empty_trash(&mut self, recycle_group_uuid: Uuid) -> Result<()> {
        verify_uuid!(self, recycle_group_uuid, all_groups);

        //debug!("Before emptying all_groups count {}, all_entries count {}",self.all_groups.len(), self.all_entries.len());

        // IMPORTANT:
        // Need to remove the deleted entries first which includes
        // entries that are in deleted groups.

        // If this is not done and if the deleted groups are removed first, then calling
        // 'deleted_entry_uuids' will miss out those entry uuids that were in the deleted groups
        // see 'group_visitor_action' as we will walk through groups to get all groups or entries

        for eid in self.deleted_entry_uuids() {
            self.all_entries
                .remove(&eid)
                .ok_or("The recycled entry is not found in All Entries map")?;
            self.add_deleted_object_by_id(eid);
        }

        // This will remove all deleted groups. The groups' entries have been deleted
        // already in the above loop
        for gid in self.deleted_group_uuids() {
            self.all_groups
                .remove(&gid)
                .ok_or("The recycled group is not found in All Groups map")?;
            self.add_deleted_object_by_id(gid);
        }

        let recycle_group = self
            .all_groups
            .get_mut(&recycle_group_uuid)
            .ok_or("The recycle group is not found in All Groups map")?;
        recycle_group.group_uuids = vec![];
        recycle_group.entry_uuids = vec![];

        //debug!("After emptying all_groups count {}, all_entries count {}",self.all_groups.len(), self.all_entries.len());

        Ok(())
    }

    pub fn remove_group_permanently(&mut self, group_uuid: Uuid) -> Result<()> {
        verify_uuid!(self, group_uuid, all_groups);

        // verify that group_uuid is in the recycle group before removing permanently
        if !self.deleted_group_uuids().contains(&group_uuid) {
            return Err(Error::NotFound(
                "The group is not found in recycle bin".into(),
            ));
        }

        let entry_ids = self.children_entry_uuids(&group_uuid);

        // First we need to remove all entries found in this group and in its sub groups
        for eid in entry_ids {
            self.remove_entry_permanently(eid)?;
        }

        // Now all entries of this group and its subgroups are removed

        // Get all subgroups recursively
        let sub_group_ids = self.children_groups_uuids(&group_uuid);

        // Remove all sub groups. Entries are already removed
        for gid in sub_group_ids {
            self.all_groups
                .remove(&gid)
                .ok_or(Error::UnexpectedError(format!(
                    "The group {} is not found in All Groups map",
                    &gid
                )))?;
        }

        // Remove the group from all_groups map
        let g = self
            .all_groups
            .remove(&group_uuid)
            .ok_or("The group is not found in All groups")?;

        // Remove this group id from group_uuids of its parent where
        // the parent may recycle bin group or group that is in recycle
        if let Some(old_parent) = self.all_groups.get_mut(&g.parent_group_uuid) {
            old_parent.group_uuids.retain(|&id| id != group_uuid);
        }

        // Add the uuid to the "DeletedObjects" to mark permanent removal of this group
        // Useful during merging dbs
        self.add_deleted_object_by_id(group_uuid);

        Ok(())
    }

    pub fn remove_group_on_merge_deleted_objects(&mut self, group_uuid: Uuid) -> Result<()> {
        verify_uuid!(self, group_uuid, all_groups);

        // As we have already verified group_uuid above, we can use unwrap also
        let group = self
            .all_groups
            .get(&group_uuid)
            .ok_or_else(|| "The group is not found in All groups")?;

        if !group.entry_uuids.is_empty() || !group.group_uuids.is_empty() {
            return Err(Error::DataError(
                "Group is not empty. The group should not have any entry or subgroup",
            ));
        }

        // Remove the group from all_groups map
        let group = self
            .all_groups
            .remove(&group_uuid)
            .ok_or_else(|| "The group is not found in All groups")?;

        // Remove this group id from group_uuids of its parent group.
        if let Some(old_parent) = self.all_groups.get_mut(&group.parent_group_uuid) {
            old_parent.group_uuids.retain(|&id| id != group_uuid);
        }

        Ok(())
    }

    pub fn remove_entry_permanently(&mut self, entry_uuid: Uuid) -> Result<()> {
        verify_uuid!(self, entry_uuid, all_entries);

        // verify that entry_uuid is in the recycle group before removing permanently
        if !self.deleted_entry_uuids().contains(&entry_uuid) {
            return Err(Error::NotFound(
                "The entry is not found in recycle bin".into(),
            ));
        }
        // Remove the entry from all_groups map
        let e = self
            .all_entries
            .remove(&entry_uuid)
            .ok_or("The entry is not found in All entries")?;

        // Remove this entry id from entry_uuids of its parent group.
        // The parent should be a recycle bin group  or group that is in recycle bin
        if let Some(old_parent) = self.all_groups.get_mut(&e.parent_group_uuid) {
            old_parent.entry_uuids.retain(|&id| id != e.uuid);
        }

        self.add_deleted_object_by_id(entry_uuid);

        Ok(())
    }

    pub fn remove_entry_on_merge_deleted_objects(&mut self, entry_uuid: Uuid) -> Result<()> {
        verify_uuid!(self, entry_uuid, all_entries);

        // Remove the entry from all_groups map
        let entry = self
            .all_entries
            .remove(&entry_uuid)
            .ok_or_else(|| "The entry is not found in All entries")?;

        // Remove this entry id from entry_uuids of its parent group.
        if let Some(old_parent) = self.all_groups.get_mut(&entry.parent_group_uuid) {
            old_parent.entry_uuids.retain(|&id| id != entry.uuid);
        }

        Ok(())
    }

    /// Moves a group from one parent group to another group
    pub fn move_group(&mut self, group_uuid: Uuid, new_parent_id: Uuid) -> Result<()> {
        verify_uuid!(self, group_uuid, all_groups);
        verify_uuid!(self, new_parent_id, all_groups);

        if group_uuid == new_parent_id {
            return Err(Error::DataError(
                "The group and its parent group cannot be the same",
            ));
        }

        let mut old_parent_id = Uuid::default();
        if let Some(grp) = self.all_groups.get_mut(&group_uuid) {
            old_parent_id = grp.parent_group_uuid;
            if old_parent_id == new_parent_id {
                error!(
                    "The new parent group is {} and is the same as the current parent group id",
                    new_parent_id
                );
                return Err(Error::DataError("The new parent is the same as the old parent for this group and move is not done"));
            }
            grp.parent_group_uuid = new_parent_id;
            // At this time we are changing only 'location_changed' time.
            grp.times.location_changed = util::now_utc();
        }

        // If the new parent is root group, we need to keep the recycle bin group as the last one in root's group_uuids
        // so that UI tree shows the Recycle Bin as last item
        // if (new_parent_id == self.root_uuid) & (self.recycle_bin_uuid != Uuid::default()) {
        //     if let Some(root_grp) = self.all_groups.get_mut(&new_parent_id) {
        //         if let Some(recycle_id) = root_grp.group_uuids.pop() {
        //             // Add this group id to the new parent group uuids and then add back recycle bin uuid
        //             root_grp.group_uuids.push(group_uuid);
        //             root_grp.group_uuids.push(recycle_id);
        //         }
        //     }
        // } else {
        //     // Add this group id to the new parent group uuids. For now it is added to the end
        //     self.all_groups
        //         .entry(new_parent_id.clone())
        //         .and_modify(|g| g.group_uuids.push(group_uuid));
        // }

        self.all_groups
            .entry(new_parent_id.clone())
            .and_modify(|g| g.group_uuids.push(group_uuid));

        //self.adjusted_push_to_parent(new_parent_id, group_uuid);

        // Remove this group id from group_uuids of previous parent
        if let Some(old_parent) = self.all_groups.get_mut(&old_parent_id) {
            old_parent.group_uuids.retain(|&id| id != group_uuid);
        }
        Ok(())
    }

    /// Moves an entry to the recycle bin group when user deletes an entry
    pub fn move_entry_to_recycle_bin(&mut self, entry_uuid: Uuid) -> Result<()> {
        move_to_recycle_bin!(self, move_entry, entry_uuid)
    }

    pub fn move_entry(&mut self, entry_uuid: Uuid, new_parent_id: Uuid) -> Result<()> {
        verify_uuid!(self, entry_uuid, all_entries);
        verify_uuid!(self, new_parent_id, all_groups);

        // all_entries map contains the key 'entry_uuid' as we have that verified above. Calling unwrap() is fine
        let entry = self.all_entries.get_mut(&entry_uuid).unwrap();
        let old_parent_id = entry.parent_group_uuid;

        verify_uuid!(self, old_parent_id, all_groups);

        if old_parent_id == new_parent_id {
            error!(
                "The new parent group is {} and is the same as the current parent group id",
                new_parent_id
            );
            return Err(Error::DataError(
                "The new parent is the same as the old parent for this entry and move is not done",
            ));
        }

        entry.parent_group_uuid = new_parent_id;
        entry.times.location_changed = util::now_utc();

        // Add this entry id to the new parent entry uuids. For now it is added to the end
        self.all_groups
            .entry(new_parent_id.clone())
            .and_modify(|g| g.entry_uuids.push(entry_uuid));

        // Remove this entry id from entry_uuids of previous parent group
        if let Some(old_parent) = self.all_groups.get_mut(&old_parent_id) {
            old_parent.entry_uuids.retain(|&id| id != entry_uuid);
        }

        Ok(())
    }

    pub fn insert_entry(&mut self, mut entry: Entry) -> Result<()> {
        // Need to return error if 'insert_entry' is called multiple times with the same entry_id
        if self.all_entries.contains_key(&entry.uuid) {
            return Err(Error::DataError(
                "Insert entry is called for an existing entry",
            ));
        }

        // TODO: Entry's group_uuid should be its parent group uuid. Should we add 'assert' for that?
        // Need to add this entry to its parent's list
        if let Some(g) = self.all_groups.get_mut(&entry.parent_group_uuid) {
            g.entry_uuids.push(entry.uuid);
        } else {
            return Err(Error::NotFound("Group is not valid for the entry".into()));
        }
        entry.complete_insert();

        self.all_entries.insert(entry.uuid, entry);
        Ok(())
    }

    pub fn update_entry(&mut self, entry: Entry) -> Result<()> {
        verify_uuid!(self, entry.uuid, all_entries);

        // Need to find the existing entry that has the same uuid as the incoming one
        // to create the history
        if let Some(e) = self.all_entries.get_mut(&entry.uuid) {
            e.update(entry);
        }

        Ok(())
    }

    pub fn clone_entry(
        &mut self,
        entry_uuid: &Uuid,
        entry_clone_option: &EntryCloneOption,
    ) -> Result<Uuid> {
        // Caller needs to ensure that a valid parent group uuid is passed
        verify_uuid!(self, entry_clone_option.parent_group_uuid, all_groups);

        let Some(source_entry) = self.all_entries.get(entry_uuid) else {
            return Err(Error::NotFound("Entry is not found to clone".into()));
        };

        let mut cloned_entry = source_entry.clone();
        // A new entry uuid is required for the cloned one
        let new_e_uuid = uuid::Uuid::new_v4();
        cloned_entry.uuid = new_e_uuid;

        // Cloned entry's parent group uuid should be set
        cloned_entry.parent_group_uuid = entry_clone_option.parent_group_uuid;

        // Title is changed
        if let Some(title) = entry_clone_option.new_title.as_ref() {
            cloned_entry.entry_field.update_value(TITLE, title);
        }

        // Link by reference done for UserName and Password
        if entry_clone_option.link_by_reference {
            // Uppercase Uuid string is used as done by other KP implementation
            let mut buff = Uuid::encode_buffer();
            let uuid_str = source_entry.uuid.simple().encode_upper(&mut buff);

            // debug!("Source entry uuid_str {} for cloning",uuid_str);

            let mut kv = KeyValue::new();
            kv.key = USER_NAME.to_string();
            kv.value = format!("{{REF:U@I:{}}}", uuid_str);
            cloned_entry.entry_field.insert_key_value(kv);

            let mut kv = KeyValue::new();
            kv.key = PASSWORD.to_string();
            kv.value = format!("{{REF:P@I:{}}}", uuid_str);
            kv.protected = true;
            cloned_entry.entry_field.insert_key_value(kv);
        }

        // Remove the source entry's histories if required
        if !entry_clone_option.keep_histories {
            // This should remove histories and history realted entry type custom data
            cloned_entry.delete_history_entries();
        }
        // Change the times for this cloned entry
        let n = util::now_utc();
        cloned_entry.times.creation_time = n;
        cloned_entry.times.last_modification_time = n;
        cloned_entry.times.last_access_time = n;

        // Need to add this new cloned entry to its parent group's list
        self.all_groups
            .entry(entry_clone_option.parent_group_uuid)
            .and_modify(|g| g.entry_uuids.push(cloned_entry.uuid));

        // Add this new cloned entry to the entries lookup map
        self.all_entries.insert(cloned_entry.uuid, cloned_entry);

        // debug!("Entry uuid {} is cloned and cloned entry uuid is {}", &entry_uuid, &new_e_uuid);

        Ok(new_e_uuid)
    }

    // Should this be moved to parent 'KeepassFile' ?
    // Sets the hash value of attachments to entries during the reading of the db file
    pub fn set_attachment_hashes(
        &mut self,
        attachment_hash_indexed: &HashMap<i32, (AttachmentHashValue, usize)>,
    ) {
        debug!(
            "After reading - attachment_hash_indexed passed is {:?}",
            attachment_hash_indexed
        );

        // Delegate the set_attachment_hashes call to each entry found
        for id in self.get_all_inorder_entry_uuids() {
            if let Some(e) = self.all_entries.get_mut(&id) {
                e.set_attachment_hashes(attachment_hash_indexed);
            }
        }
    }

    // Should this be moved to parent 'KeepassFile' ?
    // Called to set the new index_refs of all attachments found in entries before writing to the db file
    pub fn set_attachment_index_refs(
        &mut self,
        hash_index_ref: &HashMap<AttachmentHashValue, i32>,
    ) {
        debug!(
            "Before writing - hash_index_ref passed is {:?}",
            hash_index_ref
        );
        for id in self.get_all_inorder_entry_uuids() {
            if let Some(e) = self.all_entries.get_mut(&id) {
                e.set_attachment_index_refs(hash_index_ref);
            }
        }
    }

    // Collects the attachment hash values from all entries in an order
    // This is called before writing db file
    pub fn get_attachment_hashes(&self) -> Vec<AttachmentHashValue> {
        let mut hashes = vec![];
        for id in self.get_all_inorder_entry_uuids() {
            if let Some(e) = self.all_entries.get(&id) {
                e.get_attachment_hashes(&mut hashes);
            }
        }
        hashes
    }

    pub fn get_all_inorder_entry_uuids(&self) -> Vec<Uuid> {
        let mut acc = InOrderIds {
            ids: vec![],
            entry_ids_wanted: true,
        };
        self.root_group_visitor_action(&mut acc);
        acc.ids
    }

    pub fn mark_group_as_category(&mut self, group_uuid: &Uuid) {
        if let Some(g) = self.all_groups.get_mut(group_uuid) {
            g.mark_as_category();
        }
    }

    pub fn custom_data_to_groups(&mut self) {
        let mut acc = InOrderIds {
            ids: vec![],
            entry_ids_wanted: false,
        };

        // Need to call root group's custom_data_to_group separately as the following
        // group_visitor_action call will not include root group
        if let Some(rg) = self.root_group_as_mut() {
            rg.custom_data_to_group();
        }

        self.group_visitor_action(&self.root_uuid, &mut acc);
        for id in acc.ids {
            if let Some(g) = self.group_by_id_mut(&id) {
                g.custom_data_to_group();
            }
        }
    }

    // pub fn custom_data_to_entries(&mut self) {
    //     self.all_entries
    //         .values_mut()
    //         .for_each(|e| e.after_xml_reading());
    // }

    // Called to set shared meta data to all entries after parsing xml payload data
    pub fn entries_after_xml_reading(&mut self, meta: &Meta) {
        self.all_entries
            .values_mut()
            .for_each(|e| e.after_xml_reading(meta));
    }

    // Called to ensure that any house keeping is required to be done before xml writing
    pub fn entries_before_xml_writing(&mut self) {
        self.all_entries
            .values_mut()
            .for_each(|e| e.before_xml_writing());
    }

    // pub fn set_custom_entry_types(&mut self, meta:&Meta) {
    //     self.all_entries
    //         .values_mut()
    //         .for_each(|e| {
    //             e.meta_share = Arc::clone(&meta.meta_share);
    //         });
    // }

    pub(crate) fn groups_to_custom_data(&mut self) {
        let mut acc = InOrderIds {
            ids: vec![],
            entry_ids_wanted: false,
        };
        // Need to call group_to_custom_data separately as the following
        // group_visitor_action call will not include root group
        if let Some(rg) = self.root_group_as_mut() {
            rg.group_to_custom_data();
        }
        self.group_visitor_action(&self.root_uuid, &mut acc);
        for id in acc.ids {
            if let Some(g) = self.group_by_id_mut(&id) {
                g.group_to_custom_data();
            }
        }
    }

    pub(crate) fn collect_tags(&self) -> AllTags {
        let mut all_tags = AllTags::default();
        // First collect all the unique tags used at group levels
        self.root_group_visitor_action(&mut all_tags);
        // Now collect all unique tags used at entry level
        for e in self.get_all_entries(false) {
            for t in split_tags(&e.tags) {
                all_tags.entry_tags.insert(t);
            }
        }
        all_tags
    }

    pub(crate) fn auto_open_group_entries(&self) -> Vec<&Entry> {
        // auto_open_group_uuid is an Option type as we may or may not have an 'AutoOpen' group
        // Option<Uuid> -> Option<&Group>
        self.auto_open_group_uuid
            .and_then(|ref ao_grp_id| self.group_by_id(ao_grp_id))
            .map_or_else(
                // empty vec is returned if there is auto group
                || vec![],
                |group| {
                    let mut acc: Vec<&Entry> = vec![];
                    for entry_uuid in group.entry_uuids.iter() {
                        if let Some(entry) = self.entry_by_id(entry_uuid) {
                            acc.push(entry);
                        };
                    }
                    // acc may be empty if there are no entries for this auto group
                    acc
                },
            )
    }

    pub(crate) fn auto_open_group_entry_uuids(&self) -> Vec<Uuid> {
        // Here we are assuming all entries under auto open group are of auto open type
        self.auto_open_group_uuid.map_or_else(
            || vec![],
            |ref ao_grp_id| {
                // Only top level entry_uuids for this group is returned. The sub groups are not considered
                self.group_by_id(ao_grp_id)
                    .map_or_else(|| vec![], |group| group.entry_uuids.clone())
            },
            // To include entry_uuids from sub broups of auto_open_group, we need to use this
            // |ref ao_grp_id| self.children_entry_uuids(ao_grp_id),
        )
    }

    // Called after xml content is parsed to ensure that AutoOpen group has entry type as AUTO_DB_OPEN
    pub(crate) fn adjust_auto_open_group_entries(&mut self) {
        // Only groups under root are considered
        let root_child_group_ids = self
            .all_groups
            .get(&self.root_uuid)
            .map_or(vec![], |root_child_group| {
                root_child_group.group_uuids.clone()
            });

        let auto_open_entry_type = super::standard_entry_types::auto_open_entry_type();

        for ref grp_id in root_child_group_ids {
            // Find the AutoOpen group and change the entry type to AUTO_DB_OPEN if required
            // Here for now we are assuming all entries under this group are meant for auto open purpose only
            if let Some(ao_group) = self
                .all_groups
                .get_mut(grp_id)
                .filter(|g| g.name.to_uppercase() == AUTO_OPEN_GROUP_UC_NAME)
            {
                // Keep this uuid for later use
                self.auto_open_group_uuid = Some(ao_group.uuid);

                for e_id in &mut ao_group.entry_uuids {
                    if let Some(entry) = self.all_entries.get_mut(e_id) {
                        if entry.entry_field.entry_type.uuid != auto_open_entry_type.uuid {
                            // Though this entry type is not auto open type, we set the type to auto open type
                            // only when we find that the url field of this entry starts with kdbx://
                            if entry.entry_field.has_kdbx_url() {
                                entry.entry_field.entry_type = auto_open_entry_type.clone();
                            }
                        }
                    }
                }
            }
        }

        // let found_opt = self.all_groups.iter_mut().try_for_each(|g| {
        //     if g.1.name == "AutoOpen" {
        //         std::ops::ControlFlow::Break(g.1)
        //     } else {
        //         std::ops::ControlFlow::Continue(())
        //     }
        // });

        // // Move to group
        // let auto_open_entry_type = super::standard_entry_types::auto_open_entry_type();

        // if let Some(ao_group) = found_opt.break_value() {
        //     for e_id in &mut ao_group.entry_uuids {
        //         if let Some(entry) = self.all_entries.get_mut(e_id) {
        //             if entry.entry_field.entry_type.name != AUTO_DB_OPEN {
        //                 if let Some(t) = auto_open_entry_type {
        //                     entry.entry_field.entry_type = t.clone();
        //                 }
        //             }
        //         }
        //     }
        // }
    }

    // Visit each group starting with the root and do some action using the node group's data
    fn root_group_visitor_action(&self, acc: &mut dyn GroupVisitor) {
        self.group_visitor_action(&self.root_uuid, acc);
    }

    // Gets all sub groups' uuids found under a group with the group_uuid
    fn children_groups_uuids(&self, group_uuid: &Uuid) -> Vec<Uuid> {
        let mut acc = InOrderIds {
            ids: vec![],
            entry_ids_wanted: false,
        };
        self.group_visitor_action(&group_uuid, &mut acc);
        acc.ids
    }

    // Gets all entry uuids found under a group with the group_uuid and
    // also all entry uuids found in all sub groups under this group_uuid
    pub(crate) fn children_entry_uuids(&self, group_uuid: &Uuid) -> Vec<Uuid> {
        let mut acc = InOrderIds {
            ids: vec![],
            entry_ids_wanted: true,
        };
        self.group_visitor_action(&group_uuid, &mut acc);
        acc.ids
    }

    // Calls GroupVisitor action recursively on all sub groups for a given group uuid
    // This visit does not include the starting group - the group with group_uuid
    fn group_visitor_action(&self, group_uuid: &Uuid, acc: &mut dyn GroupVisitor) {
        if let Some(g) = self.all_groups.get(group_uuid) {
            acc.act(g);
            for cg in g.group_uuids.iter() {
                self.group_visitor_action(cg, acc);
            }
        }
    }
}
