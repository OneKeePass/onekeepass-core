use std::collections::HashMap;

use chrono::NaiveDateTime;
use serde::Serialize;
use uuid::Uuid;

use crate::db::KdbxFile;
use crate::db_content::{DeletedObject, Entry, Group, KeepassFile};

use crate::error::Result;

#[derive(Clone, Default, Debug, Serialize)]
struct GroupInfo {
    name: String,
    uuid: Uuid,
    parent_group_uuid: Option<Uuid>,
    previous_parent_group_uuid: Option<Uuid>,
}

impl GroupInfo {
    fn from(name: &str, uuid: Uuid) -> Self {
        Self {
            name: name.to_string(),
            uuid,
            parent_group_uuid: None,
            previous_parent_group_uuid: None,
        }
    }
}

#[derive(Clone, Default, Debug, Serialize)]
struct EntryInfo {
    name: String,
    uuid: Uuid,
    parent_group_uuid: Option<Uuid>,
    previous_parent_group_uuid: Option<Uuid>,
}

impl EntryInfo {
    fn from(name: &str, uuid: Uuid) -> Self {
        Self {
            name: name.to_string(),
            uuid,
            parent_group_uuid: None,
            previous_parent_group_uuid: None,
        }
    }
}

#[derive(Clone, Default, Debug, Serialize)]
pub struct MergeResult {
    added_groups: Vec<GroupInfo>,
    updated_groups: Vec<GroupInfo>,
    parent_changed_groups: Vec<GroupInfo>,

    added_entries: Vec<EntryInfo>,
    updated_entries: Vec<EntryInfo>,
    parent_changed_entries: Vec<EntryInfo>,

    permanently_deleted_entries: Vec<EntryInfo>,
    permanently_deleted_groups: Vec<GroupInfo>,

    meta_data_changed: bool,

    different_databases: bool,
}

pub struct Merger<'a> {
    source_db: &'a KeepassFile,
    target_db: &'a mut KeepassFile,
    merge_result: MergeResult,
    different_databases: bool,
}

impl<'a> Merger<'a> {
    fn from(source_db: &'a KeepassFile, target_db: &'a mut KeepassFile) -> Self {
        Self {
            source_db,
            target_db,
            merge_result: MergeResult::default(),
            different_databases: false,
        }
    }

    pub(crate) fn from_kdbx_file(source_kdbx: &'a KdbxFile, target_kdbx: &'a mut KdbxFile) -> Self {
        // Copy any attacments related hash and content details from source to target
        let other = source_kdbx.attachmentset();
        target_kdbx.insert_or_update_with_attachmentset(other);

        Self::from(
            &source_kdbx.keepass_main_content.as_ref().unwrap(),
            target_kdbx.keepass_main_content.as_mut().unwrap(),
        )
    }

    fn record_group_updated(&mut self, name: &str, uuid: Uuid) {
        self.merge_result
            .updated_groups
            .push(GroupInfo::from(name, uuid));
    }

    fn record_group_added(&mut self, name: &str, uuid: Uuid) {
        self.merge_result
            .added_groups
            .push(GroupInfo::from(name, uuid));
    }

    fn record_group_moved(&mut self, name: &str, uuid: Uuid) {
        self.merge_result
            .parent_changed_groups
            .push(GroupInfo::from(name, uuid));
    }

    fn record_group_deleted(&mut self, name: &str, uuid: Uuid) {
        self.merge_result
            .permanently_deleted_groups
            .push(GroupInfo::from(name, uuid));
    }

    fn record_entry_updated(&mut self, name: &str, uuid: Uuid) {
        self.merge_result
            .updated_entries
            .push(EntryInfo::from(name, uuid));
    }

    fn record_entry_added(&mut self, name: &str, uuid: Uuid) {
        self.merge_result
            .added_entries
            .push(EntryInfo::from(name, uuid));
    }

    fn record_entry_moved(&mut self, name: &str, uuid: Uuid) {
        self.merge_result
            .parent_changed_entries
            .push(EntryInfo::from(name, uuid));
    }

    fn record_entry_deleted(&mut self, name: &str, uuid: Uuid) {
        self.merge_result
            .permanently_deleted_entries
            .push(EntryInfo::from(name, uuid));
    }

    pub(crate) fn merge(&mut self) -> Result<MergeResult> {
        let source_root_group = self
            .source_db
            .root
            .group_by_id(&self.source_db.root.root_uuid())
            .ok_or_else(|| "Root source group is not found")?;

        let target_root_group = self
            .target_db
            .root
            .group_by_id_mut(&self.target_db.root.root_uuid())
            .ok_or_else(|| "Root target group is not found")?;

        // We determine whether source and target dbs are same or not
        // based on the db's root group uuid
        if source_root_group.get_uuid() == target_root_group.get_uuid() {
            // Source root group is newer than target root group
            if source_root_group.last_modification_time()
                > target_root_group.last_modification_time()
            {
                // Target root group's content is changed with source db's root group's content
                // This 'update_group' call updates the target group's modification time with source's time as
                // we pass 'true' in arg
                self.target_db
                    .root
                    .update_group(source_root_group.clone(), true);

                self.record_group_updated(
                    &source_root_group.name(),
                    source_root_group.get_uuid().clone(),
                );
            }

            // Need to enusre that both source and target use the same recycle group
            // We may need to do this for any other special groups as when introduced
            let source_recycle_bin_uuid = self.source_db.root.recycle_bin_uuid();
            self.target_db
                .root
                .set_recycle_bin_group_on_merge(source_recycle_bin_uuid);

            self.merge_meta()?;
            self.merge_groups(source_root_group)?;
            self.merge_deleted_objects()?;
        } else {
            // Source and target dbs are different

            self.different_databases = true;
            self.merge_result.different_databases = true;

            // let root_uuid = target_root_group.get_uuid().clone();

            // for entry_uuid in source_root_group.entry_uuids() {
            //     if self.target_db.root.entry_by_id(entry_uuid).is_none() {
            //         let mut source_root_entry = self
            //             .source_db
            //             .root
            //             .entry_by_id(entry_uuid)
            //             .ok_or_else(|| "Source entry is not found")?
            //             .clone();
            //         source_root_entry.set_parent_group_uuid(&root_uuid);
            //         self.target_db.root.insert_entry(source_root_entry)?;
            //     }
            // }

            // for group_uuid in source_root_group.sub_group_uuids() {
            //     if self.target_db.root.group_by_id(group_uuid).is_none() {
            //         let mut source_root_group = self
            //             .source_db
            //             .root
            //             .group_by_id(group_uuid)
            //             .ok_or_else(|| "Source entry is not found")?
            //             .clone();
            //         source_root_group.set_parent_group_uuid(&root_uuid);
            //         self.target_db.root.insert_group(source_root_group)?;
            //     }
            // }

            self.merge_groups(source_root_group)?;
            self.merge_deleted_objects()?;

            // TODO:
            // Copy any custom entry type definitions stored in custom data of source meta to meta's custom data of target

            // Copy all deleted objects from sourc db to target
        }

        Ok(self.merge_result.clone())
    }

    // Ensure that we have valid parent group ( should be an existing group) for the passed group
    fn parent_group_uuid_of_group(&mut self, group: &Group) -> Uuid {
        let p_uuid = group.parent_group_uuid();
        if !self.different_databases {
            p_uuid
        } else {
            if p_uuid == self.source_db.root.root_uuid() {
                self.target_db.root.root_uuid()
            } else if p_uuid == self.source_db.root.recycle_bin_uuid() {
                // Make sure that we create the recycle bin group if required
                // debug!("Source db recycle_bin_uuid is found {}", p_uuid);
                // debug!("Target db recycle_bin_uuid before recycle_bin_group call is  {}",self.target_db.root.recycle_bin_uuid());

                // This will create recycle bin group if required
                self.target_db.root.recycle_bin_group();

                // debug!("Target db recycle_bin_uuid before recycle_bin_group call is  {}", self.target_db.root.recycle_bin_uuid());

                self.target_db.root.recycle_bin_uuid()
            } else {
                p_uuid
            }
        }
    }

    // Ensure that we have valid parent group ( should be an existing group) for the passed entry
    fn parent_group_uuid_of_entry(&mut self, entry: &Entry) -> Uuid {
        let p_uuid = entry.parent_group_uuid();
        if !self.different_databases {
            p_uuid
        } else {
            if p_uuid == self.source_db.root.root_uuid() {
                self.target_db.root.root_uuid()
            } else if p_uuid == self.source_db.root.recycle_bin_uuid() {
                // Make sure that we create the recycle bin group if required

                // debug!("Source db recycle_bin_uuid is found {}", p_uuid);
                // debug!(
                //     "Target db recycle_bin_uuid before recycle_bin_group call is  {}",
                //     self.target_db.root.recycle_bin_uuid()
                // );

                // This will create recycle bin group if required
                self.target_db.root.recycle_bin_group();
                // debug!("Target db recycle_bin_uuid before recycle_bin_group call is  {}",self.target_db.root.recycle_bin_uuid());
                self.target_db.root.recycle_bin_uuid()
            } else {
                p_uuid
            }
        }
    }

    fn merge_groups(&mut self, source_group: &Group) -> Result<()> {
        log::debug!(
            "-- GROUP merge_groups is called for source_group {} ",
            source_group.name
        );

        self.merge_entries(source_group)?;

        for source_child_group_uuid in source_group.sub_group_uuids().iter() {
            let source_child_group = self
                .source_db
                .root
                .group_by_id(source_child_group_uuid)
                .ok_or_else(|| "Source group is not found")?;

            let source_parent_group_uuid = self.parent_group_uuid_of_group(source_child_group);

            // Find an existing group in the target db with this id
            // Using self.target_db.root.group_by_id_mut will result in
            // 'cannot borrow `self.target_db.root` as mutable more than once at a time' at
            // self.target_db.root.move_group
            if let Some(target_group) = self.target_db.root.group_by_id(source_child_group_uuid) {
                if target_group.location_changed() < source_child_group.location_changed()
                    && target_group.parent_group_uuid() != source_parent_group_uuid
                // && !self.different_databases
                {
                    // TODO:
                    // Make sure that 'last_modification_time' remains the same even after move as
                    // this time is used in comparision in 'merge_group'
                    let target_group_uuid = target_group.get_uuid();
                    let target_group_name = target_group.name().clone();

                    self.target_db
                        .root
                        .move_group(target_group_uuid, source_parent_group_uuid)?;

                    self.record_group_moved(&target_group_name, target_group_uuid);
                }
                // Merge source group fields to target group fields if required
                self.merge_group(source_child_group)?;
            } else {
                // No target group is found. Create a new group from source

                // We do not want to create the recycle bin group again when two dbs are different
                if self.source_db.root.recycle_bin_uuid() != source_child_group.get_uuid() {
                    // This cloned group's parent group is the same as the source_group's parent and
                    // that group should be existing
                    let mut group = source_child_group.clone();

                    // Ensure that the new group's parent is set properly and its children are removed
                    // Child entries and sub groups will added to this group as we continue with merge
                    group
                        .set_parent_group_uuid(&source_parent_group_uuid)
                        .clear_children();

                    // Should last modification time be updated instead of using the source's time?
                    self.target_db.root.insert_group(group)?;

                    self.record_group_added(
                        &source_child_group.name(),
                        source_child_group.get_uuid(),
                    );
                }
            }

            // Recursive call
            self.merge_groups(source_child_group)?;
        }

        Ok(())
    }

    fn merge_group(&mut self, source_group: &Group) -> Result<()> {
        let target_group = self
            .target_db
            .root
            .group_by_id(&source_group.get_uuid())
            .ok_or("Expected group is not found")?;

        // We do not change the target group data if it is newer than source
        if target_group.last_modification_time() >= source_group.last_modification_time() {
            return Ok(());
        }

        // We change the target group data as source group data as is new
        self.target_db.root.update_group(source_group.clone(), true);

        self.record_group_updated(&source_group.name(), source_group.get_uuid());

        Ok(())
    }

    fn merge_entries(&mut self, source_group: &Group) -> Result<()> {
        let source_db_root = &self.source_db.root;

        for source_entry_uuid in source_group.entry_uuids().iter() {
            // log::debug!(
            //     "-- ENTRY In merge_entries - for source_group {} for source child entry uuid {}",
            //     source_group.name,
            //     &source_entry_uuid
            // );
            // Get the source entry using the uuid
            if let Some(source_entry) = source_db_root.entry_by_id(source_entry_uuid) {
                let source_parent_group_uuid = self.parent_group_uuid_of_entry(source_entry);

                // First find out if we have an existing target entry for this source uuid in target db
                if let Some(target_entry) = self.target_db.root.entry_by_id(source_entry_uuid) {
                    // matching target entry is found

                    // Make sure the parent group is the same (Here we are assuming source_entry's group exists)
                    // Or change the parent
                    if target_entry.location_changed() < source_entry.location_changed()
                        && target_entry.parent_group_uuid() != source_parent_group_uuid
                    // && !self.different_databases
                    {
                        let (title, entry_uuid) =
                            (target_entry.title(), target_entry.get_uuid().clone());

                        self.target_db
                            .root
                            .move_entry(target_entry.get_uuid(), source_parent_group_uuid)?;

                        self.record_entry_moved(&title, entry_uuid);
                    }
                    // NOTE: If last_modification_time is updated, in 'move_entry',
                    // then we need to get 'last_modification_time' before 'move_entry' and pass that time
                    // in 'merge_entry'
                    // Merge source entry to target entry if required
                    self.merge_entry(source_entry)?;
                } else {
                    // No target entry is found. Create a new entry from source
                    let mut entry = source_entry.clone();
                    entry.set_parent_group_uuid(&source_parent_group_uuid);

                    self.record_entry_added(&entry.title(), entry.get_uuid());
                    // This entry will have its history as it is cloned from source (needs checking on ui)
                    self.target_db.root.insert_entry(entry)?;
                }
            }
        }

        Ok(())
    }

    // Called when an entry with same uuid is found in both source and target dbs
    fn merge_entry(&mut self, source_entry: &Entry) -> Result<()> {
        let target_entry = self
            .target_db
            .root
            .entry_by_id(&source_entry.get_uuid())
            .ok_or("Expected target entry is not found")?;

        // If no change detected, we just return
        if target_entry.last_modification_time() == source_entry.last_modification_time() {
            // Should we do this test also source_entry == target_entry ?
            return Ok(());
        }

        let mut target_entry = target_entry.clone();

        // debug!("--ENTRY target_entry.last_modification_time {}, source_entry.last_modification_time {}", &target_entry.last_modification_time(),&source_entry.last_modification_time());

        if target_entry.last_modification_time() < source_entry.last_modification_time() {
            // Source entry is newer
            let mut to_entry_cloned = source_entry.clone();

            let from_entry_cloned = &target_entry;

            // target entry's histories are merged to the source entry's history
            // and source entry is stored in the target db and the merged entry last modification time is same as the source one
            self.merge_histories(from_entry_cloned, &mut to_entry_cloned)?;

            self.record_entry_updated(&to_entry_cloned.title(), to_entry_cloned.get_uuid());

            // debug!("--ENTRY record_entry_updated source is the latest");
        } else {
            // Target entry is newer

            let to_entry_cloned = &mut target_entry;
            let from_entry_cloned = source_entry.clone();
            // source entry's histories are merged to the target entry's history
            // and the target entry is stored in the target db
            self.merge_histories(&from_entry_cloned, to_entry_cloned)?;

            self.record_entry_updated(&to_entry_cloned.title(), to_entry_cloned.get_uuid());

            // debug!("--ENTRY record_entry_updated target is the latest");
        }

        Ok(())
    }

    fn merge_histories(&mut self, from_entry: &Entry, to_entry: &mut Entry) -> Result<()> {
        let mut from_entry_cloned = from_entry.clone();

        // history entries are expected to be in a descending order of last_modification_time

        // The create_histories_to_merge adds the 'from_entry_cloned' entry to its history and returns histories
        let from_entry_histories = from_entry_cloned.create_histories_to_merge();

        let mut to_entry_histories = to_entry.histories_to_merge();

        // Add the from entry histories to the to end of entry histories
        to_entry_histories.extend(from_entry_histories);

        // This ensures the combined histories are sorted with duplicates values are consecutive elements
        to_entry_histories.sort_by_key(|e| e.last_modification_time());

        // Retains only the first element of all duplicates
        to_entry_histories.dedup_by_key(|e| e.last_modification_time());

        // update_modification_time is already called
        to_entry.set_merged_histories(&to_entry_histories);

        // target db should now have the updated entry
        self.target_db.root.insert_to_all_entries(to_entry.clone());

        Ok(())
    }

    fn merge_meta(&mut self) -> Result<()> {
        self.merge_result.meta_data_changed = self.target_db.meta.merge(&self.source_db.meta)?;
        Ok(())
    }

    fn merge_deleted_objects(&mut self) -> Result<()> {
        // We collect all deleted objects found in the target and source dbs into a Hashmap for easy lookup
        let mut merged_deleted_objects_m = self
            .target_db
            .root
            .deleted_objects()
            .iter()
            .map(|d| (d.uuid, d.clone()))
            .collect::<HashMap<_, _>>();

        self.source_db
            .root
            .deleted_objects()
            .iter()
            .for_each(|source_do| {
                if let Some(td) = merged_deleted_objects_m.get_mut(&source_do.uuid) {
                    // Source deletion time is the latest and update the deletion time
                    if td.deletion_time < source_do.deletion_time {
                        td.deletion_time = source_do.deletion_time;
                    }
                } else {
                    // This deletion object is found only in source db's deleted objects and added to the merged_deleted_objects
                    merged_deleted_objects_m.insert(source_do.uuid, source_do.clone());
                }
            });

        // These are groups that exist in merged target db, but also found in merged_deleted_objects_m
        let mut deleted_object_groups: Vec<(Uuid, NaiveDateTime)> = vec![];

        // These are entries that exist in merged target db, but also found in merged_deleted_objects_m
        let mut deleted_object_entries: Vec<(Uuid, NaiveDateTime)> = vec![];

        // These are uuids from deleted objects that are not found in the merged target db
        let mut deleted_objects: Vec<DeletedObject> = vec![];

        for deleted @ DeletedObject { uuid, .. } in merged_deleted_objects_m.values() {
            // Collect all groups in DeletedObject that are also found in the merged target db
            if let Some(group) = self.target_db.root.group_by_id(&uuid) {
                deleted_object_groups.push((group.get_uuid(), group.last_modification_time()));
                continue;
            }
            // Collect all entries in DeletedObject that are also found in the merged target db
            if let Some(entry) = self.target_db.root.entry_by_id(&uuid) {
                deleted_object_entries.push((entry.get_uuid(), entry.last_modification_time()));
                continue;
            }

            // These are deleted objects for which we do not find a group or an entry in the merged target db
            // That means they are deleted objects both in source and in the target db
            deleted_objects.push(deleted.clone());
        }

        for (uuid, last_modification_time) in deleted_object_entries {
            if let Some(d) = merged_deleted_objects_m.get(&uuid) {
                if last_modification_time < d.deletion_time {
                    let name = self
                        .target_db
                        .root
                        .entry_by_id(&uuid)
                        .map_or_else(|| "".to_string(), |e| e.title());

                    self.target_db
                        .root
                        .remove_entry_on_merge_deleted_objects(uuid)?;
                    // Add to the deleted objects
                    deleted_objects.push(DeletedObject::with_uuid(uuid, None));

                    self.record_entry_deleted(&name, uuid);
                }
            }
        }

        while !deleted_object_groups.is_empty() {
            // Take the first member
            let data = deleted_object_groups.remove(0);

            let (uuid, last_modification_time) = data;

            if let Some(group) = self.target_db.root.group_by_id(&uuid) {
                if !group.sub_group_uuids().is_empty() {
                    let uuids: Vec<&Uuid> =
                        deleted_object_groups.iter().map(|(uuid, _)| uuid).collect();

                    // This group's sub group is in deleted_object_groups
                    if group
                        .sub_group_uuids()
                        .iter()
                        .find(|g| uuids.contains(g))
                        .is_some()
                    {
                        // Keep this deleted data till all the subgroups of this group are deleted
                        deleted_object_groups.push(data);
                        continue;
                    }
                }
            }

            if let Some(d) = merged_deleted_objects_m.get(&uuid) {
                // This group is modified later in one db after deletion in another db
                // Skip this group from deletion
                if last_modification_time > d.deletion_time {
                    continue;
                }

                // Ensure that the group is empty
                let group = self.target_db.root.group_by_id_ok(&uuid)?;
                if !group.entry_uuids().is_empty() || !group.sub_group_uuids().is_empty() {
                    continue;
                }

                let name = group.name().clone();

                // Delete permanently this group
                self.target_db
                    .root
                    .remove_group_on_merge_deleted_objects(uuid)?;

                // Add to the deleted objects
                deleted_objects.push(DeletedObject::with_uuid(uuid, None));

                self.record_group_deleted(&name, uuid);
            }
        }

        self.target_db.root.set_deleted_objects(deleted_objects);

        Ok(())
    }
}
