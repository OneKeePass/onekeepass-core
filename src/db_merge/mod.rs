use uuid::Uuid;

use crate::db_content::{Entry, Group, KeepassFile};

use crate::error::{Error, Result};

#[cfg(test)]
mod merge_tests;

struct Merger<'a> {
    source_db: &'a KeepassFile,
    target_db: &'a mut KeepassFile,
}

impl<'a> Merger<'a> {
    fn from(source_db: &'a KeepassFile, target_db: &'a mut KeepassFile) -> Self {
        Self {
            source_db,
            target_db,
        }
    }

    fn merge(&mut self) -> Result<()> {
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

        if source_root_group.get_uuid() == target_root_group.get_uuid() {
            // Source root group is newer than target root group
            if source_root_group.last_modification_time()
                > target_root_group.last_modification_time()
            {
                // Target root group's content is changed with source db's root group's content
                // This 'update_group' call updates the target group's modification time
                self.target_db.root.update_group(source_root_group.clone());
            } else {
                // Here we need to add the source root group to the target. Then the subsequent calls
                // will add all subgroups and entries to the target
            }
        }

        self.merge_groups(source_root_group)?;

        Ok(())
    }

    fn merge_entries(&mut self, source_group: &Group) -> Result<()> {
        let source_db_root = &self.source_db.root;

        for source_entry_uuid in source_group.entry_uuids().iter() {
            // Get the Entry using the uuid
            if let Some(source_entry) = source_db_root.entry_by_id(source_entry_uuid) {
                // First find out if we have an existing target entry for this source uuid in target db
                if let Some(target_entry) = self.target_db.root.entry_by_id(source_entry_uuid) {
                    // matching target entry is found

                    // Make sure the parent group is the same (Here we are assuming source_entry's group exists)
                    // TODO: Use 'location_changed' along with the uuid comparision
                    if target_entry.parent_group_uuid() != source_entry.parent_group_uuid() {
                        self.target_db.root.move_entry(
                            *target_entry.get_uuid(),
                            *source_entry.parent_group_uuid(),
                        )?;
                    }
                    // NOTE: If last_modification_time is updated, in 'move_entry',
                    // then we need to get 'last_modification_time' before 'move_entry' and pass that time
                    // in 'merge_entry'
                    // Merge source entry to target entry if required
                    self.merge_entry(source_entry)?;
                } else {
                    // No target entry is found. Create a new entry from source
                    let entry = source_entry.clone();
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
            .entry_by_id(source_entry.get_uuid())
            .ok_or("Expected target entry is not found")?;

        // If no change detected , we just return
        if target_entry.last_modification_time() == source_entry.last_modification_time() {
            // Should we do this test also source_entry == target_entry ?
            return Ok(());
        }

        let mut target_entry = target_entry.clone();

        if target_entry.last_modification_time() < source_entry.last_modification_time() {
            // Source entry is newer

            let mut to_entry_cloned = source_entry.clone();
            to_entry_cloned.update_modification_time();
            let from_entry_cloned = &target_entry;
            // target entry's histories are merged to the source entry's history
            // and source entry is stored in the target db
            self.merge_histories(from_entry_cloned, &mut to_entry_cloned)?;
        } else {
            // Target entry is newer

            let to_entry_cloned = &mut target_entry;
            let from_entry_cloned = source_entry.clone();
            // source entry's histories are merged to the target entry's history
            // and the target entry is stored in the target db
            self.merge_histories(&from_entry_cloned, to_entry_cloned)?;
        }
        
        Ok(())
    }

    fn merge_histories(&mut self, from_entry: &Entry, to_entry: &mut Entry) -> Result<()> {
        let mut from_entry_cloned = from_entry.clone();

        // history entries are expected to be in a descending order of last_modification_time

        // The create_histories adds the 'from_entry_cloned' entry to its history and returns histories
        let from_entry_histories = from_entry_cloned.create_histories();

        let mut to_entry_histories = to_entry.histories().clone();

        // Add the from entry histories to the to end of entry histories
        to_entry_histories.extend(from_entry_histories);

        // This ensures the combined histories are sorted with duplicates values are consecutive elements
        to_entry_histories.sort_by_key(|e| e.last_modification_time());

        // Retains only the first element of all duplicates
        to_entry_histories.dedup_by_key(|e| e.last_modification_time());

        // update_modification_time is already called
        to_entry.set_histories(&to_entry_histories);

        // target db should now have the updated entry
        self.target_db.root.insert_to_all_entries(to_entry.clone());

        Ok(())
    }

    fn merge_groups(&mut self, source_group: &Group) -> Result<()> {
        log::debug!(
            "merge_groups is called for source_group {} ",
            source_group.name
        );

        self.merge_entries(source_group)?;

        for source_child_group_uuid in source_group.sub_group_uuids().iter() {
            let source_child_group = self
                .source_db
                .root
                .group_by_id(source_child_group_uuid)
                .ok_or_else(|| "Source group is not found")?;

            // Find an existing group in the target db with this id
            // Using self.target_db.root.group_by_id_mut will result in
            // 'cannot borrow `self.target_db.root` as mutable more than once at a time' at
            // self.target_db.root.move_group
            if let Some(target_group) = self.target_db.root.group_by_id(source_child_group_uuid) {
                if target_group.parent_group_uuid() != source_child_group.parent_group_uuid() {
                    // TODO:
                    // Make sure that 'last_modification_time' remains the same even after move as
                    // this time is used in comparision in 'merge_group'

                    self.target_db.root.move_group(
                        *target_group.get_uuid(),
                        *source_child_group.parent_group_uuid(),
                    )?;
                }
                // Merge source group fields to target group fields if required
                self.merge_group(source_child_group)?;
            } else {
                // No target group is found. Create a new group from source
                // This cloned group's parent group is the same as the source_group's parent and
                // that group should be existing
                let group = source_child_group.clone();
                // Should last modification time be updated instead of using the source's time?
                self.target_db.root.insert_group(group)?;
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
            .group_by_id(source_group.get_uuid())
            .ok_or("Expected group is not found")?;

        // println!("source_group.times.last_modification_time {} with name {}",source_group.times.last_modification_time,source_group.name());
        // println!("target_group.times.last_modification_time {} with name {}",target_group.times.last_modification_time,target_group.name());

        // We do not change the target group data if it is newer than source
        if target_group.last_modification_time() >= source_group.last_modification_time() {
            return Ok(());
        }

        // let mut target_group = target_group.clone();
        // target_group.name = source_group.name.clone();

        // We change the target group data if it is old
        self.target_db.root.update_group(source_group.clone());

        Ok(())
    }

    fn set_group(&mut self, entry: &mut Entry, parent_group: &mut Group) {
        if entry.group_uuid == parent_group.uuid {
            return;
        }

        //self.target.root.move_entry(entry_uuid, new_parent_id)
    }

    // fn update(&mut self) {
    //     self.target.root.remove_all_binary_kvs_and_history_entries();
    // }
}

/*
fn merge_entries(&mut self, source_group: &Group, target_group: &mut Group) -> Result<()> {
        let source_db_root = &self.source_db.root;
        let target_db_root = &mut self.target_db.root;

        for source_entry_uuid in source_group.entry_uuids().iter() {
            if let Some(source_entry) = source_db_root.entry_by_id(source_entry_uuid) {
                // First find out if we have an existing target entry for this source
                if let Some(target_entry) = target_db_root.entry_by_id(source_entry_uuid).as_mut() {
                    // matching target entry is found

                    // Make sure the parent group is the same (Here we are assuming source_entry's group exists)
                    // TODO: Use 'location_changed' and the uuid comparision
                    if target_entry.parent_group_uuid() != source_entry.parent_group_uuid() {
                        target_db_root.move_entry(
                            *target_entry.get_uuid(),
                            *source_entry.parent_group_uuid(),
                        )?;
                    }

                    // Merge source entry to target entry if required
                } else {
                    // No target entry is found. Create a new entry from source
                    let entry = source_entry.clone();
                    target_db_root.insert_entry(entry)?;
                }
            }
        }

        Ok(())
    }

        fn merge_groups(&mut self, source_group: &Group,) -> Result<()> {
        let source_db_root = &self.source_db.root;
        let target_db_root = &mut self.target_db.root;

        for source_child_group_uuid in source_group.sub_group_uuids().iter() {
            let source_child_group = source_db_root
                .group_by_id(source_child_group_uuid)
                .ok_or_else(|| Error::NotFound(format!("Source group is not found")))?;

            // Find an existing group in the target db
            if let Some(target_group) = target_db_root.group_by_id(source_child_group_uuid).as_mut() {
                if target_group.parent_group_uuid() != source_child_group.parent_group_uuid() {
                    target_db_root
                        .move_group(*target_group.get_uuid(), *source_child_group.parent_group_uuid())?;
                }
                // Merge source group fields to target group fields if required
            } else {
                // No target group is found. Create a new group from source
                // This cloned group's parent group is the same as the source_group's parent and
                // that group should be existing
                let group = source_child_group.clone();
                target_db_root.insert_group(group)?;
            }

            //self.merge_groups(source_child_group)?;
        }

        Ok(())
    }

    // self.move_group(*target_group.get_uuid(), *source_child_group.parent_group_uuid());



    for source_child_entry_uuid in source_group.entry_uuids().iter() {
            let source_child_entry = self
                .source_db
                .root
                .entry_by_id(source_child_entry_uuid)
                .ok_or_else(|| "Expected source entry is not found")?;

            if let Some(target_entry) = self.target_db.root.entry_by_id(source_child_entry_uuid) {
                if target_entry.parent_group_uuid() != source_child_entry.parent_group_uuid() {
                    // NOTE: If last_modification_time is updated, in 'move_entry',
                    // then we need to get 'last_modification_time' before 'move_entry' and use that time
                    // in 'merge_entry'
                    self.target_db.root.move_entry(
                        *target_entry.get_uuid(),
                        *source_child_entry.parent_group_uuid(),
                    )?;
                }

                // merge entry
                // self.merge_entry(source_entry)
            } else {
                // No target entry is found. Create a new entry from source
                // This cloned entry's parent group is the same as the source_entry's parent and
                // that group should be existing
                let new_entry = source_child_entry.clone();
                // Should last modification time be updated instead of using the source's time?
                self.target_db.root.insert_entry(new_entry)?;
            }
        }

*/
