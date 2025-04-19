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

        if &self.source_db.root.root_uuid() == &self.target_db.root.root_uuid() {}
    

        self.merge_groups(source_root_group)?;

        Ok(())
    }

    fn merge_entries(&mut self, source_group: &Group) -> Result<()> {
        let source_db_root = &self.source_db.root;
        //let target_db_root = &mut self.target_db.root;

        for source_entry_uuid in source_group.entry_uuids().iter() {
            if let Some(source_entry) = source_db_root.entry_by_id(source_entry_uuid) {
                // First find out if we have an existing target entry for this source
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

    fn merge_entry(&mut self, source_entry: &Entry) -> Result<()> {
        let target_entry = self
            .target_db
            .root
            .entry_by_id(source_entry.get_uuid())
            .ok_or("Expected entry is not found")?;
        if target_entry.times.last_modification_time == source_entry.times.last_modification_time {
            return Ok(());
        }

        let mut target_entry = target_entry.clone();
        target_entry.tags = source_entry.tags.clone();
        self.target_db.root.update_entry(target_entry)?;

        Ok(())
    }

    fn merge_groups(&mut self, source_group: &Group) -> Result<()> {
        log::debug!(
            "merge_groups is called for source_group {} ",
            source_group.name
        );

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
        if target_group.times.last_modification_time >= source_group.times.last_modification_time {
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
*/
