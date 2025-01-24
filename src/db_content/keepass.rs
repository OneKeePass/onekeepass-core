use std::collections::HashMap;
use uuid::Uuid;

use crate::db_content::{AttachmentHashValue, Entry, Meta, Root};

use crate::error::{self, Result};

use super::EntryType;

#[derive(Debug,Clone)]
pub struct KeepassFile {
    pub(crate) meta: Meta,
    pub(crate) root: Root,
}

impl KeepassFile {
    pub fn new() -> KeepassFile {
        KeepassFile {
            meta: Meta::new(),
            root: Root::new(),
        }
    }

    pub fn empty_trash(&mut self) -> Result<()> {
        // The recycle_bin_uuid from the root itself used for now till we move the root 'recycle_bin_uuid'
        // to meta 'recycle_bin_uuid' instead of using share_meta_to_root and share_root_to_meta
        self.root.empty_trash(self.root.recycle_bin_uuid())
    }

    // TODO:
    // Instead of this way of copying recycle_bin_uuid etc to 'root' and back, all methods in 'root' that
    // depend on 'meta' fields should be implemented in 'meta' and then call 'root' method
    // with that data. For example,  'get_all_entries' and other move to recycle methods in 'root'
    // should accept the relevant meta field and then use.

    // See 'empty_trash' method for additional comments

    // TODO: For now we are just delegating to 'root' and need to pass excluded group ids (recycle group id and template group id )
    pub fn get_all_entries<'a>(&'a self, exclude: bool) -> Vec<&'a Entry> {
        self.root.get_all_entries(exclude)
    }

    pub fn collect_all_active_entries<'a>(&'a self) -> Vec<&'a Entry> {
        self.root
            .collect_all_active_entries(self.root.recycle_bin_uuid())
    }

    pub fn collect_favorite_entries<'a>(&'a self) -> Vec<&'a Entry> {
        self.root
            .collect_favorite_entries(self.root.recycle_bin_uuid())
    }

    pub fn deleted_entry_uuids(&self) -> Vec<Uuid> {
        // TODO: Pass recycle bin group uuid from meta to root
        self.root.deleted_entry_uuids()
    }

    pub fn deleted_group_uuids(&self) -> Vec<Uuid> {
        // TODO: Pass recycle bin group uuid from meta to root
        self.root.deleted_group_uuids()
    }

    // pub fn delete_custom_entry_type(&mut self, entry_type_name: &str) -> Result<()> {
    //     if self.root.custom_entry_type_entries(entry_type_name).len() != 0 {
    //         //error::Error::DataError("Entry type can not be deleted as some entries are of this type")
    //         return Err(error::Error::CustomEntryTypeInUse);
    //     }
    //     else {
    //         return Ok(self.meta.delete_custom_entry_type(entry_type_name));
    //     }
    // }

    pub fn delete_custom_entry_type_by_id(
        &mut self,
        entry_type_uuid: &Uuid,
    ) -> Result<Option<EntryType>> {
        if self
            .root
            .custom_entry_type_entries_by_id(entry_type_uuid)
            .len()
            != 0
        {
            //error::Error::DataError("Entry type can not be deleted as some entries are of this type")
            return Err(error::Error::CustomEntryTypeInUse);
        } else {
            return Ok(self.meta.delete_custom_entry_type_by_id(entry_type_uuid));
        }
    }

    // Ensures that the meta share for the newly created entry is initialized properly
    pub fn insert_entry(&mut self, mut entry: Entry) -> Result<()> {
        entry.meta_share = self.meta.clone_meta_share();
        self.root.insert_entry(entry)
    }

    // Called after reading xml content
    pub fn after_xml_reading(
        &mut self,
        attachment_hash_indexed: &HashMap<i32, (AttachmentHashValue, usize)>,
    ) {
        // Need to read any meta specific custom data first
        self.meta.copy_from_custom_data();

        // IMPORTANT:We need to set attachment hashes in all entries read from xml
        self.root.set_attachment_hashes(attachment_hash_indexed);

        // The uuid of a group that is identified as recycle group and this is available only as child
        // element of Meta element
        if self.meta.recycle_bin_uuid != Uuid::default() {
            self.root.set_recycle_bin_uuid(self.meta.recycle_bin_uuid);
            //self.root.adjust_special_groups_order();
        }

        // This sets any relavant fields in the group based on the custom data
        self.root.custom_data_to_groups();

        //self.root.custom_data_to_entries();
        self.root.entries_after_xml_reading(&self.meta);

        self.root.adjust_auto_open_group_entries();
    }

    // Called before writing xml content
    pub fn before_xml_writing(&mut self, hash_index_ref: &HashMap<AttachmentHashValue, i32>) {
        self.meta.copy_to_custom_data();

        // Need to set the new index_refs of all attachments after writing the binaries
        self.root.set_attachment_index_refs(hash_index_ref);

        // Any entries related one
        self.root.entries_before_xml_writing();

        // When a recycle group is created under root group, we need to set it in Meta so that
        // it can be written as child element of Meta and subsequent reading of db
        // includes this special group uuid
        if self.root.recycle_bin_uuid() != Uuid::default() {
            self.meta.recycle_bin_uuid = self.root.recycle_bin_uuid();
            self.meta.recycle_bin_enabled = true;
        }

        // This copies any custom data specific field information back to custom data before xml writing
        self.root.groups_to_custom_data();

        // Sets the new version
        //self.meta.custom_data.set_internal_version(&INTERNAL_VERSION.to_string());
    }
}
