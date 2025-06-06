use uuid::Uuid;

use crate::{
    constants::{entry_keyvalue_key::TITLE, entry_type_name},
    db::{KdbxFile, NewDatabase},
    db_content::{standard_type_uuid_by_name, Entry, Group, KeepassFile},
};
////
#[allow(dead_code)]

pub(crate) fn create_test_dbs_4() -> (KdbxFile, KdbxFile) {
    let ndb = NewDatabase::default();
    let mut source = ndb.create().unwrap();

    let source_db = source.keepass_main_content.as_mut().unwrap();

    let mut group1 = Group::with_parent(&source_db.root.root_uuid());
    let group1_uuid = group1.get_uuid().clone();
    group1.set_name("group1");
    source_db.root.insert_group(group1).unwrap();

    let mut group2 = Group::with_parent(&source_db.root.root_uuid());
    let group2_uuid = group2.get_uuid().clone();
    group2.set_name("group2");
    source_db.root.insert_group(group2).unwrap();

    let entry_type_uuid = standard_type_uuid_by_name(entry_type_name::LOGIN);
    let mut entry1 = Entry::new_blank_entry_by_type_id(entry_type_uuid, None, Some(&group1_uuid));
    entry1.entry_field.update_value(TITLE, "entry1");
    source_db.root.insert_entry(entry1).unwrap();

    let entry_type_uuid = standard_type_uuid_by_name(entry_type_name::LOGIN);
    let mut entry2 = Entry::new_blank_entry_by_type_id(entry_type_uuid, None, Some(&group2_uuid));
    entry2.entry_field.update_value(TITLE, "entry2");
    source_db.root.insert_entry(entry2).unwrap();

    let target = source.clone();

    (source, target)
}

pub(crate) fn create_test_dbs_5() -> (KdbxFile, KdbxFile) {
    let ndb = NewDatabase::default();
    let mut source = ndb.create().unwrap();

    let source_db = source.keepass_main_content.as_mut().unwrap();

    let mut group1 = Group::with_parent(&source_db.root.root_uuid());
    let group1_uuid = group1.get_uuid().clone();
    group1.set_name("group1");
    source_db.root.insert_group(group1).unwrap();

    let mut group2 = Group::with_parent(&source_db.root.root_uuid());
    let group2_uuid = group2.get_uuid().clone();
    group2.set_name("group2");
    source_db.root.insert_group(group2).unwrap();

    let entry_type_uuid = standard_type_uuid_by_name(entry_type_name::LOGIN);
    let mut entry1 = Entry::new_blank_entry_by_type_id(entry_type_uuid, None, Some(&group1_uuid));
    entry1.entry_field.update_value(TITLE, "entry1");
    source_db.root.insert_entry(entry1).unwrap();

    let entry_type_uuid = standard_type_uuid_by_name(entry_type_name::LOGIN);
    let mut entry2 = Entry::new_blank_entry_by_type_id(entry_type_uuid, None, Some(&group2_uuid));
    entry2.entry_field.update_value(TITLE, "entry2");
    source_db.root.insert_entry(entry2).unwrap();

    let ndb = NewDatabase::default();
    let mut target = ndb.create().unwrap();

    let target_db = target.keepass_main_content.as_mut().unwrap();

    let mut group1 = Group::with_parent(&target_db.root.root_uuid());
    let _group1_uuid = group1.get_uuid().clone();
    group1.set_name("group11");
    target_db.root.insert_group(group1).unwrap();

    (source, target)
}

pub(crate) fn create_group(
    keepassfile: &mut KeepassFile,
    name: &str,
    parent_group_uuid: &Uuid,
) -> Group {
    let mut group = Group::with_parent(parent_group_uuid);
    group.set_name(name);
    keepassfile.root.insert_group(group.clone()).unwrap();
    group
}

pub(crate) fn create_entry(keepassfile: &mut KeepassFile, title: &str, group_uuid: &Uuid) -> Entry {
    let entry_type_uuid = standard_type_uuid_by_name(entry_type_name::LOGIN);
    let mut entry = Entry::new_blank_entry_by_type_id(entry_type_uuid, None, Some(&group_uuid));
    entry.entry_field.update_value(TITLE, title);
    keepassfile.root.insert_entry(entry.clone()).unwrap();
    entry
}

pub(crate) fn delete_entry_permanently(keepassfile: &mut KeepassFile, entry_uuid: &Uuid) {
    // First move to recycle bin
    keepassfile
        .root
        .move_entry_to_recycle_bin(*entry_uuid)
        .unwrap();
    // Delete the entry that is moved to recycle bin
    keepassfile
        .root
        .remove_entry_permanently(*entry_uuid)
        .unwrap();
}

pub(crate) fn delete_group_permanently(keepassfile: &mut KeepassFile, group_uuid: &Uuid) {
    // First move to recycle bin
    keepassfile
        .root
        .move_group_to_recycle_bin(*group_uuid)
        .unwrap();
    // Delete the group that is moved to recycle bin
    keepassfile
        .root
        .remove_group_permanently(*group_uuid)
        .unwrap();
}

pub(crate) fn update_entry(
    keepassfile: &mut KeepassFile,
    entry: &mut Entry,
    key: &str,
    value: &str,
) {
    entry.entry_field.update_value(key, value);
    keepassfile.root.update_entry(entry.clone()).unwrap();
}

pub(crate) fn find_update_entry(
    keepassfile: &mut KeepassFile,
    title: &str,
    key: &str,
    value: &str,
) -> Entry {
    let mut entry = keepassfile
        .root
        .entry_by_matching_kv(TITLE, title)
        .unwrap()
        .clone();
    entry.entry_field.update_value(key, value);
    keepassfile.root.update_entry(entry.clone()).unwrap();
    entry
}

////

// Copied from /onekeepass-core/tests/common/mod.rs
pub(crate) mod dummy_key_store_service {
    use log::debug;
    use secstr::SecVec;
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use crate::{
        db_service::{self as kp_service, KeyStoreOperation, KeyStoreService},
        util,
    };

    pub fn init_key_main_store() {
        let kss = Arc::new(Mutex::new(KeyStoreServiceImpl::default()));
        // In case, we need to hold any reference at this module, then we need to Arc::clone
        // and use it
        KeyStoreOperation::init(kss);
        debug!("key_secure - key_main_store is initialized in init_key_main_store ");
    }

    pub fn init() {
        // init_logging();
        util::init_test_logging();
        init_key_main_store();
    }

    #[derive(Default)]
    pub struct KeyStoreServiceImpl {
        store: HashMap<String, SecVec<u8>>,
    }

    impl KeyStoreService for KeyStoreServiceImpl {
        fn store_key(&mut self, db_key: &str, data: Vec<u8>) -> kp_service::Result<()> {
            // On successful loading of database, the keys are encrypted with Aes GCM cipher
            // and the encryption key for keys is stored in the KeyChain for macOS.
            // For now in case of Windows and Linux, we keep it locally

            debug!("store_key is called and data size {}", data.len());
            self.store.insert(db_key.into(), SecVec::new(data));
            debug!("Encrypted key is stored for other cfg");
            Ok(())
        }

        fn get_key(&self, db_key: &str) -> Option<Vec<u8>> {
            self.store.get(db_key).map(|v| Vec::from(v.unsecure()))
        }

        fn delete_key(&mut self, db_key: &str) -> kp_service::Result<()> {
            self.store.remove(db_key);
            debug!("Keys are deleted..");
            Ok(())
        }

        fn copy_key(&mut self, source_db_key: &str, target_db_key: &str) -> kp_service::Result<()> {
            if let Some(source_db_key) = self.store.get(source_db_key).cloned() {
                self.store.insert(target_db_key.into(), source_db_key);
                debug!("Keys are copied...");
            }
            Ok(())
        }
    }
}
