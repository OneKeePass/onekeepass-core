use crate::{
    constants::{entry_keyvalue_key::TITLE, entry_type_name},
    db::{KdbxFile, NewDatabase},
    db_content::{standard_type_uuid_by_name, Entry, Group, KeepassFile},util,
};
////

// Just cread source db and target db as clone of source
pub(crate) fn create_test_dbs() -> (KeepassFile, KeepassFile) {
    let ndb = NewDatabase::default();
    let source = ndb.create().unwrap();
    let target = source.clone();
    let source_db = source.keepass_main_content.unwrap();
    let target_db = target.keepass_main_content.unwrap();
    (source_db, target_db)
}

// Source db and target dbs have same groups
pub(crate) fn create_test_dbs_1() -> (KeepassFile, KeepassFile) {
    let ndb = NewDatabase::default();
    let source = ndb.create().unwrap();

    let mut source_db = source.keepass_main_content.unwrap();

    let mut group1 = Group::with_parent(&source_db.root.root_uuid());
    group1.set_name("group1");
    source_db.root.insert_group(group1).unwrap();

    let mut group1 = Group::with_parent(&source_db.root.root_uuid());
    group1.set_name("group2");
    source_db.root.insert_group(group1).unwrap();

    let target_db = source_db.clone();

    (source_db, target_db)
}

pub(crate) fn create_test_dbs_2() -> (KeepassFile, KeepassFile) {
    let ndb = NewDatabase::default();
    let source = ndb.create().unwrap();

    let mut source_db = source.keepass_main_content.unwrap();

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

    let target_db = source_db.clone();

    (source_db, target_db)
}

pub(crate) fn create_test_dbs_3() -> (KeepassFile, KeepassFile) {
    let (mut source_db, mut target_db) = create_test_dbs_2();

    let e1 = source_db
    .root
    .entry_by_matching_kv_mut(TITLE, "entry1")
    .unwrap();

    util::test_clock::advance_by(1);

    e1.entry_field.update_value(TITLE, "entry1 changed");

    (source_db, target_db)
}

pub(crate) fn create_test_dbs_4() -> (KdbxFile,KdbxFile) {
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

pub(crate) fn create_test_dbs_5() -> (KdbxFile,KdbxFile) {
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
    let group1_uuid = group1.get_uuid().clone();
    group1.set_name("group11");
    target_db.root.insert_group(group1).unwrap();

    (source, target)

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
