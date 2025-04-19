mod common;

use crate::{
    db::NewDatabase,
    db_content::{Group, KeepassFile},
    util,
};
use common::dummy_key_store_service;
use test_context::{test_context, TestContext};

use super::Merger;

struct MergeTestContext {}

impl TestContext for MergeTestContext {
    fn setup() -> MergeTestContext {
        dummy_key_store_service::init();
        MergeTestContext {}
    }

    fn teardown(self) {
        // Perform any teardown you wish.
    }
}

// Just cread source db and target db as clone of source
fn create_test_dbs() -> (KeepassFile, KeepassFile) {
    let ndb = NewDatabase::default();
    let source = ndb.create().unwrap();
    let target = source.clone();
    let source_db = source.keepass_main_content.unwrap();
    let target_db = target.keepass_main_content.unwrap();
    (source_db, target_db)
}

// Source db and target dbs have same groups
fn create_test_dbs_1() -> (KeepassFile, KeepassFile) {
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

#[test_context(MergeTestContext)]
#[test]
fn verify_new_group(_ctx: &mut MergeTestContext) {
    // let d1 = now_utc();
    // println!("d1 is {}", d1);
    // util::test_clock::init_datetime(2020, 1, 1, 12, 10, 20);
    // let d2 = now_utc();
    // println!("d2 is {}", d2);
    // util::test_clock::advance_by(50);
    // let d3 = now_utc();
    // println!("d3 is {}", d3);

    // let ndb = NewDatabase::default();
    // let source = ndb.create().unwrap();
    // let target = source.clone();

    // let source_db = &mut source.keepass_main_content.unwrap();
    // println!("Root uuid is {:?}", &source_db.root.root_uuid());

    // let target_db = &mut target.keepass_main_content.unwrap();

    let (mut source_db, mut target_db) = create_test_dbs();

    let mut group1 = Group::with_parent(&source_db.root.root_uuid());
    group1.set_name("S_G1_db1");
    source_db.root.insert_group(group1).unwrap();

    // let groups = kc1.root.get_all_groups(false);
    // println!( "groups are {:?}", &groups);

    let mut group1 = Group::with_parent(&target_db.root.root_uuid());
    group1.set_name("T_G1_db2");
    target_db.root.insert_group(group1).unwrap();

    let mut merger = Merger::from(&source_db, &mut target_db);

    merger.merge().unwrap();

    let groups = source_db
        .root
        .get_all_groups(false)
        .iter()
        .map(|g| g.name.clone())
        .collect::<Vec<String>>();

    // println!("groups in source db are {:?}", &groups);

    let groups = target_db
        .root
        .get_all_groups(false)
        .iter()
        .map(|g| g.name.clone())
        .collect::<Vec<String>>();

    // println!("groups in final target db are {:?}", &groups);

    assert_eq!(groups.contains(&"S_G1_db1".to_string()), true);
}

#[test_context(MergeTestContext)]
#[test]
fn verify_updated_group(_ctx: &mut MergeTestContext) {
    let (mut source_db, mut target_db) = create_test_dbs_1();

    util::test_clock::advance_by(1);

    if let Some(g1) = source_db.root.group_by_name_mut("group1") {
        g1.set_name("group1 changed").update_modification_time();
    }

    let mut merger = Merger::from(&source_db, &mut target_db);
    merger.merge().unwrap();

    let groups = target_db
        .root
        .get_all_groups(false)
        .iter()
        .map(|g| g.name.clone())
        .collect::<Vec<String>>();

    // println!("groups in final target db are {:?}", &groups);

    assert_eq!(groups.contains(&"group1 changed".to_string()), true);
}

#[test_context(MergeTestContext)]
#[test]
fn verify_group_location_changed(_ctx: &mut MergeTestContext) {
    let (mut source_db, mut target_db) = create_test_dbs_1();

    // Create a new group
    let mut group3 = Group::with_parent(&source_db.root.root_uuid());
    group3.set_name("group3").update_modification_time();
    let g3_uuid = group3.get_uuid().clone();
    source_db.root.insert_group(group3).unwrap();

    // Move the group1 as child of group3
    let g1_uuid = source_db
        .root
        .group_by_name("group1")
        .unwrap()
        .get_uuid()
        .clone();
    source_db.root.move_group(g1_uuid, g3_uuid).unwrap();

    Merger::from(&source_db, &mut target_db).merge().unwrap();

    let g1_parent_uuid = target_db
        .root
        .group_by_id(&g1_uuid)
        .unwrap()
        .parent_group_uuid();

    // println!("g3_uuid is {}, g1_parent is {}  ", g3_uuid, g1_parent);

    assert_eq!(g1_parent_uuid,&g3_uuid);
}

#[test_context(MergeTestContext)]
#[test]
fn verify_root_group_updated(_ctx: &mut MergeTestContext) {
    let (mut source_db, mut target_db) = create_test_dbs_1();

    util::test_clock::advance_by(1);

    if let Some(g1) = source_db.root.group_by_id_mut(&source_db.root.root_uuid()) {
        g1.set_name("root name changed").update_modification_time();
    }

    let mut merger = Merger::from(&source_db, &mut target_db);
    merger.merge().unwrap();

    let groups = target_db
        .root
        .get_all_groups(false)
        .iter()
        .map(|g| g.name.clone())
        .collect::<Vec<String>>();

    println!("groups in final target db are {:?}", &groups);

}
