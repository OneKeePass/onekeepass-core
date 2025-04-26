mod common;

use crate::{
    constants::{self, entry_keyvalue_key::TITLE, entry_type_name},
    db::{KdbxFile, NewDatabase},
    db_content::{standard_type_uuid_by_name, Entry, Group, KeepassFile},
    util,
};

use common::*;

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

#[test_context(MergeTestContext)]
#[test]
fn verify_new_group(_ctx: &mut MergeTestContext) {
    let (mut source, mut target) = create_test_dbs_4();

    let source_db = source.keepass_main_content.as_mut().unwrap();
    let target_db = target.keepass_main_content.as_mut().unwrap();

    let mut group1 = Group::with_parent(&source_db.root.root_uuid());
    group1.set_name("S_G1_db1");
    source_db.root.insert_group(group1).unwrap();

    let mut group1 = Group::with_parent(&target_db.root.root_uuid());
    group1.set_name("T_G1_db2");
    target_db.root.insert_group(group1).unwrap();

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let groups = target
        .keepass_main_content
        .as_ref()
        .unwrap()
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
fn verify_new_group_1(_ctx: &mut MergeTestContext) {
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

    assert_eq!(g1_parent_uuid, &g3_uuid);
}

#[test_context(MergeTestContext)]
#[test]
fn verify_root_group_updated(_ctx: &mut MergeTestContext) {
    let (mut source_db, mut target_db) = create_test_dbs_1();

    util::test_clock::advance_by(1);

    let new_root_name = "root name changed";

    if let Some(g1) = source_db.root.group_by_id_mut(&source_db.root.root_uuid()) {
        g1.set_name(new_root_name).update_modification_time();
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
    assert_eq!(groups.contains(&new_root_name.to_string()), true);
}

#[test_context(MergeTestContext)]
#[test]
fn verify_entry_location_changed(_ctx: &mut MergeTestContext) {
    let (mut source_db, mut target_db) = create_test_dbs_2();

    // Move the entry to group2 as child in source db
    let g2 = source_db.root.group_by_name("group2").unwrap().clone();

    let g2_uuid = g2.get_uuid().clone();

    // println!("-- Group {} and child entries BEFORE {:?}",&g2_uuid, g2.entry_uuids() ) ;

    let e1_uuid = source_db
        .root
        .entry_by_matching_kv(TITLE, "entry1")
        .unwrap()
        .get_uuid()
        .clone();

    // println!("-- entry 1 uuid is {}",&e1_uuid);

    source_db.root.move_entry(e1_uuid, g2_uuid).unwrap();

    // before merge target db's "group2" should have one entry
    let g2 = target_db.root.group_by_name("group2").unwrap().clone();

    //let g2_uuid = g2.get_uuid().clone();
    // println!("-- Group {} and child entries AFTER {:?}",&g2_uuid, g2.entry_uuids() ) ;

    assert_eq!(g2.entry_uuids().len() == 1, true);

    Merger::from(&source_db, &mut target_db).merge().unwrap();

    let g2 = target_db.root.group_by_name("group2").unwrap().clone();

    // let g2_uuid = g2.get_uuid().clone();
    // println!("-- Group {} and child entries AFTER {:?}",&g2_uuid, g2.entry_uuids() ) ;

    assert_eq!(g2.entry_uuids().len() == 2, true);
}

#[test_context(MergeTestContext)]
#[test]
fn verify_entry_simple_update(_ctx: &mut MergeTestContext) {
    let (mut source_db, mut target_db) = create_test_dbs_2();

    let mut e1 = source_db
        .root
        .entry_by_matching_kv(TITLE, "entry1")
        .unwrap()
        .clone();

    let e1_uuid = e1.get_uuid().clone();

    let before_histories = e1.histories().clone();
    // println!("before_histories {:?}", &before_histories.len());
    assert_eq!(before_histories.len() == 0, true);

    util::test_clock::advance_by(1);

    e1.entry_field.update_value(TITLE, "entry1 changed");
    source_db.root.update_entry(e1.clone()).unwrap();

    let e1 = target_db.root.entry_by_id(&e1_uuid).unwrap().clone();
    let target_entry_before_histories = e1.histories().clone();
    // println!("target target_entry_before_histories {:?}", &target_entry_before_histories.len());
    assert_eq!(target_entry_before_histories.len() == 0, true);

    Merger::from(&source_db, &mut target_db).merge().unwrap();

    let e1 = target_db.root.entry_by_id(&e1_uuid).unwrap().clone();
    let target_entry_after_histories = e1.histories().clone();
    // println!("target target_entry_after_histories {:?}", &target_entry_after_histories.len());
    assert_eq!(target_entry_after_histories.len() == 1, true);
}

#[test_context(MergeTestContext)]
#[test]
fn verify_meta_add_custom_icon(_ctx: &mut MergeTestContext) {
    let (mut source, mut target) = create_test_dbs_4();

    let source_db = source.keepass_main_content.as_mut().unwrap();
    let target_db = target.keepass_main_content.as_ref().unwrap();

    let dummy_icon_data: Vec<u8> = vec![1, 2, 55, 67];
    source_db.meta.add_custom_icon(&dummy_icon_data);

    assert_eq!(target_db.meta.all_custom_icons().len() == 0, true);

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    assert_eq!(
        target.keepass_main_content().meta.all_custom_icons().len() == 1,
        true
    );
}

#[test_context(MergeTestContext)]
#[test]
fn verify_merge_different_databases(_ctx: &mut MergeTestContext) {

    let (mut source, mut target) = create_test_dbs_5();

    let source_db = source.keepass_main_content.as_mut().unwrap();
    let target_db = target.keepass_main_content.as_mut().unwrap();

    println!("target_db groups {:?}" , target_db.root.get_all_groups(false).iter().map(|g| g.name.clone()).collect::<String>());

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_mut().unwrap();

    println!("target_db groups {:?}" , target_db.root.get_all_groups(false).iter().map(|g| g.name.clone()).collect::<String>());

}


