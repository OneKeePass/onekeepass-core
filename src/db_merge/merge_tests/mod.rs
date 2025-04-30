mod common;

use crate::error::Result;
use crate::{
    constants::{self, entry_keyvalue_key::TITLE, entry_type_name},
    db::{KdbxFile, NewDatabase},
    db_content::{standard_type_uuid_by_name, Entry, Group, KeepassFile},
    util,
};
use common::*;

use test_context::{test_context, TestContext};

use crate::db_merge::merger::Merger;

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
fn verify_updated_group(_ctx: &mut MergeTestContext) {
    let (mut source, mut target) = create_test_dbs_4();

    let source_db = source.keepass_main_content.as_mut().unwrap();

    util::test_clock::advance_by(1);

    if let Some(g1) = source_db.root.group_by_name_mut("group1") {
        g1.set_name("group1 changed").update_modification_time();
    }

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_ref().unwrap();
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
    let (mut source, mut target) = create_test_dbs_4();

    let source_db = source.keepass_main_content.as_mut().unwrap();

    // Create a new group
    let mut group3 = Group::with_parent(&source_db.root.root_uuid());
    group3.set_name("group3").update_modification_time();
    let g3_uuid = group3.get_uuid().clone();
    source_db.root.insert_group(group3).unwrap();

    // Need to enusre that the following group move is happens in some later time
    util::test_clock::advance_by(1);

    // Move the group1 as child of group3 in the source
    let g1_uuid = source_db
        .root
        .group_by_name("group1")
        .unwrap()
        .get_uuid()
        .clone();

    source_db.root.move_group(g1_uuid, g3_uuid).unwrap();

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_ref().unwrap();

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
    let (mut source, mut target) = create_test_dbs_4();

    let source_db = source.keepass_main_content.as_mut().unwrap();

    util::test_clock::advance_by(1);

    let new_root_name = "root name changed";

    if let Some(g1) = source_db.root.group_by_id_mut(&source_db.root.root_uuid()) {
        g1.set_name(new_root_name).update_modification_time();
    }

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_ref().unwrap();
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
    let (mut source, mut target) = create_test_dbs_4();

    let source_db = source.keepass_main_content.as_mut().unwrap();
    let target_db = target.keepass_main_content.as_ref().unwrap();

    // Need to enusre that the following entry move is happens in some later time
    util::test_clock::advance_by(1);

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

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_ref().unwrap();
    let g2 = target_db.root.group_by_name("group2").unwrap().clone();

    // let g2_uuid = g2.get_uuid().clone();
    // println!("-- Group {} and child entries AFTER {:?}",&g2_uuid, g2.entry_uuids() ) ;

    assert_eq!(g2.entry_uuids().len() == 2, true);
}

#[test_context(MergeTestContext)]
#[test]
fn verify_entry_simple_update(_ctx: &mut MergeTestContext) {
    let (mut source, mut target) = create_test_dbs_4();

    let source_db = source.keepass_main_content.as_mut().unwrap();
    let target_db = target.keepass_main_content.as_ref().unwrap();

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

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_ref().unwrap();
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
    let (source, mut target) = create_test_dbs_5();

    let target_db = target.keepass_main_content.as_mut().unwrap();

    println!(
        "target_db groups {:?}",
        target_db
            .root
            .get_all_groups(false)
            .iter()
            .map(|g| g.name.clone())
            .collect::<String>()
    );

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_mut().unwrap();

    println!(
        "target_db groups {:?}",
        target_db
            .root
            .get_all_groups(false)
            .iter()
            .map(|g| g.name.clone())
            .collect::<String>()
    );
}

#[test_context(MergeTestContext)]
#[test]
fn verify_merge_deletions(_ctx: &mut MergeTestContext) {
    let (mut source, mut target) = create_test_dbs_4();

    let source_db = source.keepass_main_content.as_mut().unwrap();
    let target_db = target.keepass_main_content.as_ref().unwrap();

    // Adbvance time to simulate detetion in different time
    util::test_clock::advance_by(1);

    let g2 = source_db.root.group_by_name("group2").unwrap().clone();
    let e2 = source_db
        .root
        .entry_by_matching_kv(TITLE, "entry2")
        .unwrap()
        .clone();

    delete_group_permanently(source_db, g2.get_uuid());

    // Before merge target should not have any deleted objtect
    let target_db_deleted_objects = target_db.root.deleted_objects();
    assert_eq!(target_db_deleted_objects.is_empty(), true);

    // Merge source to the target
    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_ref().unwrap();
    let target_db_deleted_objects = target_db.root.deleted_objects().clone();

    assert_eq!(target_db_deleted_objects.len() == 2, true);

    // Both group and its entry should be in the deleted objects of the target
    let r = target_db_deleted_objects
        .iter()
        .filter(|d| [*g2.get_uuid(), *e2.get_uuid()].contains(&d.uuid))
        .count();

    assert_eq!(r == 2, true);
}


#[test_context(MergeTestContext)]
#[test]
fn verify_merge_deletions_2(_ctx: &mut MergeTestContext) {
    let (mut source, _) = create_test_dbs_4();

    // Adbvance time to simulate creation of data in different time
    util::test_clock::advance_by(1);

    let source_db = source.keepass_main_content.as_mut().unwrap();
    let g2 = source_db.root.group_by_name("group2").unwrap().clone();
    let group = create_group(source_db, "group22", g2.get_uuid());
    let _ = create_entry(source_db, "entry22", group.get_uuid());

    // Now create target from this source
    let mut target = source.clone();

    // Adbvance time to simulate detetion in different time
    util::test_clock::advance_by(1);

    // Delete "group22" in source
    // This deletes group22 and its child "entry22"
    let source_db = source.keepass_main_content.as_mut().unwrap();
    delete_group_permanently(source_db, group.get_uuid());

    // source db has some deleted objects
    let source_db_deleted_objects = source_db.root.deleted_objects();
    //println!("Source Dos before {:?}", source_db_deleted_objects);
    assert_eq!(source_db_deleted_objects.len() == 2, true);

    // Adbvance time to simulate modification in different time
    util::test_clock::advance_by(1);

    // Modify entry entry22 in target
    let target_db = target.keepass_main_content.as_mut().unwrap();
    let _ = find_update_entry(target_db, "entry22", TITLE, "entry22 changed");

    // Now merge the source to the target
    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    // As entry22 is modified in target after the deletion time of group22 and entry22 in source
    // The whole group is retained 
    let target_db = target.keepass_main_content.as_ref().unwrap();    
    let target_db_deleted_objects = target_db.root.deleted_objects().clone();
    
    // println!(" Dos after {:?}", target_db_deleted_objects);

    assert_eq!(target_db_deleted_objects.len() == 0, true);

}

