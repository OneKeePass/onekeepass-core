// Tests for custom-icon handling during database merge:
//
//   - content-hash dedup with source→target UUID remap
//   - target-wins on UUID collision (matches KeePassXC)
//   - history-entry remap
//   - group remap
//   - no-op equality, pure-add, different-DB path

use uuid::Uuid;

use test_context::{test_context, TestContext};

use crate::constants::entry_keyvalue_key::TITLE;
use crate::db_content::Icon;
use crate::db_merge::merger::Merger;
use crate::util;

use super::common::{
    create_group, create_test_dbs_4, create_test_dbs_5, dummy_key_store_service,
};

struct IconMergeCtx {}

impl TestContext for IconMergeCtx {
    fn setup() -> IconMergeCtx {
        dummy_key_store_service::init();
        IconMergeCtx {}
    }
    fn teardown(self) {}
}

// Adds an Icon with caller-chosen UUID and bytes; returns the UUID. The
// existing Meta::add_custom_icon test helper always allocates a fresh
// random UUID, which is the wrong shape for these tests where we need
// either matching or mismatched UUIDs across source/target.
fn push_icon(
    keepass: &mut crate::db_content::KeepassFile,
    uuid: Uuid,
    data: Vec<u8>,
) {
    keepass.meta.custom_icons.icons.push(Icon {
        uuid,
        data,
        name: None,
        last_modification_time: util::now_utc(),
    });
}

fn icon_count(keepass: &crate::db_content::KeepassFile) -> usize {
    keepass.meta.custom_icons.icons.len()
}

// 1. Source and target each have the same icon bytes under different UUIDs.
//    A source entry references the source UUID. After merge:
//       - target's icon list still has only one icon (no duplicate),
//       - the merged-in entry's custom_icon_uuid points at target's UUID.
#[test_context(IconMergeCtx)]
#[test]
fn content_dedup_remaps_entry_icon(_ctx: &mut IconMergeCtx) {
    let (mut source, mut target) = create_test_dbs_4();

    let bytes = b"PNG-BYTES-A".to_vec();
    let target_icon_uuid = Uuid::new_v4();
    let source_icon_uuid = Uuid::new_v4();
    assert_ne!(target_icon_uuid, source_icon_uuid);

    push_icon(
        target.keepass_main_content.as_mut().unwrap(),
        target_icon_uuid,
        bytes.clone(),
    );
    push_icon(
        source.keepass_main_content.as_mut().unwrap(),
        source_icon_uuid,
        bytes.clone(),
    );

    // Point an existing source entry at source's icon.
    let source_db = source.keepass_main_content.as_mut().unwrap();
    let mut e1 = source_db
        .root
        .entry_by_matching_kv(TITLE, "entry1")
        .unwrap()
        .clone();
    let e1_uuid = e1.get_uuid();
    e1.custom_icon_uuid = Some(source_icon_uuid);
    util::test_clock::advance_by(1);
    e1.update_modification_time_now();
    source_db.root.update_entry(e1).unwrap();

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_ref().unwrap();
    assert_eq!(icon_count(target_db), 1, "duplicate icon was kept");
    assert_eq!(
        target_db.meta.custom_icons.icons[0].uuid, target_icon_uuid,
        "target's icon UUID should survive; source's UUID should fold into it"
    );

    let merged_entry = target_db.root.entry_by_id(&e1_uuid).unwrap();
    assert_eq!(
        merged_entry.custom_icon_uuid,
        Some(target_icon_uuid),
        "source entry's custom_icon_uuid should be remapped to target's UUID"
    );
}

// 2. Both sides have an icon under the SAME UUID but with different bytes.
//    Follow KeePassXC: target wins; target's bytes are kept and source's
//    bytes are discarded. No remap entry is needed.
#[test_context(IconMergeCtx)]
#[test]
fn uuid_collision_target_wins(_ctx: &mut IconMergeCtx) {
    let (mut source, mut target) = create_test_dbs_4();

    let shared_uuid = Uuid::new_v4();
    push_icon(
        target.keepass_main_content.as_mut().unwrap(),
        shared_uuid,
        b"TARGET-BYTES".to_vec(),
    );
    util::test_clock::advance_by(1);
    push_icon(
        source.keepass_main_content.as_mut().unwrap(),
        shared_uuid,
        b"SOURCE-BYTES".to_vec(),
    );

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_ref().unwrap();
    assert_eq!(icon_count(target_db), 1);
    assert_eq!(
        target_db.meta.custom_icons.icons[0].data,
        b"TARGET-BYTES".to_vec(),
        "target's bytes should not be replaced on UUID collision"
    );
}

// 3. The source entry has its current custom_icon_uuid AND a history entry
//    pointing at the same source UUID. The dedup remap must rewrite both.
#[test_context(IconMergeCtx)]
#[test]
fn history_entry_icon_is_remapped(_ctx: &mut IconMergeCtx) {
    let (mut source, mut target) = create_test_dbs_4();

    let bytes = b"PNG-BYTES-B".to_vec();
    let target_icon_uuid = Uuid::new_v4();
    let source_icon_uuid = Uuid::new_v4();
    push_icon(
        target.keepass_main_content.as_mut().unwrap(),
        target_icon_uuid,
        bytes.clone(),
    );
    push_icon(
        source.keepass_main_content.as_mut().unwrap(),
        source_icon_uuid,
        bytes.clone(),
    );

    // Take source entry1, assign source icon, do an update that pushes the
    // previous state into history. We do this twice so the entry has a
    // current state AND a history state both carrying source_icon_uuid.
    let source_db = source.keepass_main_content.as_mut().unwrap();
    let mut e1 = source_db
        .root
        .entry_by_matching_kv(TITLE, "entry1")
        .unwrap()
        .clone();
    let e1_uuid = e1.get_uuid();
    e1.custom_icon_uuid = Some(source_icon_uuid);
    util::test_clock::advance_by(1);
    e1.update_modification_time_now();
    source_db.root.update_entry(e1).unwrap();

    // Second update so a history element exists. We re-fetch to pick up
    // the entry's current state (with last update applied) so the history
    // accumulates the prior version verbatim.
    let mut e1 = source_db
        .root
        .entry_by_matching_kv(TITLE, "entry1")
        .unwrap()
        .clone();
    e1.entry_field.update_value(TITLE, "entry1-v2");
    util::test_clock::advance_by(1);
    e1.update_modification_time_now();
    source_db.root.update_entry(e1).unwrap();

    let e1_after = source_db.root.entry_by_id(&e1_uuid).unwrap();
    assert_eq!(e1_after.custom_icon_uuid, Some(source_icon_uuid));
    assert!(
        !e1_after.history.entries.is_empty(),
        "test setup: source entry must have at least one history record"
    );
    let history_count_before_merge = e1_after.history.entries.len();
    let history_ref_count_before = e1_after
        .history
        .entries
        .iter()
        .filter(|h| h.custom_icon_uuid == Some(source_icon_uuid))
        .count();
    assert!(
        history_ref_count_before > 0,
        "test setup: at least one history record must reference source_icon_uuid"
    );

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_ref().unwrap();
    assert_eq!(icon_count(target_db), 1);
    let merged = target_db.root.entry_by_id(&e1_uuid).unwrap();
    assert_eq!(merged.custom_icon_uuid, Some(target_icon_uuid));
    assert_eq!(
        merged.history.entries.len(),
        history_count_before_merge,
        "history length should be preserved (or grown) across merge"
    );
    // Every history element that previously referenced source_icon_uuid
    // must now reference target_icon_uuid; none should still point at
    // the old source UUID.
    for h in &merged.history.entries {
        assert_ne!(
            h.custom_icon_uuid,
            Some(source_icon_uuid),
            "history entry should not retain source_icon_uuid after dedup"
        );
    }
}

// 4. No-op: source and target start identical (create_test_dbs_4 clones one).
//    Merge produces no icon changes and no remap effects.
#[test_context(IconMergeCtx)]
#[test]
fn no_op_when_icons_identical(_ctx: &mut IconMergeCtx) {
    let (mut source, mut target) = create_test_dbs_4();

    let shared_uuid = Uuid::new_v4();
    let bytes = b"PNG-BYTES-C".to_vec();
    push_icon(
        source.keepass_main_content.as_mut().unwrap(),
        shared_uuid,
        bytes.clone(),
    );
    push_icon(
        target.keepass_main_content.as_mut().unwrap(),
        shared_uuid,
        bytes.clone(),
    );

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_ref().unwrap();
    assert_eq!(icon_count(target_db), 1);
    assert_eq!(target_db.meta.custom_icons.icons[0].uuid, shared_uuid);
    assert_eq!(target_db.meta.custom_icons.icons[0].data, bytes);
}

// 5. Pure add — source has an icon that target lacks. Target gains it with
//    UUID and bytes unchanged.
#[test_context(IconMergeCtx)]
#[test]
fn pure_add_new_icon(_ctx: &mut IconMergeCtx) {
    let (mut source, mut target) = create_test_dbs_4();

    let new_uuid = Uuid::new_v4();
    let bytes = b"PNG-BYTES-D".to_vec();
    push_icon(
        source.keepass_main_content.as_mut().unwrap(),
        new_uuid,
        bytes.clone(),
    );

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_ref().unwrap();
    assert_eq!(icon_count(target_db), 1);
    assert_eq!(target_db.meta.custom_icons.icons[0].uuid, new_uuid);
    assert_eq!(target_db.meta.custom_icons.icons[0].data, bytes);
}

// 6. Group remap — source group has custom_icon_uuid = Us, target has
//    matching bytes under Ut. After merge, the inserted group in target
//    references Ut.
#[test_context(IconMergeCtx)]
#[test]
fn group_icon_is_remapped(_ctx: &mut IconMergeCtx) {
    let (mut source, mut target) = create_test_dbs_4();

    let bytes = b"PNG-BYTES-E".to_vec();
    let target_icon_uuid = Uuid::new_v4();
    let source_icon_uuid = Uuid::new_v4();
    push_icon(
        target.keepass_main_content.as_mut().unwrap(),
        target_icon_uuid,
        bytes.clone(),
    );
    push_icon(
        source.keepass_main_content.as_mut().unwrap(),
        source_icon_uuid,
        bytes.clone(),
    );

    // Build a NEW group on source that target doesn't have, with the
    // custom icon assigned, so the merge takes the "insert new group"
    // path (which is where remap_group_icon fires).
    let source_db = source.keepass_main_content.as_mut().unwrap();
    let root_uuid = source_db.root.root_uuid();
    let new_group = create_group(source_db, "iconed-group", &root_uuid);
    let new_group_uuid = new_group.get_uuid();
    {
        let g = source_db.root.group_by_id_mut(&new_group_uuid).unwrap();
        g.custom_icon_uuid = Some(source_icon_uuid);
        util::test_clock::advance_by(1);
        g.update_modification_time_now();
    }

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_ref().unwrap();
    assert_eq!(icon_count(target_db), 1);
    let merged_group = target_db.root.group_by_id(&new_group_uuid).unwrap();
    assert_eq!(
        merged_group.custom_icon_uuid,
        Some(target_icon_uuid),
        "new group inserted from source should have its custom_icon_uuid remapped to target's UUID"
    );
}

// 7. Different-databases path (different root UUIDs). The cross-DB branch
//    calls Meta::merge_from_different_db, which runs the same custom_icons
//    dedup helper as the same-DB path and produces an icon_remap that the
//    merger threads into every clone site. The dedup invariant therefore
//    holds across unrelated DBs too.
#[test_context(IconMergeCtx)]
#[test]
fn remap_applies_on_different_databases_path(_ctx: &mut IconMergeCtx) {
    let (mut source, mut target) = create_test_dbs_5();

    let bytes = b"PNG-BYTES-F".to_vec();
    let target_icon_uuid = Uuid::new_v4();
    let source_icon_uuid = Uuid::new_v4();
    push_icon(
        target.keepass_main_content.as_mut().unwrap(),
        target_icon_uuid,
        bytes.clone(),
    );
    push_icon(
        source.keepass_main_content.as_mut().unwrap(),
        source_icon_uuid,
        bytes.clone(),
    );

    let source_db = source.keepass_main_content.as_mut().unwrap();
    let mut e1 = source_db
        .root
        .entry_by_matching_kv(TITLE, "entry1")
        .unwrap()
        .clone();
    let e1_uuid = e1.get_uuid();
    e1.custom_icon_uuid = Some(source_icon_uuid);
    util::test_clock::advance_by(1);
    e1.update_modification_time_now();
    source_db.root.update_entry(e1).unwrap();

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_ref().unwrap();
    assert_eq!(
        icon_count(target_db),
        1,
        "cross-DB merge should dedup byte-identical icons across the two DBs"
    );
    assert_eq!(
        target_db.meta.custom_icons.icons[0].uuid, target_icon_uuid,
        "target's icon UUID should survive on cross-DB merge (target wins on identity)"
    );

    let merged_entry = target_db
        .root
        .entry_by_id(&e1_uuid)
        .expect("source entry should be merged into target on the cross-DB path");
    assert_eq!(
        merged_entry.custom_icon_uuid,
        Some(target_icon_uuid),
        "source entry's custom_icon_uuid should be remapped to target's UUID on cross-DB merge"
    );
}

