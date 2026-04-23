use uuid::Uuid;

use crate::constants::custom_data_key::OKP_ENTRY_TYPE;
use crate::error::{Error, Result};
use crate::util;

use super::entry::Entry;
use super::entry_type::EntryType;
use super::group::Group;
use super::keepass::KeepassFile;
use super::meta::Meta;
use super::root::Root;
use super::Icon;

pub(crate) struct CrossDbMoveResult {
    pub(crate) moved_entry_uuids: Vec<Uuid>,
    pub(crate) moved_group_uuids: Vec<Uuid>,
    pub(crate) target_parent_group_name: String,
}

pub(crate) fn clone_entry_to_other_db(
    source: &KeepassFile,
    target: &mut KeepassFile,
    entry_uuid: &Uuid,
    target_parent_group_uuid: &Uuid,
) -> Result<Uuid> {
    let source_entry = source
        .root
        .entry_by_id(entry_uuid)
        .ok_or_else(|| Error::NotFound("Source entry not found".into()))?
        .clone();

    // Source entry must not be in the recycle bin
    if is_inside_recycle_bin(&source.root, &source_entry.parent_group_uuid) {
        return Err(Error::DataError(
            "Entries inside the recycle bin cannot be cloned to another database",
        ));
    }

    validate_target_parent(&target.root, target_parent_group_uuid)?;

    let mut cloned = source_entry;

    // New UUID - no collision check needed (new identity, not a preserved UUID)
    cloned.uuid = uuid::Uuid::new_v4();
    cloned.parent_group_uuid = *target_parent_group_uuid;

    // Always clear history for cross-db clone
    cloned.delete_history_entries();

    // Collect icons/types now (history already cleared, so only main entry is scanned)
    let mut icon_uuids: Vec<Uuid> = Vec::new();
    collect_entry_icon_uuids(&cloned, &mut icon_uuids);

    let mut entry_type_uuids: Vec<Uuid> = Vec::new();
    collect_entry_type_uuids(&cloned, &mut entry_type_uuids);

    let icons_to_copy = collect_owned_icons(&source.meta, &icon_uuids);
    let entry_types_to_copy = collect_owned_entry_types(&source.meta, &entry_type_uuids);

    copy_custom_icons_into(&mut target.meta, icons_to_copy);
    copy_custom_entry_types_into(&mut target.meta, entry_types_to_copy);

    // Reset all timestamps
    let n = util::now_utc();
    cloned.times.creation_time = n;
    cloned.times.last_modification_time = n;
    cloned.times.last_access_time = n;
    cloned.times.location_changed = n;

    let new_uuid = cloned.uuid;

    // insert_entry rebinds meta_share to target and pushes uuid onto parent's entry_uuids list
    target.insert_entry(cloned)?;

    Ok(new_uuid)
}

pub(crate) fn move_entry_between_keepass_files(
    source: &mut KeepassFile,
    target: &mut KeepassFile,
    entry_uuid: &Uuid,
    target_parent_group_uuid: &Uuid,
) -> Result<CrossDbMoveResult> {
    let source_entry = source
        .root
        .entry_by_id(entry_uuid)
        .ok_or_else(|| Error::NotFound("Source entry not found".into()))?
        .clone();

    // The entry being moved must not be inside the source recycle bin.
    if is_inside_recycle_bin(&source.root, &source_entry.parent_group_uuid) {
        return Err(Error::DataError(
            "Entries inside the recycle bin cannot be moved to another database",
        ));
    }

    validate_target_parent(&target.root, target_parent_group_uuid)?;

    if target.root.entry_by_id(entry_uuid).is_some() {
        return Err(Error::DataError("ErrorEntryUuidExistsInTarget"
            // "An entry with the same uuid already exists in the target database. \
            //  If these databases are copies, use 'Merge Opened Databases' from the Database menu.",
        ));
    }

    let mut icon_uuids: Vec<Uuid> = Vec::new();
    collect_entry_icon_uuids(&source_entry, &mut icon_uuids);

    let mut entry_type_uuids: Vec<Uuid> = Vec::new();
    collect_entry_type_uuids(&source_entry, &mut entry_type_uuids);

    let icons_to_copy = collect_owned_icons(&source.meta, &icon_uuids);
    let entry_types_to_copy = collect_owned_entry_types(&source.meta, &entry_type_uuids);

    copy_custom_icons_into(&mut target.meta, icons_to_copy);
    copy_custom_entry_types_into(&mut target.meta, entry_types_to_copy);

    let mut cloned_entry = source_entry;
    cloned_entry.parent_group_uuid = *target_parent_group_uuid;
    cloned_entry.times.location_changed = util::now_utc();

    // Uses the regular insert path: rebinds meta_share AND pushes onto the target
    // parent's entry_uuids list (the target parent is a native group, not a cloned one).
    target.insert_entry(cloned_entry)?;

    source.root.remove_entry_cross_db_move(entry_uuid)?;

    let target_parent_group_name = target
        .root
        .group_by_id(target_parent_group_uuid)
        .map(|g| g.name.clone())
        .unwrap_or_default();

    Ok(CrossDbMoveResult {
        moved_entry_uuids: vec![*entry_uuid],
        moved_group_uuids: vec![],
        target_parent_group_name,
    })
}

pub(crate) fn move_group_between_keepass_files(
    source: &mut KeepassFile,
    target: &mut KeepassFile,
    group_uuid: &Uuid,
    target_parent_group_uuid: &Uuid,
) -> Result<CrossDbMoveResult> {
    if *group_uuid == source.root.root_uuid() {
        return Err(Error::DataError(
            "The root group cannot be moved to another database",
        ));
    }
    if *group_uuid == source.root.recycle_bin_uuid() {
        return Err(Error::DataError(
            "The recycle bin group cannot be moved to another database",
        ));
    }

    if source.root.group_by_id(group_uuid).is_none() {
        return Err(Error::NotFound("Source group not found".into()));
    }

    // Must not be inside the source recycle bin.
    if is_inside_recycle_bin(&source.root, group_uuid) {
        return Err(Error::DataError(
            "Groups inside the recycle bin cannot be moved to another database",
        ));
    }

    // The subtree must not contain the source recycle bin.
    let descendant_group_ids = source.root.children_groups_uuids(group_uuid);
    let source_recycle = source.root.recycle_bin_uuid();
    if source_recycle != Uuid::default() && descendant_group_ids.contains(&source_recycle) {
        return Err(Error::DataError(
            "The selected group contains the recycle bin and cannot be moved",
        ));
    }

    validate_target_parent(&target.root, target_parent_group_uuid)?;

    // Collect uuids of everything in the subtree for collision checks.
    let mut all_subtree_group_ids: Vec<Uuid> = Vec::with_capacity(descendant_group_ids.len() + 1);
    all_subtree_group_ids.push(*group_uuid);
    all_subtree_group_ids.extend(descendant_group_ids.iter().copied());

    let subtree_entry_ids = source.root.children_entry_uuids(group_uuid);

    for gid in &all_subtree_group_ids {
        if target.root.group_by_id(gid).is_some() {
            return Err(Error::DataError("ErrorGroupUuidExistsInTarget"
                // "A group with the same uuid already exists in the target database",
            ));
        }
    }
    for eid in &subtree_entry_ids {
        if target.root.entry_by_id(eid).is_some() {
            return Err(Error::DataError("ErrorEntryUuidExistsInTarget"
                // "An entry with the same uuid already exists in the target database",
            ));
        }
    }

    // Clone owned groups in parent-before-children order (top-level first).
    let mut cloned_groups: Vec<Group> = Vec::with_capacity(all_subtree_group_ids.len());
    for gid in &all_subtree_group_ids {
        let g = source
            .root
            .group_by_id(gid)
            .ok_or_else(|| Error::NotFound("Subtree group not found during clone".into()))?
            .clone();
        cloned_groups.push(g);
    }

    let mut cloned_entries: Vec<Entry> = Vec::with_capacity(subtree_entry_ids.len());
    for eid in &subtree_entry_ids {
        let e = source
            .root
            .entry_by_id(eid)
            .ok_or_else(|| Error::NotFound("Subtree entry not found during clone".into()))?
            .clone();
        cloned_entries.push(e);
    }

    // Collect referenced custom icon uuids and custom entry type uuids from the subtree.
    let mut icon_uuids: Vec<Uuid> = Vec::new();
    let mut entry_type_uuids: Vec<Uuid> = Vec::new();

    for g in &cloned_groups {
        if let Some(u) = g.custom_icon_uuid {
            if !icon_uuids.contains(&u) {
                icon_uuids.push(u);
            }
        }
    }
    for e in &cloned_entries {
        collect_entry_icon_uuids(e, &mut icon_uuids);
        collect_entry_type_uuids(e, &mut entry_type_uuids);
    }

    let icons_to_copy = collect_owned_icons(&source.meta, &icon_uuids);
    let entry_types_to_copy = collect_owned_entry_types(&source.meta, &entry_type_uuids);

    // Phase 2: mutate target.
    copy_custom_icons_into(&mut target.meta, icons_to_copy);
    copy_custom_entry_types_into(&mut target.meta, entry_types_to_copy);

    // Rebind the top-level group to its new parent and touch location_changed.
    let moved_entry_uuids = subtree_entry_ids.clone();
    let moved_group_uuids = all_subtree_group_ids.clone();

    if let Some(first) = cloned_groups.first_mut() {
        first.parent_group_uuid = *target_parent_group_uuid;
        first.times.location_changed = util::now_utc();
    }

    let mut is_top_level = true;
    for g in cloned_groups.into_iter() {
        target.root.insert_group_cross_db(g, is_top_level)?;
        is_top_level = false;
    }

    for e in cloned_entries.into_iter() {
        target.insert_entry_cross_db(e)?;
    }

    // Phase 3: remove the subtree from source.
    source.root.remove_group_subtree_cross_db_move(group_uuid)?;

    let target_parent_group_name = target
        .root
        .group_by_id(target_parent_group_uuid)
        .map(|g| g.name.clone())
        .unwrap_or_default();

    Ok(CrossDbMoveResult {
        moved_entry_uuids,
        moved_group_uuids,
        target_parent_group_name,
    })
}

fn validate_target_parent(target_root: &Root, target_parent_group_uuid: &Uuid) -> Result<()> {
    if target_root.group_by_id(target_parent_group_uuid).is_none() {
        return Err(Error::NotFound(
            "Target parent group not found in target database".into(),
        ));
    }
    let target_recycle = target_root.recycle_bin_uuid();
    if target_recycle != Uuid::default() && *target_parent_group_uuid == target_recycle {
        return Err(Error::DataError(
            "Cannot move into the target database's recycle bin",
        ));
    }
    if is_inside_recycle_bin(target_root, target_parent_group_uuid) {
        return Err(Error::DataError(
            "Cannot move into a group inside the target database's recycle bin",
        ));
    }
    Ok(())
}

// Walks the parent chain upward from candidate until it reaches the recycle bin group,
// the root group, or a dead end.
fn is_inside_recycle_bin(root: &Root, candidate: &Uuid) -> bool {
    let rb = root.recycle_bin_uuid();
    if rb == Uuid::default() {
        return false;
    }
    let mut current = *candidate;
    // Bound the loop to avoid cycles in malformed data.
    for _ in 0..10_000 {
        if current == rb {
            return true;
        }
        match root.group_by_id(&current) {
            Some(g) => {
                let parent = g.parent_group_uuid;
                if parent == Uuid::default() || parent == current {
                    return false;
                }
                current = parent;
            }
            None => return false,
        }
    }
    false
}

fn collect_entry_icon_uuids(entry: &Entry, out: &mut Vec<Uuid>) {
    if let Some(u) = entry.custom_icon_uuid {
        if !out.contains(&u) {
            out.push(u);
        }
    }
    for h in entry.history.entries.iter() {
        if let Some(u) = h.custom_icon_uuid {
            if !out.contains(&u) {
                out.push(u);
            }
        }
    }
}

fn collect_entry_type_uuids(entry: &Entry, out: &mut Vec<Uuid>) {
    push_entry_type_uuid_from_custom_data(entry, out);
    for h in entry.history.entries.iter() {
        push_entry_type_uuid_from_custom_data(h, out);
    }
}

fn push_entry_type_uuid_from_custom_data(entry: &Entry, out: &mut Vec<Uuid>) {
    if let Some(b64) = entry.custom_data.get_item_value(OKP_ENTRY_TYPE) {
        if let Some(uuid) = util::decode_uuid(b64) {
            if !out.contains(&uuid) {
                out.push(uuid);
            }
        }
    }
}

fn collect_owned_icons(meta: &Meta, icon_uuids: &[Uuid]) -> Vec<Icon> {
    icon_uuids
        .iter()
        .filter_map(|u| {
            meta.custom_icons
                .icons
                .iter()
                .find(|i| i.uuid == *u)
                .cloned()
        })
        .collect()
}

fn collect_owned_entry_types(meta: &Meta, entry_type_uuids: &[Uuid]) -> Vec<EntryType> {
    entry_type_uuids
        .iter()
        .filter_map(|u| meta.get_custom_entry_type_by_id(u))
        .collect()
}

fn copy_custom_icons_into(target_meta: &mut Meta, icons: Vec<Icon>) {
    for icon in icons {
        if !target_meta
            .custom_icons
            .icons
            .iter()
            .any(|i| i.uuid == icon.uuid)
        {
            target_meta.custom_icons.icons.push(icon);
        }
    }
}

fn copy_custom_entry_types_into(target_meta: &mut Meta, entry_types: Vec<EntryType>) {
    for et in entry_types {
        if target_meta.get_custom_entry_type_by_id(&et.uuid).is_none() {
            target_meta.insert_or_update_custom_entry_type(et);
        }
    }
}
