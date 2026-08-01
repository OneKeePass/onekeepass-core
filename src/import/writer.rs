use log::debug;
use uuid::Uuid;

use crate::{
    constants::entry_type_uuid,
    db_content::{Entry, Group, KeepassFile, KeyValue, Section},
    error::Result,
};

use super::model::{ImportedItem, ImportedKind};

// Writes normalised import items into a kdbx database. This is the only place that
// creates groups and entries during an import, so every source format gets the same
// grouping, entry type and field behaviour
pub(crate) struct ImportWriter {
    // Group that receives items with an empty folder path
    pub(crate) default_group_name: String,
}

impl ImportWriter {
    pub(crate) fn write(
        &self,
        items: &[ImportedItem],
        keepass_file: &mut KeepassFile,
    ) -> Result<()> {
        debug!("Going to create content from {} import items", items.len());

        for item in items {
            let parent_group_uuid = self.resolve_group(&item.folder_path, keepass_file)?;

            let mut entry = new_entry_of_kind(item.kind, &parent_group_uuid);

            if let Some(section) = custom_field_section(item) {
                entry.entry_field.entry_type.add_section(&section);
            }

            if let Some(tags) = item.tags.as_deref() {
                entry.set_tags(tags);
            }

            // Left alone when the source gave none, so the entry keeps the icon that
            // comes with its entry type
            if let Some(icon_id) = item.icon_id {
                entry.icon_id = icon_id;
            }

            for field in &item.fields {
                let kv = KeyValue::from(field.name.clone(), field.value.clone(), field.protected);
                entry.entry_field.insert_key_value(kv);
            }

            keepass_file.root.insert_entry(entry)?;
        }

        Ok(())
    }

    // The first path segment is looked up by name across the whole database. That is
    // what the flat csv Group column has always done - importing into an existing db
    // reuses a matching group wherever it sits in the tree. Deeper segments are looked
    // up only among the children of the segment before them, so a nested path cannot
    // accidentally attach to an unrelated group of the same name. A single segment path
    // therefore behaves exactly as it did before this writer existed
    fn resolve_group(&self, path: &[String], keepass_file: &mut KeepassFile) -> Result<Uuid> {
        let root_uuid = keepass_file.root.root_uuid();

        let Some((first, rest)) = path.split_first() else {
            return group_by_name_or_create(&self.default_group_name, &root_uuid, keepass_file);
        };

        let mut parent_uuid = group_by_name_or_create(first, &root_uuid, keepass_file)?;
        for name in rest {
            parent_uuid = child_group_or_create(name, &parent_uuid, keepass_file)?;
        }

        Ok(parent_uuid)
    }
}

// Declares this item's custom fields on its entry type. Built from the item because the
// names are not the same for every entry - an unmapped csv column yields the same name
// on every row, but a packed vendor column yields whatever that one item had
fn custom_field_section(item: &ImportedItem) -> Option<Section> {
    let names: Vec<&str> = item
        .fields
        .iter()
        .filter(|f| f.custom)
        .map(|f| f.name.as_str())
        .collect();

    if names.is_empty() {
        None
    } else {
        Some(Section::new_custom_field_section(names))
    }
}

// An unrecognised source item type arrives here as Login, so the fallback is the
// previous behaviour rather than a failure
fn new_entry_of_kind(kind: ImportedKind, parent_group_uuid: &Uuid) -> Entry {
    let type_uuid = match kind {
        ImportedKind::Login => return Entry::new_login_entry(Some(parent_group_uuid)),
        ImportedKind::CreditCard => crate::build_uuid!(entry_type_uuid::CREDIT_DEBIT_CARD),
        ImportedKind::Identity => crate::build_uuid!(entry_type_uuid::IDENTITY),
        ImportedKind::BankAccount => crate::build_uuid!(entry_type_uuid::BANK_ACCOUNT),
    };

    Entry::new_blank_entry_by_type_id(&type_uuid, None, Some(parent_group_uuid))
}

fn group_by_name_or_create(
    name: &str,
    parent_uuid: &Uuid,
    keepass_file: &mut KeepassFile,
) -> Result<Uuid> {
    // The recycle bin is deliberately excluded. A source folder called "Recycle Bin"
    // would otherwise resolve onto the target database's trash and the imported entries
    // would arrive already deleted. A normal group of that name is created instead
    let recycle_bin_uuid = keepass_file.root.recycle_bin_uuid();
    let existing = keepass_file
        .root
        .group_by_name(name)
        .map(|group| group.get_uuid())
        .filter(|uuid| *uuid != recycle_bin_uuid);

    match existing {
        Some(uuid) => Ok(uuid),
        None => create_group(name, parent_uuid, keepass_file),
    }
}

fn child_group_or_create(
    name: &str,
    parent_uuid: &Uuid,
    keepass_file: &mut KeepassFile,
) -> Result<Uuid> {
    // Collected up front so the immutable lookups below do not overlap the mutable
    // borrow needed to create a missing group
    let child_uuids: Vec<Uuid> = keepass_file
        .root
        .group_by_id(parent_uuid)
        .map(|parent| parent.group_uuids.clone())
        .unwrap_or_default();

    for child_uuid in child_uuids {
        let matched = keepass_file
            .root
            .group_by_id(&child_uuid)
            .map_or(false, |child| child.name == name);
        if matched {
            return Ok(child_uuid);
        }
    }

    create_group(name, parent_uuid, keepass_file)
}

fn create_group(name: &str, parent_uuid: &Uuid, keepass_file: &mut KeepassFile) -> Result<Uuid> {
    let mut group = Group::with_parent(parent_uuid);
    group.set_name(name);
    let uuid = group.get_uuid();
    keepass_file.root.insert_group(group)?;
    Ok(uuid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::model::ImportedField;

    fn empty_db() -> KeepassFile {
        let mut kp = KeepassFile::new();
        let mut root_g = Group::new_with_id();
        root_g.name = "Root".into();
        kp.root.set_root_uuid(root_g.uuid);
        kp.root.insert_to_all_groups(root_g);
        kp
    }

    fn writer() -> ImportWriter {
        ImportWriter {
            default_group_name: "CsvImported".to_string(),
        }
    }

    fn item(folder_path: Vec<&str>) -> ImportedItem {
        ImportedItem {
            folder_path: folder_path.into_iter().map(|s| s.to_string()).collect(),
            fields: vec![ImportedField {
                name: "Title".to_string(),
                value: "An entry".to_string(),
                protected: false,
                custom: false,
            }],
            ..Default::default()
        }
    }

    fn custom_field(name: &str) -> ImportedField {
        ImportedField {
            name: name.to_string(),
            value: "a value".to_string(),
            protected: false,
            custom: true,
        }
    }

    fn section_field_names(kp: &KeepassFile, entry_uuid: &Uuid) -> Vec<String> {
        kp.root
            .entry_by_id(entry_uuid)
            .unwrap()
            .entry_field
            .entry_type
            .sections
            .iter()
            .filter(|s| s.name == "Custom Fields")
            .flat_map(|s| s.field_defs.iter().map(|f| f.name.clone()))
            .collect()
    }

    // Items with no folder must land in the default group rather than in a group whose
    // name is the empty string
    #[test]
    fn an_empty_folder_path_uses_the_default_group() {
        let mut kp = empty_db();
        writer().write(&[item(vec![])], &mut kp).unwrap();

        assert!(kp.root.group_by_name("").is_none());
        assert!(kp.root.group_by_name("CsvImported").is_some());
    }

    #[test]
    fn a_single_segment_path_creates_one_group_and_is_then_reused() {
        let mut kp = empty_db();
        writer()
            .write(&[item(vec!["Work"]), item(vec!["Work"])], &mut kp)
            .unwrap();

        let work = kp.root.group_by_name("Work").expect("Work group");
        assert_eq!(work.entry_uuids.len(), 2, "both entries share the group");
    }

    #[test]
    fn a_nested_path_creates_the_whole_chain() {
        let mut kp = empty_db();
        writer().write(&[item(vec!["Work", "Clients"])], &mut kp).unwrap();

        let work = kp.root.group_by_name("Work").expect("Work group");
        let work_children = work.group_uuids.clone();
        assert_eq!(work_children.len(), 1);

        let clients = kp
            .root
            .group_by_id(&work_children[0])
            .expect("child group");
        assert_eq!(clients.name, "Clients");
        assert_eq!(clients.entry_uuids.len(), 1);
    }

    // A non-Login kind must produce an entry of that standard type, not a Login. The
    // uuid is what OKP persists in entry custom data under OKP_K3
    #[test]
    fn a_kind_selects_the_matching_standard_entry_type() {
        let mut kp = empty_db();

        let card = ImportedItem {
            kind: ImportedKind::CreditCard,
            ..item(vec!["Cards"])
        };
        let login = item(vec!["Cards"]);

        writer().write(&[card, login], &mut kp).unwrap();

        let group = kp.root.group_by_name("Cards").unwrap();
        let type_uuids: Vec<_> = group
            .entry_uuids
            .iter()
            .map(|id| {
                kp.root
                    .entry_by_id(id)
                    .unwrap()
                    .entry_field
                    .entry_type
                    .uuid
            })
            .collect();

        let card_uuid = crate::build_uuid!(entry_type_uuid::CREDIT_DEBIT_CARD);
        let login_uuid = crate::build_uuid!(entry_type_uuid::LOGIN);

        assert!(type_uuids.contains(&card_uuid), "card entry type applied");
        assert!(type_uuids.contains(&login_uuid), "login entry type applied");
    }

    // Custom fields differ per item once a vendor packs them into one column, so each
    // entry must declare its own rather than share one section for the whole import
    #[test]
    fn each_entry_declares_only_its_own_custom_fields() {
        let mut kp = empty_db();

        let mut first = item(vec!["Imported"]);
        first.fields.push(custom_field("Security question"));
        let mut second = item(vec!["Imported"]);
        second.fields.push(custom_field("Account no"));

        writer().write(&[first, second], &mut kp).unwrap();

        let entries = kp.root.group_by_name("Imported").unwrap().entry_uuids.clone();
        let declared: Vec<Vec<String>> = entries
            .iter()
            .map(|id| section_field_names(&kp, id))
            .collect();

        assert!(declared.contains(&vec!["Security question".to_string()]));
        assert!(declared.contains(&vec!["Account no".to_string()]));
    }

    // An entry with no custom fields must not gain an empty Custom Fields section
    #[test]
    fn an_entry_without_custom_fields_gets_no_section() {
        let mut kp = empty_db();
        writer().write(&[item(vec!["Imported"])], &mut kp).unwrap();

        let entry_uuid = kp.root.group_by_name("Imported").unwrap().entry_uuids[0];
        assert!(section_field_names(&kp, &entry_uuid).is_empty());
    }

    #[test]
    fn a_source_icon_is_applied_and_its_absence_leaves_the_default() {
        let mut kp = empty_db();

        let with_icon = ImportedItem {
            icon_id: Some(40),
            ..item(vec!["Imported"])
        };
        writer()
            .write(&[with_icon, item(vec!["Imported"])], &mut kp)
            .unwrap();

        let entries = kp.root.group_by_name("Imported").unwrap().entry_uuids.clone();
        let icons: Vec<i32> = entries
            .iter()
            .map(|id| kp.root.entry_by_id(id).unwrap().icon_id)
            .collect();

        assert!(icons.contains(&40), "the source icon was applied");
        let default_icon = Entry::new_login_entry(None).icon_id;
        assert!(
            icons.contains(&default_icon),
            "an item without an icon keeps its entry type's own"
        );
    }

    // A source folder called "Recycle Bin" must not resolve onto the target database's
    // trash - the imported entries would arrive already deleted
    #[test]
    fn an_imported_group_never_resolves_onto_the_recycle_bin() {
        let mut kp = empty_db();
        let recycle_bin_uuid = kp.root.recycle_bin_group().unwrap().get_uuid();

        writer().write(&[item(vec!["Recycle Bin"])], &mut kp).unwrap();

        assert!(
            kp.root
                .group_by_id(&recycle_bin_uuid)
                .unwrap()
                .entry_uuids
                .is_empty(),
            "nothing was imported into the trash"
        );
    }

    // Two different parents may each hold a child of the same name. The deeper lookup
    // is scoped to the parent, so the second must not be folded into the first
    #[test]
    fn same_named_children_under_different_parents_stay_separate() {
        let mut kp = empty_db();
        writer()
            .write(
                &[item(vec!["Work", "Shared"]), item(vec!["Personal", "Shared"])],
                &mut kp,
            )
            .unwrap();

        let work_child = kp.root.group_by_name("Work").unwrap().group_uuids[0];
        let personal_child = kp.root.group_by_name("Personal").unwrap().group_uuids[0];

        assert_ne!(work_child, personal_child);
        assert_eq!(kp.root.group_by_id(&work_child).unwrap().name, "Shared");
        assert_eq!(kp.root.group_by_id(&personal_child).unwrap().name, "Shared");
    }
}
