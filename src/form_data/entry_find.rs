use serde::{Deserialize, Serialize};

use crate::db_content::{Entry, KeepassFile};

use super::EntrySummary;

// The kinds of entry lists that can be requested on demand (outside of the entry categories)
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EntryFindKind {
    WithAttachments,
    WithHistory,
    Passkeys,
    Totp,
    BySize,
}

impl EntryFindKind {
    fn matches(&self, entry: &Entry) -> bool {
        match self {
            EntryFindKind::WithAttachments => entry.attachment_count() > 0,
            EntryFindKind::WithHistory => entry.history_count() > 0,
            EntryFindKind::Passkeys => entry.has_passkey(),
            EntryFindKind::Totp => entry.has_otp(),
            EntryFindKind::BySize => true,
        }
    }
}

#[derive(Serialize, Debug)]
pub struct EntryFindItem {
    pub summary: EntrySummary,
    // Approximate size in bytes - see Entry's data_size fn
    pub data_size: u64,
    pub attachment_count: usize,
    pub history_count: usize,
}

#[derive(Serialize, Debug)]
pub struct EntryFindResult {
    pub kind: EntryFindKind,
    pub items: Vec<EntryFindItem>,
    // Sum of data_size of the listed items
    pub total_data_size: u64,
}

// Collects the active entries (not in the recycle bin) that match the given kind
pub(crate) fn find_entries(kp: &KeepassFile, kind: EntryFindKind) -> EntryFindResult {
    let mut items: Vec<EntryFindItem> = kp
        .collect_all_active_entries()
        .into_iter()
        .filter(|e| kind.matches(e))
        .map(|e| EntryFindItem {
            summary: EntrySummary::from_entry(kp, e),
            data_size: e.data_size(),
            attachment_count: e.attachment_count(),
            history_count: e.history_count(),
        })
        .collect();

    if kind == EntryFindKind::BySize {
        items.sort_by(|a, b| {
            b.data_size
                .cmp(&a.data_size)
                .then_with(|| a.summary.title.cmp(&b.summary.title))
        });
    } else {
        // Same ordering as the entry list's entry_summary_data
        items.sort_by(|a, b| a.summary.title.cmp(&b.summary.title));
    }

    let total_data_size = items.iter().map(|i| i.data_size).sum();

    EntryFindResult {
        kind,
        items,
        total_data_size,
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::constants::entry_keyvalue_key::{KPEX_PASSKEY_CREDENTIAL_ID, TITLE};
    use crate::db_content::{BinaryKeyValue, Group, KeyValue};

    fn kv(key: &str, value: &str) -> KeyValue {
        let mut kv = KeyValue::new();
        kv.key = key.into();
        kv.value = value.into();
        kv
    }

    fn attachment(name: &str, size: usize) -> BinaryKeyValue {
        BinaryKeyValue {
            key: name.into(),
            value: String::default(),
            index_ref: 0,
            data_hash: 0,
            data_size: size,
        }
    }

    struct TestDb {
        kp: KeepassFile,
        root_uuid: Uuid,
        recycle_bin_uuid: Uuid,
    }

    impl TestDb {
        fn new() -> Self {
            let mut kp = KeepassFile::new();

            let root_g = Group::new_with_id();
            let root_uuid = root_g.uuid;
            kp.root.set_root_uuid(root_uuid);
            kp.root.insert_to_all_groups(root_g);

            let mut bin_g = Group::new_with_id();
            bin_g.parent_group_uuid = root_uuid;
            let recycle_bin_uuid = bin_g.uuid;
            kp.root.insert_to_all_groups(bin_g);
            kp.root.set_recycle_bin_uuid(recycle_bin_uuid);

            TestDb {
                kp,
                root_uuid,
                recycle_bin_uuid,
            }
        }

        // Inserts an entry titled 'title' under 'parent' after 'build' has filled it in
        fn add(&mut self, parent: Uuid, title: &str, build: impl FnOnce(&mut Entry)) {
            let mut e = Entry::new();
            e.uuid = Uuid::new_v4();
            e.parent_group_uuid = parent;
            e.entry_field.insert_key_value(kv(TITLE, title));
            build(&mut e);
            self.kp.root.insert_entry(e).unwrap();
        }

        fn titles(&self, kind: EntryFindKind) -> Vec<String> {
            find_entries(&self.kp, kind)
                .items
                .into_iter()
                .map(|i| i.summary.title.unwrap_or_default())
                .collect()
        }
    }

    fn sample_db() -> TestDb {
        let mut db = TestDb::new();
        let root = db.root_uuid;

        db.add(root, "Plain", |_| {});
        db.add(root, "Files", |e| {
            e.binary_key_values.push(attachment("a.pdf", 5000));
        });
        db.add(root, "Edited", |e| {
            let mut h = Entry::new();
            h.entry_field.insert_key_value(kv(TITLE, "Edited old"));
            e.history.entries.push(h);
        });
        // A passkey stored on a Login entry, not on the Passkey entry type
        db.add(root, "Login with passkey", |e| {
            e.entry_field
                .insert_key_value(kv(KPEX_PASSKEY_CREDENTIAL_ID, "Y3JlZC1pZA"));
        });
        db.add(root, "Empty passkey id", |e| {
            e.entry_field
                .insert_key_value(kv(KPEX_PASSKEY_CREDENTIAL_ID, ""));
        });
        db.add(root, "Totp", |e| {
            e.entry_field.insert_key_value(kv(
                "otp",
                "otpauth://totp/OneKeePass:test?secret=JBSWY3DPEHPK3PXP&period=30",
            ));
        });
        db.add(root, "Bad otp", |e| {
            e.entry_field
                .insert_key_value(kv("otp", "otpauth://totp/no-secret-here"));
        });

        let bin = db.recycle_bin_uuid;
        db.add(bin, "Deleted with files", |e| {
            e.binary_key_values.push(attachment("b.pdf", 9000));
        });
        db
    }

    #[test]
    fn with_attachments_skips_recycle_bin() {
        assert_eq!(sample_db().titles(EntryFindKind::WithAttachments), ["Files"]);
    }

    #[test]
    fn with_history() {
        assert_eq!(sample_db().titles(EntryFindKind::WithHistory), ["Edited"]);
    }

    #[test]
    fn passkeys_on_any_entry_type_with_a_credential_id() {
        assert_eq!(
            sample_db().titles(EntryFindKind::Passkeys),
            ["Login with passkey"]
        );
    }

    #[test]
    fn totp_needs_a_parseable_otp_url() {
        assert_eq!(sample_db().titles(EntryFindKind::Totp), ["Totp"]);
    }

    #[test]
    fn by_size_lists_all_active_entries_largest_first() {
        let db = sample_db();
        let result = find_entries(&db.kp, EntryFindKind::BySize);

        assert_eq!(result.items.len(), 7);
        assert_eq!(result.items[0].summary.title.as_deref(), Some("Files"));
        assert!(result
            .items
            .windows(2)
            .all(|w| w[0].data_size >= w[1].data_size));
        assert_eq!(
            result.total_data_size,
            result.items.iter().map(|i| i.data_size).sum::<u64>()
        );
    }

    #[test]
    fn items_carry_counts_for_every_kind() {
        let db = sample_db();
        let result = find_entries(&db.kp, EntryFindKind::BySize);
        let files = result
            .items
            .iter()
            .find(|i| i.summary.title.as_deref() == Some("Files"))
            .unwrap();
        assert_eq!(files.attachment_count, 1);
        assert_eq!(files.history_count, 0);
    }

    #[test]
    fn kind_serializes_as_camel_case() {
        assert_eq!(
            serde_json::to_string(&EntryFindKind::WithAttachments).unwrap(),
            "\"withAttachments\""
        );
        let k: EntryFindKind = serde_json::from_str("\"bySize\"").unwrap();
        assert_eq!(k, EntryFindKind::BySize);
    }
}
