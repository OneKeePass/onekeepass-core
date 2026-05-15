use crate::constants::custom_data_key::OKP_ENTRY_TYPE_MAP_DATA;
use crate::constants::GENERATOR_NAME;
use crate::crypto;
use crate::db_content::EntryType;
use crate::db_content::{CustomData, CustomIcons, MemoryProtection};
use crate::error::Result;
use crate::util;
use chrono::NaiveDateTime;
use log::debug;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

// Carries both the modified flag (drives MergeResult.meta_data_changed and the
// save-pending state) and the icon UUID remap. The remap records pairs where
// the source DB had an icon byte-identical to one in the target DB but under a
// different UUID — entries/groups cloned from source must rewrite their
// custom_icon_uuid through this map so they end up pointing at the surviving
// target-side icon.
#[derive(Default)]
pub struct MetaMergeReport {
    pub modified: bool,
    pub icon_remap: HashMap<Uuid, Uuid>,
}

use super::entry_type::VersionedEntryType;
use super::Item;

#[derive(Debug, PartialEq)]
pub(crate) struct HistoryItemsMeta {
    pub(crate) history_max_items: i32,
    pub(crate) history_max_size: i32,
}

// This is a shared data from Meta to Groups and Entries and is stored in a Arc struct for the sharing.
// All mutable components of this struct need to use Mutex
#[derive(Debug)]
pub struct MetaShare {
    pub custom_entry_types_by_id: Mutex<HashMap<Uuid, EntryType>>,
    history_items_meta: Mutex<HistoryItemsMeta>,
}

impl Default for MetaShare {
    fn default() -> Self {
        Self {
            //custom_entry_types:Mutex::new(HashMap::default()),
            custom_entry_types_by_id: Mutex::new(HashMap::default()),
            history_items_meta: Mutex::new(HistoryItemsMeta {
                history_max_items: 10,
                history_max_size: 6291456,
            }),
        }
    }
}

impl MetaShare {
    pub fn get_entry_type_by_id(&self, uuid: &Uuid) -> Option<EntryType> {
        let t = self.custom_entry_types_by_id.lock().unwrap();
        t.get(uuid).map(|e| e.clone())
    }

    pub fn history_max_items(&self) -> i32 {
        self.history_items_meta.lock().unwrap().history_max_items
    }

    pub fn set_history_max_items(&self, max_no: i32) {
        self.history_items_meta.lock().unwrap().history_max_items = max_no;
    }

    pub fn history_max_size(&self) -> i32 {
        self.history_items_meta.lock().unwrap().history_max_size
    }

    pub fn set_history_max_size(&self, max_size: i32) {
        self.history_items_meta.lock().unwrap().history_max_size = max_size;
    }

    #[allow(dead_code)]
    pub fn with_custom_entry_type_by_id<F, R>(&self, uuid: &Uuid, action: F) -> R
    where
        F: FnOnce(Option<&EntryType>) -> R,
    {
        let t = self.custom_entry_types_by_id.lock().unwrap();
        action(t.get(uuid))
    }
}

#[derive(Debug, Clone)]
pub struct Meta {
    pub(crate) generator: String,
    pub(crate) database_name: String,
    pub(crate) database_description: String,
    pub(crate) default_user_name: String,
    pub(crate) maintenance_history_days: i32,
    pub(crate) recycle_bin_enabled: bool,

    // When a db is loaded, this is set from xml content if available and copied to root. 
    // But when a recycle bin is created first time in onekeepas, 
    // the new recycle group is created in 'root' and its uuid  is later 
    // copied to meta from root before writing to xml
    pub(crate) recycle_bin_uuid: Uuid,

    pub(crate) last_selected_group: Uuid,
    pub(crate) entry_template_group: Uuid,

    pub(crate) memory_protection: MemoryProtection,
    pub(crate) custom_icons: CustomIcons,
    pub(crate) custom_data: CustomData,

    pub(crate) database_name_changed: NaiveDateTime,
    pub(crate) database_description_changed: NaiveDateTime,
    pub(crate) default_user_name_changed: NaiveDateTime,
    pub(crate) settings_changed: NaiveDateTime,

    pub(crate) master_key_changed: NaiveDateTime,
    pub(crate) entry_template_group_changed: NaiveDateTime,

    // history_max_items and history_max_size are moved to MetaShare
    pub(crate) meta_share: Arc<MetaShare>,
}

//As NaiveDateTime does not have default fn, we need to implement "new" or "default" fn for Meta explicitly
impl Meta {
    pub fn new() -> Meta {
        let current_time = util::now_utc();
        Meta {
            generator: GENERATOR_NAME.into(), //String::default(),
            database_name: String::default(),
            database_description: String::default(),
            default_user_name: String::default(),
            maintenance_history_days: 365, //365

            recycle_bin_enabled: false,
            recycle_bin_uuid: Uuid::default(),
            last_selected_group: Uuid::default(),
            entry_template_group: Uuid::default(),

            memory_protection: MemoryProtection::default(),
            custom_icons: Default::default(),
            custom_data: CustomData::default(),

            default_user_name_changed: current_time,
            database_name_changed: current_time,
            database_description_changed: current_time,
            settings_changed: current_time,
            master_key_changed: current_time,
            entry_template_group_changed: current_time,

            meta_share: Arc::default(),
        }
    }

    
    pub(crate) fn database_name(&self) -> &String {
        &self.database_name
    }

    // The incoming Meta instance 'other' is partially filled from db_service::MetaFormData and passed it here
    pub fn update(&mut self, other: Meta) -> Result<()> {
        let current_time = util::now_utc();

        // For now, only the relevant fields that need to be updated are copied from other to self
        if self.database_name != other.database_name {
            self.database_name = other.database_name;
            self.database_name_changed = current_time;
        }

        if self.database_description != other.database_description {
            self.database_description = other.database_description;
            self.database_description_changed = current_time;
        }

        self.recycle_bin_enabled = other.recycle_bin_enabled;
        //self.history_max_items = other.history_max_items;
        //self.history_max_size = other.history_max_size;
        self.maintenance_history_days = other.maintenance_history_days;
        self.settings_changed = current_time;
        Ok(())
    }

    pub fn copy_from_custom_data(&mut self) {
        self.copy_entry_types_from_custom_data();
    }

    pub fn copy_to_custom_data(&mut self) {
        self.copy_entry_types_to_custom_data();
        // TODO:
        // Need to read and store this internal version info in meta and should be updated
        // only when we update the INTERNAL_VERSION or inserted only first time
        // self.custom_data.set_internal_version(&INTERNAL_VERSION.to_string());
    }

    fn copy_entry_types_from_custom_data(&mut self) {
        if let Some(data) = self.custom_data.get_item_value(OKP_ENTRY_TYPE_MAP_DATA) {
            debug!("Found custom entry types");
            let etypes: HashMap<Uuid, EntryType> =
                VersionedEntryType::decode_entry_types_by_id(data);
            let mut s = self.meta_share.custom_entry_types_by_id.lock().unwrap();
            s.extend(etypes.iter().map(|(k, v)| (k.clone(), v.clone())));
            debug!("Found custom entry types loaded and size is {}", s.len());
        }
    }

    fn copy_entry_types_to_custom_data(&mut self) {
        let s = self.meta_share.custom_entry_types_by_id.lock().unwrap();
        if !s.is_empty() {
            if let Some(data) = VersionedEntryType::encode_entry_types_by_id(&s) {
                self.custom_data
                    .insert_item(Item::from_kv_with_modification_time(
                        OKP_ENTRY_TYPE_MAP_DATA,
                        &data,
                        util::now_utc(),
                    ));
                debug!("Custom entrypes saved to custom data");
            }
        }
    }

    pub fn clone_meta_share(&self) -> Arc<MetaShare> {
        Arc::clone(&self.meta_share)
    }
    pub fn insert_or_update_custom_entry_type(&mut self, entry_type: EntryType) {
        let mut types = self.meta_share.custom_entry_types_by_id.lock().unwrap();
        types.insert(entry_type.uuid.clone(), entry_type);
    }

    pub fn custom_entry_type_names_by_id(&self) -> Vec<(Uuid, String)> {
        let types = self.meta_share.custom_entry_types_by_id.lock().unwrap();
        types
            .iter()
            .map(|(k, v)| (k.clone(), v.name.clone()))
            .collect()
    }

    pub fn with_custom_entry_type<F, R>(&self, action: F) -> R
    where
        F: FnOnce(Vec<&EntryType>) -> R,
    {
        let t = self.meta_share.custom_entry_types_by_id.lock().unwrap();
        let vals = t.values().map(|v| v).collect();
        action(vals)
    }

    // pub fn custom_entry_types<'a>(&'a self) -> Vec<&'a EntryType> {
    //     let types = self.meta_share.custom_entry_types_by_id.lock().unwrap();
    //     types
    //         .iter().map(|(_,e)|  {
    //             e
    //             //IMPORATNT: we use unwrap expecting that STANDARD_TYPE_UUIDS_BY_NAME and STANDARD_TYPE_NAMES match
    //             //let uuid = STANDARD_TYPE_UUIDS_BY_NAME.get(s).unwrap();
    //             //UUID_TO_ENTRY_TYPE_MAP.get(uuid).map_or_else(||&*DEFAULT_ENTRY_TYPE , |e| e)
    //         }).collect::<Vec<&EntryType>>()
    // }

    pub fn get_custom_entry_type_by_id(&self, uuid: &Uuid) -> Option<EntryType> {
        self.meta_share.get_entry_type_by_id(uuid)
    }

    pub fn delete_custom_entry_type_by_id(&mut self, entry_type_id: &Uuid) -> Option<EntryType> {
        let mut types = self.meta_share.custom_entry_types_by_id.lock().unwrap();
        types.remove(entry_type_id)
    }

    // pub fn update(&mut self,other:Meta) -> &mut Self {
    //     //TODO: We need to see what are the other relevant fiields that need to be updated "other"
    //     self.database_name = other.database_name;
    //     self.database_decription = other.database_decription;
    //     self.last_selected_group = other.last_selected_group;
    //     self
    // }

    // pub fn update(self, other:Meta) -> Self {
    //     Meta {
    //         generator:self.generator,
    //         memory_protection:self.memory_protection,
    //         ..other  //.. specifies that the remaining fields not explicitly set should have the same value as the fields in the given instance.
    //     }
    // }
}

impl Meta {
    // Same-DB merge: source and target share root_uuid (copies of the same DB).
    // Runs the full meta merge: identity fields gated on settings_changed,
    // custom icons (dedup + remap), and custom data (additive).
    pub fn merge(&mut self, other: &Meta) -> Result<MetaMergeReport> {
        let current_time = util::now_utc();
        let mut modified = false;

        // Identity fields (database name, description, default user name,
        // memory protection, master_key_changed, etc.) are gated on
        // settings_changed: only adopt source's values if source's settings
        // were updated more recently than target's. These are target-identity
        // fields, so this block is intentionally NOT run for cross-DB merges
        // (see merge_from_different_db below).
        // debug!("-- META: self.settings_changed {} other.settings_changed {}", &self.settings_changed, &other.settings_changed);
        if self.settings_changed < other.settings_changed {
            // debug!("-- META: self.settings_changed < other.settings_changed {}",self.settings_changed < other.settings_changed);
            if self.database_name != other.database_name {
                self.database_name = other.database_name.clone();
                self.database_name_changed = current_time;
                // debug!("-- META: database_name is changed");
                modified = true;
            }
            if self.database_description != other.database_description {
                self.database_description = other.database_description.clone();
                self.database_description_changed = current_time;
                // debug!("-- META: database_description is changed");
                modified = true;
            }

            if self.maintenance_history_days != other.maintenance_history_days {
                self.maintenance_history_days = other.maintenance_history_days.clone();
                // debug!("-- META: maintenance_history_days is changed");
                modified = true;
            }

            if self.memory_protection != other.memory_protection {
                self.memory_protection = other.memory_protection.clone();
                // debug!("-- META: memory_protection is changed");
                modified = true;
            }

            if self.entry_template_group != other.entry_template_group {
                self.entry_template_group = other.entry_template_group.clone();
                // debug!("-- META: entry_template_group is changed");
                modified = true;
            }

            if self.master_key_changed != other.master_key_changed {
                self.master_key_changed = other.master_key_changed.clone();
                // debug!("-- META: master_key_changed is changed");
                modified = true;
            }

            if self.default_user_name != other.default_user_name {
                self.default_user_name = other.default_user_name.clone();
                self.default_user_name_changed = current_time;
                // debug!("-- META: default_user_name is changed");
                modified = true;
            }
        }

        let (icons_modified, icon_remap) = self.merge_custom_icons(other)?;
        if icons_modified {
            modified = true;
        }

        if self.merge_custom_data(other, current_time) {
            modified = true;
        }

        if modified {
            // debug!("-- META: Before self.settings_changed {} ", &self.settings_changed);
            self.settings_changed = current_time;
            // debug!("-- META: After self.settings_changed {} ", &self.settings_changed);
        }

        Ok(MetaMergeReport {
            modified,
            icon_remap,
        })
    }

    // Cross-DB merge: source and target are unrelated databases (different
    // root_uuids). Used when the user imports one DB into another.
    //
    // Intentionally skips the settings_changed-gated identity block: target
    // keeps its own database_name, description, default_user_name,
    // memory_protection, master_key_changed, etc. — those are target's
    // identity, not properties of the data being imported.
    //
    // Custom icons and custom data are still merged because both are
    // inherently additive / dedup-aware:
    //   - custom icons: content-hash dedup, target-wins on UUID collision,
    //     append-only for genuinely new icons (same helper as merge()).
    //   - custom data: additive merge; existing keys keep their value unless
    //     source has the same key with a different value (then source wins
    //     for that single key). Source's custom-entry-type definitions and
    //     other meta-level keys get imported.
    //
    // The icon_remap returned here is used by Merger at every clone site
    // for source entries/groups, exactly the same as the same-DB path.
    pub fn merge_from_different_db(&mut self, other: &Meta) -> Result<MetaMergeReport> {
        let current_time = util::now_utc();
        let mut modified = false;

        let (icons_modified, icon_remap) = self.merge_custom_icons(other)?;
        if icons_modified {
            modified = true;
        }

        if self.merge_custom_data(other, current_time) {
            modified = true;
        }

        if modified {
            self.settings_changed = current_time;
        }

        Ok(MetaMergeReport {
            modified,
            icon_remap,
        })
    }

    // Merges source's custom_icons into self with content-hash dedup.
    // Returns (modified, icon_remap). Shared by both merge() and
    // merge_from_different_db() — the policy is identical for same-DB and
    // cross-DB merges because the dedup invariant is content-addressable and
    // target-wins on UUID collision is safe either way.
    fn merge_custom_icons(
        &mut self,
        other: &Meta,
    ) -> Result<(bool, HashMap<Uuid, Uuid>)> {
        let mut modified = false;
        let mut icon_remap: HashMap<Uuid, Uuid> = HashMap::new();

        log::debug!("Going to merge custom_icons in meta data ... and comparion custom icons {}",self.custom_icons != other.custom_icons);
        if self.custom_icons != other.custom_icons {
            // Index target icons by content hash for O(1) dedup lookup. The
            // dedup invariant mirrors add_custom_icon (custom_icons.rs): no two
            // icons in a DB should share bytes. Length pre-check would skip
            // hashing here, but pre-hashing target once is cheaper than
            // hashing per source icon with a length scan against every target.
            let mut target_by_hash: HashMap<Vec<u8>, Uuid> =
                HashMap::with_capacity(self.custom_icons.icons.len());
            for t in &self.custom_icons.icons {
                let h = crypto::sha256_hash_from_slice(&t.data)?;
                target_by_hash.insert(h, t.uuid);
            }

            log::debug!("Formed target_by_hash map with size {}",target_by_hash.len());

            for other_icon in other.custom_icons.icons.iter() {
                let other_hash = crypto::sha256_hash_from_slice(&other_icon.data)?;

                // (A) Same bytes already in target under some UUID. If the
                //     target UUID differs from the source UUID, record a remap
                //     so source-borne entries/groups will retarget to the
                //     existing target icon when they're cloned into target.
                if let Some(&target_uuid) = target_by_hash.get(&other_hash) {
                    if target_uuid != other_icon.uuid {
                        icon_remap.insert(other_icon.uuid, target_uuid);
                    }
                    continue;
                }

                // (B) Source UUID already in target but with different bytes
                //     (content hash didn't match in (A)). Follow KeePassXC's
                //     rule: target wins — leave target's icon alone.
                //     OneKeePass has no edit-icon operation, so a
                //     last_modification_time tie-breaker would not be
                //     meaningful here.
                if self
                    .custom_icons
                    .icons
                    .iter()
                    .any(|i| i.uuid == other_icon.uuid)
                {
                    continue;
                }

                // (C) Genuinely new icon: append, and re-index in case a
                //     subsequent source icon shares these bytes.
                target_by_hash.insert(other_hash, other_icon.uuid);
                self.custom_icons.icons.push(other_icon.clone());
                modified = true;
            }
        }

        Ok((modified, icon_remap))
    }

    // Additively merges source's custom_data into self. For overlapping keys
    // with differing values, source's value wins and last_modification_time
    // is stamped with current_time. Returns whether anything changed.
    //
    // Used by both merge() and merge_from_different_db(). On the cross-DB
    // path this is how source's custom-entry-type definitions (stored in
    // meta custom_data under OKP_ENTRY_TYPE_MAP_DATA) come over.
    fn merge_custom_data(&mut self, other: &Meta, current_time: NaiveDateTime) -> bool {
        let mut modified = false;
        if self.custom_data != other.custom_data {
            for other_item in other.custom_data.get_items() {
                if let Some(this_item) = self.custom_data.get_item_mut(&other_item.key) {
                    // Found a matching item
                    // TODO: Use this_item.last_modification_time ?
                    if this_item.value != other_item.value {
                        this_item.value = other_item.value.clone();
                        this_item.last_modification_time = Some(current_time);
                        // debug!("-- META: custom_data is changed");
                        modified = true;
                    }
                } else {
                    // No matching item found, create a new one
                    self.custom_data
                        .insert_item(Item::from_kv_with_modification_time(
                            &other_item.key,
                            &other_item.value,
                            current_time,
                        ));
                    // debug!("-- META: custom_data is inserted");
                    modified = true;
                }
            }

            // Need to drop any custom data item that are not found in source should be removed from target
        }
        modified
    }

    #[allow(unused)]
    #[cfg(test)]
    pub(crate) fn add_custom_icon(&mut self, icon_data: &Vec<u8>) {
        let mut icon = super::Icon::default();
        icon.uuid = Uuid::new_v4();
        icon.data = icon_data.clone();
        icon.last_modification_time = util::now_utc();
        self.custom_icons.icons.push(icon);
    }

    #[allow(unused)]
    #[cfg(test)]
    pub(crate) fn all_custom_icons(&self) -> &Vec<super::Icon> {
        &self.custom_icons.icons
    }
}
