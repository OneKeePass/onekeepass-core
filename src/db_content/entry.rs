use log::debug;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::constants::custom_data_key::{
    OKP_ENTRY_TYPE, OKP_ENTRY_TYPE_DATA, OKP_ENTRY_TYPE_DATA_INDEX, OKP_ENTRY_TYPE_LIST_DATA,
};
use crate::constants::entry_keyvalue_key::*;
use crate::db_content::{entry_type::*, Item};
use crate::db_content::{AttachmentHashValue, CustomData, Times};
use crate::util;

use super::meta::MetaShare;
use super::Meta;

// To carry additional entry field grouping and for easy KV data lookup
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EntryField {
    // Grouping of fields as sections maintained in EntryType
    pub(crate) entry_type: EntryType,
    // All fields of this entry. For easy look up, storesd in map
    // where the map keys for this map are from the key field value of KeyValue
    pub(crate) fields: HashMap<String, KeyValue>,
}

impl EntryField {
    fn _make_default_kvs(fields: &Vec<String>) -> Vec<KeyValue> {
        // All types will have these two fields by default
        let mut kvs = vec![
            KeyValue {
                key: TITLE.into(),
                value: String::default(),
                protected: false,
                data_type: FieldDataType::default(),
            },
            KeyValue {
                key: NOTES.into(),
                value: String::default(),
                protected: false,
                data_type: FieldDataType::default(),
            },
        ];

        for f in fields {
            kvs.push(KeyValue {
                key: f.into(),
                value: String::default(),
                protected: if f == PASSWORD { true } else { false }, // make it true for Password
                data_type: FieldDataType::default(),
            });
        }
        kvs
    }

    // Creates KeyValue structs for all FieldDefs found for this entry type
    fn from_field_defs(fields: &Vec<&FieldDef>) -> Vec<KeyValue> {
        // All types will have these two fields by default
        let mut kvs = vec![
            KeyValue {
                key: TITLE.into(),
                value: String::default(),
                protected: false,
                data_type: FieldDataType::Text,
            },
            KeyValue {
                key: NOTES.into(),
                value: String::default(),
                protected: false,
                data_type: FieldDataType::Text,
            },
        ];

        for f in fields {
            kvs.push(KeyValue {
                key: f.name.clone(),
                value: String::default(),
                protected: f.require_protection, //if f == PASSWORD { true } else { false }, // make it true for Password
                data_type: f.data_type,
            });
        }
        kvs
    }

    pub fn default_for_type_by_id(
        entry_type_uuid: &Uuid,
        custom_entry_type: Option<EntryType>,
    ) -> EntryField {
        let etype = match custom_entry_type {
            Some(ref et) => et,
            None => EntryType::standard_type_by_id(entry_type_uuid),
        };

        let fields = &etype
            .sections
            .iter()
            .flat_map(|s| &s.field_defs)
            .collect::<Vec<_>>();

        let kvs = EntryField::from_field_defs(fields);

        let mut entry_field = EntryField::default();
        entry_field.entry_type = etype.clone();
        //entry_field.entry_type.uuid = Uuid::new_v4(); // Should this be done in EntryType::default() ?
        entry_field.insert_key_values(kvs);
        entry_field
    }

    /// Called after reading the field KeyValue while parsing the XML content
    pub fn insert_key_value(&mut self, kv: KeyValue) {
        self.fields.insert(kv.key.clone(), kv);
    }

    pub fn insert_key_values(&mut self, kvs: Vec<KeyValue>) {
        for kv in kvs {
            self.fields.insert(kv.key.clone(), kv);
        }
    }

    /// Called to get all fields of this entry and used while writing to XML content
    pub fn get_key_values(&self) -> Vec<&KeyValue> {
        // Order of KeyValues are not guaranteed
        self.fields.values().collect()
    }

    pub fn find_key_value(&self, key: &str) -> Option<&KeyValue> {
        self.fields.values().find(|f| f.key == key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub(crate) uuid: Uuid,
    //The parent group uuid to refer back the group if required
    pub group_uuid: Uuid,
    pub icon_id: i32,
    pub times: Times,
    pub tags: String,
    pub entry_field: EntryField,
    //pub key_values: Vec<KeyValue>,
    pub binary_key_values: Vec<BinaryKeyValue>,
    pub custom_data: CustomData,
    pub history: History,
    #[serde(skip)]
    pub(crate) meta_share: Arc<MetaShare>,
}

impl Entry {
    pub fn new() -> Self {
        Entry {
            uuid: Uuid::default(),
            group_uuid: Uuid::default(),
            icon_id: i32::default(),
            times: Times::new(),
            tags: String::default(),
            entry_field: EntryField::default(),
            //key_values: vec![],
            binary_key_values: vec![],
            custom_data: CustomData::default(),
            //history has a list of previous entries and those entries listed will have its 'history' empty
            history: History::default(),
            meta_share: Arc::default(),
        }
    }

    pub fn new_blank_entry_by_type_id(
        entry_type_uuid: &Uuid,
        custom_entry_type: Option<EntryType>,
        parent_group_uuid: Option<&Uuid>,
    ) -> Entry {
        let entry_field = EntryField::default_for_type_by_id(entry_type_uuid, custom_entry_type);
        let mut entry = Entry::new();
        entry.uuid = uuid::Uuid::new_v4();
        //entry.times.expiry_time = util::add_years(entry.times.expiry_time, 3);
        entry.entry_field = entry_field;
        if let Some(gid) = parent_group_uuid {
            entry.group_uuid = *gid;
            // IMPORTANT: The caller needs to set the parent Group uuid if not passed
        }
        entry
    }

    // Any entry specific custom data parsing and setting in Entry to be done here
    pub fn after_xml_reading(&mut self, meta: &Meta) {
        self.meta_share = Arc::clone(&meta.meta_share);
        // Create EntryType from custom data
        let etype = self.dserilalize_to_entry_type();
        self.entry_field.entry_type = etype;

        // Note this entry's history entries' entry_field.entry_type is set on demand
        // That is when user selects a particular history index to display. See method history_entry_by_index
    }

    pub fn before_xml_writing(&mut self) {
        // Any entry customized data should copied back to custom data here so that we can persist in db
    }

    // Creates the EntryType for an entry from any previously serialized entry type data
    fn dserilalize_to_entry_type(&self) -> EntryType {
        // IMPORATNT: meta_share should have been set before calling this method so that
        // custom entry types can be considered
        if let Some(b64_uuid) = self.custom_data.get_item_value(OKP_ENTRY_TYPE) {
            let uuid = util::decode_uuid(b64_uuid).map_or(Uuid::default(), |u| u);
            debug!("Entry type uuid from custom data is {:?} ", &uuid);
            debug!(
                "And will look for entry type from the existing standard list or user generated custom entry type list"
            );
            if let Some(et) = self.meta_share.get_entry_type_by_id(&uuid) {
                debug!("Found user created custom entry type {:?} ", et);
                et
            } else {
                debug!("No user created entry type found and looking for a standard type with uuid {} in builtin standard types ", &uuid);
                EntryType::standard_type_by_id(&uuid).clone()
            }
        } else if let Some(data) = self.custom_data.get_item_value(OKP_ENTRY_TYPE_DATA) {
            debug!("Entry type is formed from decoding stored type data");
            //VersionedEntryType::from_name_prefixed_string(data)
            let custom_entry_types = self.meta_share.custom_entry_types_by_id.lock().unwrap();
            VersionedEntryType::decode_entry_type(data, &custom_entry_types)
        } else {
            // Return standard default
            debug!("No entry type info or data is found and will be using the default type");
            EntryType::default_type().clone()
        }
    }

    pub fn update(&mut self, mut updated_entry: Entry) {
        // The 'updated_entry' created in EntryDataForm will not have meta_share set
        // and we need to set it here
        updated_entry.meta_share = Arc::clone(&self.meta_share);

        // First we need to create history entries before any updates to the existing entry
        let histories = self.create_histories();

        // Change the last modified time
        // Only expiry related information is copied from the incoming updated_entry.times
        self.times.expires = updated_entry.times.expires;
        self.times.expiry_time = updated_entry.times.expiry_time;
        let now = util::now_utc();
        self.times.last_access_time = now;
        self.times.last_modification_time = now;

        self.binary_key_values = updated_entry.binary_key_values;
        self.history = History { entries: histories };
        self.group_uuid = updated_entry.group_uuid;
        self.icon_id = updated_entry.icon_id;
        self.tags = updated_entry.tags;

        self.entry_field = updated_entry.entry_field;

        // Call copy_to_custom_data after we set entry_field from the incoming updated_entry
        self.copy_to_custom_data();
        // Now we need to do this for the last added history entry
        self.serialize_last_history_entry_entry_type_data();
        self.adjust_history_entries_entry_type_indexes();
    }

    // Called when an entry is updated or a new entry inserted
    pub fn copy_to_custom_data(&mut self) {
        // To be safe first we need to remove the existing entry type related
        // keys. It is expected we have either OKP_ENTRY_TYPE or OKP_ENTRY_TYPE_DATA. Not both
        self.custom_data.remove_item(OKP_ENTRY_TYPE);
        self.custom_data.remove_item(OKP_ENTRY_TYPE_DATA);

        let mut insert_action = || {
            let custom_types = self.meta_share.custom_entry_types_by_id.lock().unwrap();
            if let Some(s) =
                VersionedEntryType::encode_entry_type(&self.entry_field.entry_type, &custom_types)
            {
                self.custom_data
                    .insert_item(Item::from_kv(OKP_ENTRY_TYPE_DATA, &s));
            }
        };

        // Need to check Custom Entry Types first as EntryType::standard_type will always return
        // an EntryType ( at least the default one)
        // Need to use if let Some(..) to use 'get_entry_type' without any temp variable issue
        if let Some(ref et) = self
            .meta_share
            .get_entry_type_by_id(&self.entry_field.entry_type.uuid)
        {
            if self.entry_field.entry_type.changed(et) {
                log::info!("The incoming Custom entry type (meta data) is changed and updating the entry type data in custom data item");
                insert_action();
            } else {
                // It is a custom entry type, but no new field added and just the custom entry type uuid is inserted in the custom data
                let b64_uuid = &util::encode_uuid(&self.entry_field.entry_type.uuid);
                log::info!("As there is no change to custom entry type info, only type's uuid as b64 str {} is saved", &b64_uuid);
                self.custom_data
                    .insert_item(Item::from_kv(OKP_ENTRY_TYPE, &b64_uuid));
            }
        } else if self
            .entry_field
            .entry_type
            .changed(EntryType::standard_type_by_id(
                &self.entry_field.entry_type.uuid,
            ))
        {
            log::info!("The incoming Standard entry type is changed and updating the entry type data in custom data item");
            insert_action();
        } else {
            // entries entry type info (meta data) is not changed and the standard entry type uuid is stored
            // But if it is the default one (Login type), then it is not saved to save space in xml

            if EntryType::default_type().uuid != self.entry_field.entry_type.uuid {
                log::info!(
                    "The entry uses a standard entry type which is not Login and the uuid b64 {} is saved",
                    &util::encode_uuid(&self.entry_field.entry_type.uuid)
                );
                self.custom_data.insert_item(Item::from_kv(
                    OKP_ENTRY_TYPE,
                    &util::encode_uuid(&self.entry_field.entry_type.uuid),
                ));
            } else {
                log::info!("The entry is default one and its uuid is not saved");
            }
        }
    }

    /// Called after loading the db file and xml is parsed
    pub fn set_attachment_hashes(
        &mut self,
        attachment_hash_indexed: &HashMap<i32, (AttachmentHashValue, usize)>,
    ) {
        //First we set all hashes for an entry followed by the entries found in its history
        for bv in &mut self.binary_key_values {
            if let Some(h) = attachment_hash_indexed.get(&bv.index_ref) {
                bv.data_hash = h.0;
                bv.data_size = h.1;
            }
        }
        //We call also the histories entries.
        //IMPORATNT: It is assumed each entry found in historty.entries should have empty history
        for e in &mut self.history.entries {
            e.set_attachment_hashes(attachment_hash_indexed);
        }
    }

    /// Called after forming inner header binary data and before writing xml as bytes
    pub fn set_attachment_index_refs(
        &mut self,
        hash_index_ref: &HashMap<AttachmentHashValue, i32>,
    ) {
        //First we set all index refs for an entry followed by the entries found in its history
        for bv in &mut self.binary_key_values {
            if let Some(idx) = hash_index_ref.get(&bv.data_hash) {
                bv.index_ref = *idx;
            } else {
                println!("Error: Index ref for the attachment with hash {} and name {} of entry uuuid {:?} is not found after writing to inner header", 
                &bv.data_hash, &bv.key, &self.uuid);
            }
        }
        //We call also the histories entries.
        //IMPORATNT: It is assumed each entry found in historty.entries should have empty history
        for e in &mut self.history.entries {
            e.set_attachment_index_refs(hash_index_ref);
        }
    }

    /// Gets the hash values of all attachments from this entry and the entries found in history field
    pub fn get_attachment_hashes(&self, hashes: &mut Vec<u64>) {
        //First we collect all hashes from an entry followed by the entries found in its history
        //let mut hashes = vec![];
        for bv in &self.binary_key_values {
            hashes.push(bv.data_hash);
        }
        //We call also the histories entries.
        //IMPORATNT: It is assumed each entry found in historty.entries should have empty history
        for e in &self.history.entries {
            e.get_attachment_hashes(hashes);
        }
    }

    // Finds a field's value from KeyValue
    pub fn find_kv_field_value(&self, name: &str) -> Option<String> {
        self.entry_field
            .find_key_value(name)
            .map(|x| x.value.clone())
    }
}

// All history entries related methods implemented on Entry are organized separately
// here for easy maintenance
//
// We need to use somewhat complex logic as explained briefly here:
// To avoid storing the serialized data of EntryType for each history entry and thus increasing db size,
// we keep one copy of all EntryTypes that are used in all history entries in custom data with key OKP_ENTRY_TYPE_LIST_DATA
// and using custom data with key OKP_ENTRY_TYPE_DATA_INDEX in its place and loading deserialized data
// on demand when user views each history entry in UI by going OKP_ENTRY_TYPE_DATA_INDEX -> OKP_ENTRY_TYPE_DATA.
// For example, if all history entries of the same as the main entry, we need not keep a separate EntryType data
// for each history entries. Instead it uses the same EntryType info from the main entry
impl Entry {
    // Called to recreate the history entries. The existing entry before update is
    // added to the history and returned
    fn create_histories(&mut self) -> Vec<Entry> {
        let mut existing_entry_copy: Entry = self.clone();

        // Remove any history related list of entry types. The existing_entry_copy will continue to have
        // other custom item OKP_ENTRY_TYPE or OKP_ENTRY_TYPE_DATA. The OKP_ENTRY_TYPE_DATA will be
        // replaced by OKP_ENTRY_TYPE_DATA_INDEX in the method 'copy_last_history_entry_to_custom_data'
        existing_entry_copy
            .custom_data
            .remove_item(OKP_ENTRY_TYPE_LIST_DATA);

        //Make a copy of the existing history entries
        let mut histories: Vec<Entry> = existing_entry_copy.history.entries;
        // We keep the max_items histories only
        let max_items_allowed = self.meta_share.history_max_items() as usize;
        if histories.len() >= max_items_allowed {
            let remove_count = histories.len() - max_items_allowed + 1; // +1 used as we will adding the existing_entry_copy
            histories = histories
                .into_iter()
                .skip(remove_count)
                .map(|e| e)
                .collect();
            debug!("Removed {} history items", { remove_count });
        }

        // TODO: Should we add removing all history entries that exceeds certain size ?
        // Or just do not add to the history any entry that exceeds certain size ?

        //existing_entry_copy should not have any history entries before adding to h
        existing_entry_copy.history.entries = vec![];

        // Add the existing_entry_copy as last item in the history list
        histories.push(existing_entry_copy);

        // This histories will set to the new updated entry
        histories
    }

    // Gets a history entry
    pub fn history_entry_by_index(&self, index: i32) -> Option<Entry> {
        let he = self.history.entries.get(index as usize).cloned();
        he.map(|mut e1| {
            // Need to set the appropriate group uuid to the history entry
            e1.group_uuid = self.group_uuid.clone();
            e1.meta_share = Arc::clone(&self.meta_share);
            // Set the history entry's entry_type
            Entry::replace_entry_type_index_by_type_data(&mut e1, &self.encoded_entry_types(true));
            e1
        })
    }

    pub fn delete_history_entry_by_index(&mut self, index: i32) {
        let idx = index as usize;
        if idx < self.history.entries.len() {
            let e = self.history.entries.remove(idx); // e is the deleted history entry
            let idx_opt = e.custom_data.get_item_value(OKP_ENTRY_TYPE_DATA_INDEX);
            if let Some(idx_s) = idx_opt {
                let mut encoded_ets = Entry::encoded_entry_types(&self, false);
                // Do the following if there is no other history entry has the same entry type index and
                // the index is not the same as the current entry index
                if Some(encoded_ets.len().to_string().as_str()) != idx_opt
                    && !self.history.entries.iter().any(|he| {
                        he.custom_data.get_item_value(OKP_ENTRY_TYPE_DATA_INDEX) == idx_opt
                    })
                {
                    debug!("Deleted index is {} should be removed from the list and other history entries indexes are adjusted", idx_s);

                    let idx = idx_s.parse::<i32>().unwrap_or(-1);
                    if idx != -1 {
                        debug!(
                            "Delete history entry: Size of list before adjustment {}",
                            encoded_ets.len()
                        );
                        encoded_ets.remove(idx as usize);

                        self.history.entries.iter_mut().for_each(|he| {
                            if let Some(idx_s1) =
                                he.custom_data.get_item_value(OKP_ENTRY_TYPE_DATA_INDEX)
                            {
                                if let Some(n) = idx_s1.parse::<usize>().ok() {
                                    if n > idx as usize {
                                        he.custom_data.update_item_value(
                                            OKP_ENTRY_TYPE_DATA_INDEX,
                                            &(n - 1).to_string(),
                                        );
                                    }
                                }
                            }
                        });
                        debug!(
                            "Delete history entry: Size of list after adjustment {}",
                            encoded_ets.len()
                        );
                        self.update_encoded_entry_type_list_data(encoded_ets);
                    }
                }
            }
        } else {
            log::error!(
                "delete_history_entry_by_index called with invalid index {}",
                idx
            );
        }

        // This is not required strictly
        if self.history.entries.is_empty() {
            // Remove OKP_ENTRY_TYPE_LIST_DATA that were used for history entries' entry type deserialization
            self.custom_data.remove_item(OKP_ENTRY_TYPE_LIST_DATA);
        }
    }

    // Deletes all the history entries of an entry
    pub fn delete_history_entries(&mut self) {
        self.history.entries.clear();
        // Remove OKP_ENTRY_TYPE_LIST_DATA that were used for history entries' entry type deserialization
        self.custom_data.remove_item(OKP_ENTRY_TYPE_LIST_DATA);
    }

    // Creates a list of base64 encoded str from the serialized entry type list data of all applicable entry types
    // used in some of the history entries
    fn encoded_entry_types(&self, include_current: bool) -> Vec<String> {
        let mut entry_types =
            if let Some(s) = self.custom_data.get_item_value(OKP_ENTRY_TYPE_LIST_DATA) {
                VersionedEntryType::encoded_entry_type_list_to_encoded_types(s)
            } else {
                vec![]
            };
        // Add this entry's OKP_ENTRY_TYPE_DATA as last item to the 'entry_types' if it is not there
        // This is required to create entry type from the serialized after converting OKP_ENTRY_TYPE_DATA_INDEX item to
        // OKP_ENTRY_TYPE_DATA
        if include_current {
            if let Some(t) = self.custom_data.get_item_value(OKP_ENTRY_TYPE_DATA) {
                if !entry_types.contains(&t.into()) {
                    entry_types.push(t.into());
                } else {
                    debug!("OKP_ENTRY_TYPE_LIST_DATA already has the current entry type and current entry type is not added to the list for reading");
                }
            }
        }
        entry_types
    }

    // Serializes all entry types used by the history entries of an entry and stores it
    // in the custom data item
    fn update_encoded_entry_type_list_data(&mut self, encoded_entry_types: Vec<String>) {
        if !encoded_entry_types.is_empty() {
            let size = encoded_entry_types.len();
            if let Some(ref d) =
                VersionedEntryType::encoded_types_to_encoded_type_list(encoded_entry_types)
            {
                self.custom_data
                    .insert_item(Item::from_kv(OKP_ENTRY_TYPE_LIST_DATA, d));
                debug!("Inserted item OKP_ENTRY_TYPE_LIST_DATA with size {}", size);
            }
        } else {
            debug!("The encoded_entry_types is empty and any previous custom data in OKP_ENTRY_TYPE_LIST_DATA will be deleted");
            self.custom_data.remove_item(OKP_ENTRY_TYPE_LIST_DATA);
        }
    }

    // Gets the EntryType for a history entry of an entry from the previously
    // serialized entry types list data by using the index reference of that data.
    fn replace_entry_type_index_by_type_data(history_entry: &mut Entry, entry_types: &Vec<String>) {
        // Need to form any required OKP_ENTRY_TYPE using the index found in
        // OKP_ENTRY_TYPE_DATA_INDEX and the arg 'entry_types' for each history entry here

        // Get the encoded entry type str using the index found from OKP_ENTRY_TYPE_DATA_INDEX
        // and corresponding entry type data found in 'entry_types' list
        // We need to convert index str to usize for indexing
        if let Some(encoded_et) = history_entry
            .custom_data
            .get_item_value(OKP_ENTRY_TYPE_DATA_INDEX)
            .and_then(|i: &str| entry_types.get(i.parse::<usize>().map_or(1000, |x| x)))
        {
            // This entry's OKP_ENTRY_TYPE_DATA is created for later use in the method
            // 'dserilalize_to_entry_type'
            history_entry
                .custom_data
                .insert_item(Item::from_kv(OKP_ENTRY_TYPE_DATA, encoded_et));

            // Should we remove OKP_ENTRY_TYPE_DATA_INDEX from this entry's custom data?
            history_entry
                .custom_data
                .remove_item(OKP_ENTRY_TYPE_DATA_INDEX);
        }
        // Now we can create entry type for this history entry
        history_entry.entry_field.entry_type = history_entry.dserilalize_to_entry_type();
    }

    // This ensures we do not serilaize the current Entry Type in OKP_ENTRY_TYPE_LIST_DATA
    // This is  generally this is not required. Only happens if the user restores any previously
    // entry from history that uses old entry type data
    fn adjust_history_entries_entry_type_indexes(&mut self) {
        let types_list = self.encoded_entry_types(false);
        let current_entry_type = self.custom_data.get_item_value(OKP_ENTRY_TYPE_DATA);
        if let Some(et) = current_entry_type {
            if types_list.contains(&et.into()) {
                debug!("encoded_entry_types conatins the current entry type serialized data and needs to be removed");
                // Re index all history entries
                // First we need to replace all OKP_ENTRY_TYPE_DATA_INDEX items of history entries by OKP_ENTRY_TYPE_DATA
                self.history.entries.iter_mut().for_each(|he| {
                    Entry::replace_entry_type_index_by_type_data(he, &types_list);
                });

                // Create new encoded_entry_types without the current entry type
                let mut encoded_entry_types: Vec<String> = types_list
                    .iter()
                    .filter(|s| *s != et)
                    .map(|s| s.clone())
                    .collect(); //vec![];
                self.history.entries.iter_mut().for_each(|he| {
                    Entry::replace_history_entry_type_data_by_index(
                        he,
                        &mut encoded_entry_types,
                        current_entry_type,
                    );
                });

                // Update the new OKP_ENTRY_TYPE_LIST_DATA items in the history entries
                self.update_encoded_entry_type_list_data(encoded_entry_types);
            }
        }
    }

    fn replace_history_entry_type_data_by_index(
        hist_entry: &mut Entry,
        encoded_entry_types: &mut Vec<String>,
        current_entry_type: Option<&str>,
    ) {
        let he_encoded_et_opt = hist_entry.custom_data.get_item_value(OKP_ENTRY_TYPE_DATA);
        if let Some(he_encoded_et_str) = he_encoded_et_opt {
            debug!(
                "History type data {:?} found in custom item",
                he_encoded_et_str
            );
            if encoded_entry_types.contains(&he_encoded_et_str.into()) {
                // unwrap will not fail as he_encoded_et_str is found in encoded_entry_types
                let index = encoded_entry_types
                    .iter()
                    .position(|x| x == &he_encoded_et_str)
                    .unwrap();
                debug!("Index of history type data is {} and will be set as value of  OKP_ENTRY_TYPE_DATA_INDEX", index);
                hist_entry
                    .custom_data
                    .insert_item(Item::from_kv(OKP_ENTRY_TYPE_DATA_INDEX, &index.to_string()));
            } else {
                if current_entry_type == he_encoded_et_opt {
                    debug!("Entry type of history entry and entry matched and will not be added to the encoded_entry_types list");
                    // this history entry's entry type is the same as entry's and it is the last entry in history entries
                    hist_entry.custom_data.insert_item(Item::from_kv(
                        OKP_ENTRY_TYPE_DATA_INDEX,
                        &(encoded_entry_types.len()).to_string(),
                    ));
                } else {
                    encoded_entry_types.push(he_encoded_et_str.into());
                    // The index is the index of the last element added just above
                    hist_entry.custom_data.insert_item(Item::from_kv(
                        OKP_ENTRY_TYPE_DATA_INDEX,
                        &(encoded_entry_types.len() - 1).to_string(),
                    ));
                    debug!(
                        "Else Index of history type data is {} and  added encoded_entry_type",
                        (encoded_entry_types.len() - 1)
                    );
                }
            }
            // Remove the Item OKP_ENTRY_TYPE_DATA (if any) of the history entry 'he' as
            // we have created OKP_ENTRY_TYPE_DATA_INDEX
            hist_entry.custom_data.remove_item(OKP_ENTRY_TYPE_DATA);
        }
    }

    // Only the last history entry' entry type data serialization is taken care of
    fn serialize_last_history_entry_entry_type_data(&mut self) {
        let mut encoded_entry_types: Vec<String> = self.encoded_entry_types(false);
        debug!(
            "Last history_entry Begin Entry's encoded_entry_types is {:?}",
            encoded_entry_types
        );
        let current_entry_type = self.custom_data.get_item_value(OKP_ENTRY_TYPE_DATA);
        // Get the recently inserted history entry
        if let Some(he) = self.history.entries.last_mut() {
            Entry::replace_history_entry_type_data_by_index(
                he,
                &mut encoded_entry_types,
                current_entry_type,
            );
        }

        debug!(
            "Last history_entry End Entry's encoded_entry_types is {:?}",
            encoded_entry_types
        );
        // Update the entry's OKP_ENTRY_TYPE_LIST_DATA using v from above
        self.update_encoded_entry_type_list_data(encoded_entry_types);
    }
}

// We may need to add additional entry field specific
// information here - field data type, length restriction etc and need to be
// transfered from and to Entry CustomData
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyValue {
    pub key: String,
    pub value: String,
    pub protected: bool,
    pub data_type: FieldDataType,
}

impl KeyValue {
    pub fn new() -> Self {
        KeyValue {
            key: String::default(),
            value: String::default(),
            protected: bool::default(),
            data_type: FieldDataType::default(),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BinaryKeyValue {
    /// Attachment name
    pub key: String,
    /// An empty tag with Ref attribute
    pub value: String,
    /// This is the index into the Inner header Binaries collection for this attachment
    pub index_ref: i32,
    #[serde(with = "util::from_or_to::string")]
    pub data_hash: AttachmentHashValue,
    pub data_size: usize,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct History {
    //History has a list of previous entries
    pub(crate) entries: Vec<Entry>,
}
