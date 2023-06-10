use chrono::{DateTime, Datelike, Local, NaiveDateTime};
use log::debug;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::From;
use uuid::Uuid;

use crate::constants::entry_keyvalue_key::*;
use crate::constants::entry_type_name::CREDIT_DEBIT_CARD;
use crate::password_generator::{score_password, PasswordScore};
use crate::util::{self, empty_str};

use crate::db_content::{
    join_tags, split_tags, BinaryKeyValue, Entry, EntryField, EntryType, FieldDataType, FieldDef,
    KeyValue, Section,
};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct KeyValueData {
    pub key: String,
    pub value: Option<String>,
    pub protected: bool,
    pub required: bool,
    pub helper_text: Option<String>,
    pub data_type: FieldDataType,
    pub standard_field: bool,
    // TODO: Use select_field name instead of forming options list everytime.
    pub select_field_options: Option<Vec<String>>,
    #[serde(skip_deserializing)]
    pub password_score: Option<PasswordScore>,
}

impl From<&KeyValue> for KeyValueData {
    fn from(kv: &KeyValue) -> Self {
        let password_score = if kv.key == PASSWORD {
            Some(score_password(&kv.value))
        } else {
            None
        };
        Self {
            key: kv.key.clone(),
            value: Some(kv.value.clone()),
            protected: kv.protected,
            required: false,
            helper_text: None,
            data_type: FieldDataType::default(),
            standard_field: false,
            select_field_options: None,
            password_score,
        }
    }
}

impl From<&KeyValueData> for KeyValue {
    fn from(kvd: &KeyValueData) -> Self {
        let mut kv = KeyValue::new();
        kv.key = kvd.key.clone();
        //For now, if the data type is Text
        kv.value = kvd
            .value
            .as_ref()
            .map_or_else(String::default, |v| v.clone());
        kv.protected = kvd.protected;
        kv
    }
}

impl From<&KeyValueData> for FieldDef {
    fn from(kvd: &KeyValueData) -> Self {
        Self {
            name: kvd.key.clone(),
            required: kvd.required,
            require_protection: kvd.protected,
            //helper_text: kvd.helper_text.clone(),
            data_type: kvd.data_type,
        }
    }
}

//const CUSTOM_FILEDS:&str = "Custom Fields";

use lazy_static::lazy_static;

lazy_static! {

    pub static ref CUSTOM_FILEDS:String = "Custom Fields".into();

    pub static ref CC_SELECT_FIELD_CHOICES: HashMap<&'static str, Vec<String>> =  {
        let local: DateTime<Local> = Local::now();

        let years:Vec<String> = (local.year()..(local.year()+10)).map(|n|n.to_string()).collect();
        //let v2: Vec<&'static str> = years.iter().map(|s| &**s).collect();
        let mut m = HashMap::new();
        m.insert("Brand",
            vec!["Visa", "Matercard",
                "American Express","Discover", "Diners Club",
                "Union Pay", "Other"].iter().map(|s|s.to_string()).collect());

        m.insert("Expiration Month",
            vec!["01-January", "02-February","03-March",
                "04-April","05-May","06-June", "07-July",
                "08-August","09-September","10-October",
                "11-November","12-December",
        ].iter().map(|s|s.to_string()).collect());
        m.insert("Expiration Year", years);
        m
    };
}

#[derive(Debug, Clone, Serialize, Deserialize)]
//#[serde(rename_all = "kebab-case")]
// Using the rename will only this struct. It will not rename the child struct fields 'kebab-case' unless
// that child is also this attribute. For now the UI layer changes to the required case
pub struct EntryFormData {
    pub uuid: Uuid,
    pub group_uuid: Uuid,
    pub icon_id: i32,

    pub last_modification_time: NaiveDateTime,
    pub creation_time: NaiveDateTime,
    pub last_access_time: NaiveDateTime,
    pub expires: bool,
    pub expiry_time: NaiveDateTime,

    pub tags: Vec<String>,
    pub binary_key_values: Vec<BinaryKeyValue>,
    pub history_count: i32,
    pub entry_type_name: String,
    pub entry_type_uuid: Uuid,
    pub entry_type_icon_name: Option<String>,
    pub title: String,
    pub notes: String,
    pub standard_section_names: Vec<String>,
    pub section_names: Vec<String>,
    pub section_fields: HashMap<String, Vec<KeyValueData>>,
}

impl EntryFormData {
    // Creates the EntryFormData from the given entry and is ready to be used by UI layer
    fn from_entry(entry: &Entry) -> Self {
        let entry_type_name = entry.entry_field.entry_type.name.clone();
        let entry_type_uuid = entry.entry_field.entry_type.uuid.clone();
        let entry_type_icon_name = entry.entry_field.entry_type.icon_name.clone();
        // Let us get the all section names
        let mut section_names: Vec<String> = entry
            .entry_field
            .entry_type
            .sections
            .iter()
            .map(|s| s.name.clone())
            .collect();

        let standard_field_names = entry.entry_field.entry_type.standard_field_names_by_id();
        // All available fields that are read from xml content
        let mut fields = entry.entry_field.fields.clone();

        // These two are treated separatley in UI layer. So we extract them from the list
        let title: String = fields
            .remove(TITLE)
            .map_or("No Title".into(), |x| x.value.clone());
        let notes: String = fields
            .remove(NOTES)
            .map_or(empty_str().into(), |x| x.value.clone());

        // All KVs per section name
        let mut section_fields: HashMap<String, Vec<KeyValueData>> = HashMap::default();

        for n in section_names.iter() {
            let section_opt = entry
                .entry_field
                .entry_type
                .sections
                .iter()
                .find(|s| &s.name == n);
            // Get the section
            if let Some(section) = section_opt {
                let mut kvs: Vec<KeyValueData> = vec![];
                // Copy the data type info to KVs
                for fd in section.field_defs.iter() {
                    // println!("Field Def is {:?}", fd);
                    // Remove the KV from fields for the matching name
                    if let Some(kv) = fields.remove(&fd.name) {
                        // Clone values from KeyValue to KeyValueData
                        let mut kvd: KeyValueData = (&kv).into();

                        // Additionally, the following field values are found in FieldDef and
                        // kvd is populated from them
                        kvd.data_type = fd.data_type;
                        kvd.required = fd.required;
                        kvd.helper_text = fd.helper_text(); //fd.helper_text.clone();
                        kvd.standard_field = standard_field_names.contains(&kv.key.as_str());

                        // This is specific to CREDIT_DEBIT_CARD entry form
                        if entry_type_name == CREDIT_DEBIT_CARD {
                            // TODO: Send only the field name instead of option list and UI should have pulled
                            // the list map one time and use the key to get options
                            if let Some(v) = CC_SELECT_FIELD_CHOICES.get(kvd.key.as_str()) {
                                kvd.select_field_options =
                                    Some(v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
                            }
                        }

                        kvs.push(kvd);
                    } else {
                        // The FieldDef of this entry type is not in KV. This can happen when new fields
                        // are added in standard types or when we need to use default entry type in case of deserilalizing issue
                        // debug!("Not found in KV - Field Def {:?}", fd);
                        let mut kvd: KeyValueData = KeyValueData::default();
                        kvd.data_type = fd.data_type;
                        kvd.required = fd.required;
                        kvd.helper_text = fd.helper_text(); //fd.helper_text.clone();
                        kvd.standard_field = standard_field_names.contains(&fd.name.as_str());
                        kvd.key = fd.name.clone();

                        kvs.push(kvd);
                    }
                }

                // Add all KVs for a section
                section_fields.insert(section.name.clone(), kvs);
            }
        }

        // Any left out KVs are meant for Custom Fields
        if fields.len() != 0 {
            // There is a possibility that user might have created a section with name CUSTOM_FILEDS
            // and in that case we need to add these extra fields to that section itself
            // Here we are assuming only the language 'en' at this time.
            // Also it is that assumed UI side the name 'Custom Fields' is checked to be unique
            // in a case insensitive manner - for example disallowing adding 'Custom Fields' and 'custom fields'
            // If user adds a new section with "custom fields" or "CUSTOM FIELDS" first time, UI side we need
            // to convert to "Custom Fields"
            // Need to figure out what to do for languages other than 'en'
            if let Some(mut all_custom_fields_kv_data) = section_fields.remove(&*CUSTOM_FILEDS) {
                all_custom_fields_kv_data.extend(fields.values().map(|kv| kv.into()));
                section_fields.insert(CUSTOM_FILEDS.clone(), all_custom_fields_kv_data);
            } else {
                section_names.push(CUSTOM_FILEDS.clone());
                section_fields.insert(
                    CUSTOM_FILEDS.clone(),
                    fields.values().map(|kv| kv.into()).collect(),
                );
            }
        }

        let standard_section_names = entry
            .entry_field
            .entry_type
            .standard_section_names_by_id()
            .iter()
            .map(|v| (*v).into())
            .collect();

        Self {
            uuid: entry.uuid,
            group_uuid: entry.group_uuid,
            icon_id: entry.icon_id,

            last_modification_time: entry.times.last_modification_time,
            creation_time: entry.times.creation_time,
            last_access_time: entry.times.last_access_time,
            expires: entry.times.expires,
            expiry_time: entry.times.expiry_time,

            history_count: entry.history.entries.len() as i32,
            entry_type_name,
            entry_type_uuid,
            entry_type_icon_name,
            title,
            notes,
            tags: split_tags(&entry.tags), //entry.tags.clone()
            binary_key_values: entry.binary_key_values.clone(),
            standard_section_names,
            section_names,
            section_fields,
        }
    }

    fn into_entry(entry_form_data: &EntryFormData) -> Entry {
        let title_kv = KeyValue {
            key: TITLE.into(),
            value: entry_form_data.title.clone(),
            protected: false,
            data_type: FieldDataType::default(),
        };
        let notes_kv = KeyValue {
            key: NOTES.into(),
            value: entry_form_data.notes.clone(),
            protected: false,
            data_type: FieldDataType::default(),
        };

        let mut entry_field = EntryField::default();
        entry_field.fields.insert(TITLE.into(), title_kv);
        entry_field.fields.insert(NOTES.into(), notes_kv);

        for section_name in entry_form_data.section_names.iter() {
            // For each section name found, we find all KVs and form EntryField
            if let Some(kvds) = entry_form_data.section_fields.get(section_name) {
                let mut fds: Vec<FieldDef> = vec![];
                for kvd in kvds {
                    // Each KV Data found for a section a KV is created and inserted to entry_filed.fields
                    entry_field.fields.insert(kvd.key.clone(), kvd.into());

                    // Also we preapare the data type info separately to store in EntryType sections
                    // All these values mostly will be the same what is sent to UI. Mainly in case of
                    // new fields, these are set in UI layer and we need to persist those
                    fds.push(kvd.into())
                }

                // Drop a section if it does not have any fields
                // Mostly this is possible if user removes all custom fields of a custom section
                // In case of standard sections, one or more field should be there
                if !fds.is_empty() {
                    entry_field.entry_type.sections.push(Section {
                        name: section_name.clone(),
                        field_defs: fds,
                    });
                }
                
            }
        }

        entry_field.entry_type.name = entry_form_data.entry_type_name.clone();
        entry_field.entry_type.uuid = entry_form_data.entry_type_uuid.clone();
        entry_field.entry_type.icon_name = entry_form_data.entry_type_icon_name.clone();

        let mut entry = Entry::new();
        entry.uuid = entry_form_data.uuid;
        entry.group_uuid = entry_form_data.group_uuid;

        entry.entry_field = entry_field;
        entry.icon_id = entry_form_data.icon_id;
        entry.tags = join_tags(&entry_form_data.tags);
        entry.times.expires = entry_form_data.expires;
        entry.times.expiry_time = entry_form_data.expiry_time;

        entry
    }

    // pub fn new_form_entry_by_type(
    //     entry_type_name: &str,
    //     custom_entry_type: Option<EntryType>,
    //     parent_group_uuid: Option<&Uuid>,
    // ) -> Self {
    //     //parent_group_uuid.as_ref().as_deref()
    //     let e =
    //         &Entry::new_blank_entry_by_type(entry_type_name, custom_entry_type, parent_group_uuid);
    //     e.into()
    // }

    pub fn new_form_entry_by_type_id(
        entry_type_uuid: &Uuid,
        custom_entry_type: Option<EntryType>,
        parent_group_uuid: Option<&Uuid>,
    ) -> Self {
        //parent_group_uuid.as_ref().as_deref()
        let e = &Entry::new_blank_entry_by_type_id(
            entry_type_uuid,
            custom_entry_type,
            parent_group_uuid,
        );
        e.into()
    }
}

impl From<&Entry> for EntryFormData {
    fn from(entry: &Entry) -> Self {
        EntryFormData::from_entry(entry)
    }
}

impl From<&EntryFormData> for Entry {
    fn from(entry_form_data: &EntryFormData) -> Self {
        EntryFormData::into_entry(entry_form_data)
    }
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
pub struct EntrySummary {
    pub uuid: String,
    pub title: Option<String>,
    pub secondary_title: Option<String>, //usually the user name
    pub icon_id: i32,
    pub history_index: Option<i32>,
}

impl EntrySummary {
    pub fn history_entries_summary(entry: &Entry) -> Vec<EntrySummary> {
        let mut summary_list: Vec<EntrySummary> = vec![];
        //for he in &entry.history.entries {
        for (i, he) in entry.history.entries.iter().enumerate() {
            let kv = he.entry_field.find_key_value("Title");
            //let ht = he.times.last_modification_time.format("%Y-%m-%dT%H:%M:%S");

            summary_list.push(Self {
                uuid: he.uuid.to_string(),
                title: kv.map(|x| x.value.clone()),
                // There is some issue of using chrono Local to get the time in local TZ in mac 12.6+ in M1
                // See more details in util.rs test. The utc time is set here and in the UI side, the datetime in local TZ shown
                secondary_title: Some(
                    he.times
                        .last_modification_time
                        .format("%Y-%m-%dT%H:%M:%S")
                        .to_string(),
                ),
                // secondary_title: Some(util::format_utc_naivedatetime_to_local(
                //     &he.times.last_modification_time,
                //     Some("%Y-%m-%d %I:%M:%S %p"),
                // )),
                icon_id: he.icon_id,
                history_index: Some(i as i32),
            });
        }
        summary_list
    }

    // Gets the secondary title to show in addition to main title while displaying
    // an entry item in a list - a UI specific thing
    fn secondary_title(entry: &Entry) -> Option<String> {
        if entry.entry_field.entry_type.name == CREDIT_DEBIT_CARD {
            entry.entry_field.find_key_value(NUMBER).map(|f| {
                let s = f.value.trim();
                if !s.is_empty() {
                    if s.len() > 4 {
                        s.split_at(s.len() - 4).1.into()
                    } else {
                        s.into()
                    }
                } else {
                    util::empty_str()
                }
            })
        } else if let Some(ref t) = entry.entry_field.entry_type.secondary_title {
            entry.find_kv_field_value(t)
        } else {
            let secondary_title: Option<String> = entry
                .entry_field
                .entry_type
                .sections
                .iter()
                .filter(|s| s.field_defs.len() > 0)
                .nth(0) // First Section thas has some fields
                .map(|s| {
                    s.field_defs
                        .iter()
                        .filter(|f| !f.require_protection) //Skip the Password field
                        .nth(0) // Get the first fieldDef
                        .map_or("", |f| &f.name)
                }) // First field's name
                .map(|n| entry.entry_field.find_key_value(n))
                .flatten() // To get Option<Option<&KeyValue>> to Option<&KeyValue>
                .and_then(|kv| Some(kv.value.clone()));

            secondary_title
        }
    }

    pub fn entry_summary_data(entries: Vec<&Entry>) -> Vec<EntrySummary> {
        let mut summary_list: Vec<EntrySummary> = vec![];
        for e in entries {
            let title = e.find_kv_field_value(TITLE);
            let secondary_title = EntrySummary::secondary_title(e);
            summary_list.push(Self {
                uuid: e.uuid.to_string(),
                title,
                secondary_title,
                icon_id: e.icon_id,
                history_index: None,
            });
        }
        summary_list
    }
}

#[derive(Serialize, Deserialize)]
pub struct EntryTypeNames {
    pub custom: Vec<String>,
    pub standard: Vec<String>,
}

#[derive(Default, Serialize, Deserialize)]
pub struct EntryTypeHeader {
    pub uuid: Uuid,
    pub name: String,
    pub icon_name: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct EntryTypeHeaders {
    pub custom: Vec<EntryTypeHeader>,
    pub standard: Vec<EntryTypeHeader>,
}

// EntryTypeFormData has some fields of EntryFormData and name of these fields
// should match as UI layer uses EntryFormData for both entry and entry type forms
#[derive(Serialize, Deserialize)]
pub struct EntryTypeFormData {
    pub entry_type_name: String,
    pub entry_type_icon_name: Option<String>,
    pub section_names: Vec<String>,
    pub section_fields: HashMap<String, Vec<KeyValueData>>,
}

// Used to create a new custom entry type. The incoming EntryTypeFormData has information
// to create a custom entry type except the entry type uuid
impl From<&EntryTypeFormData> for EntryType {
    fn from(entry_type_form_data: &EntryTypeFormData) -> Self {
        let section_fields: Vec<Section> =
            entry_type_form_data
                .section_names
                .iter()
                .fold(vec![], |mut v, n| {
                    let section = Section {
                        name: n.clone(),
                        field_defs: match entry_type_form_data.section_fields.get(n) {
                            Some(vf) => vf.iter().map(|kvd| kvd.into()).collect(),
                            None => vec![],
                        },
                    };
                    v.push(section);
                    v
                });
        let mut et = EntryType::default();
        // IMPORTANT:
        // Need to generate a new uuid for this new custom entry type
        // In case, we change the custom type creation flow and the incoming entry_type_form_data has uuid already set
        // then we need to use that instead of creating a new one
        et.uuid = Uuid::new_v4();
        et.name = entry_type_form_data.entry_type_name.clone();
        et.sections = section_fields;
        et.icon_name = entry_type_form_data.entry_type_icon_name.clone();
        et
    }
}

#[cfg(test)]
mod tests {
    use crate::constants::entry_type_uuid;
    use crate::db_content::*;
    use crate::form_data::*;

    #[test]
    fn verify_creating_display_entry() {
        let uuid = uuid::Builder::from_slice(&entry_type_uuid::LOGIN)
            .unwrap()
            .build();
        let mut entry = Entry::new_blank_entry_by_type_id(&uuid, None, None);

        entry.entry_field.fields.insert(
            "Title".into(),
            KeyValue {
                key: "Title".into(),
                value: "Test Title".into(),
                protected: false,
                data_type: FieldDataType::default(),
            },
        );

        let custom_fields = vec![
            KeyValue {
                key: "Custom First Name".into(),
                value: String::default(),
                protected: false,
                data_type: FieldDataType::default(),
            },
            KeyValue {
                key: "Custom Last Name".into(),
                value: String::default(),
                protected: false,
                data_type: FieldDataType::default(),
            },
            KeyValue {
                key: "My quetsion:*".into(),
                value: String::default(),
                protected: true,
                data_type: FieldDataType::default(),
            },
        ];

        entry.tags = "Tag1;Tag2;Tag6;Bank Account".into();
        for fld in custom_fields {
            entry.entry_field.fields.insert(fld.key.clone(), fld);
        }

        let de: EntryFormData = (&entry).into(); // same as EntryFormData::from(&entry);

        //println!("Entry {:?}", entry);
        //println!("{:?}", de);
        let json_str = serde_json::to_string_pretty(&de).unwrap();
        println!("{}", json_str);

        assert_eq!(
            de.section_fields.get("Custom Fields").unwrap().len() == 3,
            true
        );
        assert_eq!(
            de.section_fields
                .get("Custom Fields")
                .unwrap()
                .iter()
                .find(|kv| kv.key == "Custom First Name")
                .is_some(),
            true
        );
    }
}
