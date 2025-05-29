use chrono::{DateTime, Datelike, Local, NaiveDateTime};
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::From;
use uuid::Uuid;

use crate::constants::entry_keyvalue_key::*;
use crate::constants::entry_type_name::CREDIT_DEBIT_CARD;
use crate::constants::standard_in_section_names::ADDITIONAL_ONE_TIME_PASSWORDS;
use crate::password_passphrase_generator::PasswordScore;

use crate::util::{self, empty_str};

use crate::error::{Error, Result};

use crate::db_content::{
    join_tags, split_tags, AutoType, BinaryKeyValue, Entry, EntryField, EntryType, FieldDataType,
    FieldDef, KeepassFile, KeyValue, OtpData, Root, Section,
};

pub use crate::db_content::CurrentOtpTokenData;

// #[derive(Debug, Clone, Serialize)]
// #[serde(tag = "type_name", content = "content")]
// pub enum KeyValueAdditionalData {
//     // Entry PlaceHolder Parsed value
//     Resolved(Option<String>),
// }

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct KeyValueData {
    key: String,
    value: Option<String>,
    protected: bool,
    required: bool,
    helper_text: Option<String>,
    data_type: FieldDataType,
    standard_field: bool,

    // TODO: Use select_field name instead of forming options list everytime.
    pub select_field_options: Option<Vec<String>>,

    // Only relevant for PASSWORD field and in other cases it is None
    // We get the PasswordScore based on the String value of password
    // Only serialization is enabled so as to send the data to UI
    #[serde(skip_deserializing)]
    pub password_score: Option<PasswordScore>,

    // Following are set on otp token generation
    // Should this also use 'skip_deserializing' ?
    pub current_opt_token: Option<CurrentOtpTokenData>,
    // Future idea to use instead of adding separate fields as done using 'password_score' and 'current_opt_token' ?
    // #[serde(skip_deserializing)]
    // pub additional_data: Option<KeyValueAdditionalData>,
}

impl From<&KeyValue> for KeyValueData {
    fn from(kv: &KeyValue) -> Self {
        let password_score = if kv.key == PASSWORD {
            Some((&kv.value).into())
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
            current_opt_token: None,
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

impl KeyValueData {
    fn generate_otp(&mut self, parsed_otp_values: &Option<HashMap<String, OtpData>>) {
        if self.data_type == FieldDataType::OneTimePassword {
            if let Some(parsed_otp_data) =
                parsed_otp_values.as_ref().and_then(|pm| pm.get(&self.key))
            {
                match parsed_otp_data.current_otp_token_data() {
                    Ok(token_data) => {
                        self.current_opt_token = Some(token_data);
                    }
                    Err(e) => {
                        info!("Generating current otp failed {}", e);
                    }
                }
            }
        }
    }

    // Called to generate an otp token if there is a parsed otp data available for this KV
    // The data type will be overriden to be 'OneTimePassword'
    fn _generate_otp_on_check(&mut self, parsed_otp_values: &Option<HashMap<String, OtpData>>) {
        if let Some(m) = parsed_otp_values.as_ref() {
            if m.contains_key(&self.key) {
                // We need to set data type as this field has a valid otp url
                self.data_type = FieldDataType::OneTimePassword;
                self.generate_otp(parsed_otp_values);
            }
        }
    }
}

use lazy_static::lazy_static;

use super::{categories, parsing};

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
// that child is also has this attribute. For now the UI layer changes to the required case
pub struct EntryFormData {
    uuid: Uuid,

    // TODO:
    // Need to change this field name to 'parent_group_uuid' as used in Entry and Group struct.
    // But this requires additional changes on the UI cljs code also
    group_uuid: Uuid,

    icon_id: i32,

    last_modification_time: NaiveDateTime,
    creation_time: NaiveDateTime,
    last_access_time: NaiveDateTime,
    expires: bool,
    expiry_time: NaiveDateTime,

    tags: Vec<String>,
    binary_key_values: Vec<BinaryKeyValue>,
    history_count: i32,
    entry_type_name: String,
    entry_type_uuid: Uuid,
    entry_type_icon_name: Option<String>,
    title: String,
    notes: String,

    standard_section_names: Vec<String>,
    section_names: Vec<String>,

    // For lookup by section name (section name is the key)
    section_fields: HashMap<String, Vec<KeyValueData>>,

    auto_type: AutoType,

    // This map has keys from kvd key (uppercase) and values are from kvd value that has some
    // placeholder, parsed and resolved
    #[serde(skip_deserializing)]
    parsed_fields: HashMap<String, String>,
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
        // Kept in a map for easy access using its name
        let mut fields = entry.entry_field.fields.clone();

        // Keep track of all field names that are added to various sections
        let mut field_names_done: Vec<String> = vec![];

        // These two are treated separatley in UI layer. So we extract them from the list
        let title: String = fields
            .remove(TITLE)
            .map_or("No Title".into(), |x| x.value.clone());
        let notes: String = fields
            .remove(NOTES)
            .map_or(empty_str().into(), |x| x.value.clone());

        // All KVs per section name
        let mut section_fields: HashMap<String, Vec<KeyValueData>> = HashMap::default();

        // Combines each KeyValue with its field definition
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

                    // Remove the KV from 'fields' for the field def matching name
                    if let Some(kv) = fields.remove(&fd.name) {
                        // Clone values from KeyValue to KeyValueData
                        let mut kvd: KeyValueData = (&kv).into();

                        // Following may be requird when we change a field's protection flag
                        // in FieldDef from its earlier definition.
                        // May Need more tests to confirm no other issue.
                        // if kvd.protected != fd.require_protection {
                        //     // Overriding the old protected flag read from db with new value from
                        //     // field definition
                        //     kvd.protected = fd.require_protection;
                        // }

                        // Additionally, the following field values are found in FieldDef and
                        // kvd is populated from them
                        kvd.data_type = fd.data_type;
                        kvd.required = fd.required;
                        kvd.helper_text = fd.helper_text();
                        kvd.standard_field = standard_field_names.contains(&kv.key.as_str());

                        // We generate token only if the data type of this field is 'OneTimePassword' type
                        if fd.data_type == FieldDataType::OneTimePassword {
                            kvd.generate_otp(&entry.parsed_otp_values);
                        }

                        // kvd.generate_otp_on_check(&entry.parsed_otp_values);

                        // This is specific to CREDIT_DEBIT_CARD entry form
                        if entry_type_name == CREDIT_DEBIT_CARD {
                            // TODO: Send only the field name instead of option list and UI should have pulled
                            // the list map one time and use the key to get options
                            if let Some(v) = CC_SELECT_FIELD_CHOICES.get(kvd.key.as_str()) {
                                kvd.select_field_options =
                                    Some(v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
                            }
                        }
                        // Now this field is used to create KVD
                        field_names_done.push(kv.key.clone());

                        kvs.push(kvd);
                    } else {
                        // The FieldDef of this entry type is not in KV. This can happen when new fields
                        // are added in standard types or when we need to use default entry type in case of deserilalizing issue

                        // Need to ensure that the field name of this 'fd.name' is NOT yet
                        // added earlier to any other section.

                        // This will happen in a situation when a new field is introduced later in the standard section with same name as
                        // in any previously user added custom section

                        // For example, let us assume we have a previously user defined section "Section1" with field name "UserName" for
                        // this standard entry type
                        // Now assume that this entry type does not have "Login Details".
                        // If a section with name "Login Details"is added to this standard type that includes the
                        // field name "UserName", then we do not want to have duplicate "UserName" fields in both "Login Details" and "Section1"
                        // The following check ensures that this does not happen

                        if field_names_done.contains(&fd.name) {
                            continue;
                        }

                        // debug!("Not found in KV - Field Def {:?}", fd);
                        let mut kvd: KeyValueData = KeyValueData::default();
                        kvd.data_type = fd.data_type;
                        kvd.required = fd.required;
                        kvd.helper_text = fd.helper_text(); //fd.helper_text.clone();
                        kvd.standard_field = standard_field_names.contains(&fd.name.as_str());
                        kvd.key = fd.name.clone();

                        // Completed the combining of this field with its definition to create KVD
                        field_names_done.push(kvd.key.clone());

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
                all_custom_fields_kv_data.extend(fields.values().map(|kv| {
                    // let mut kvd: KeyValueData = kv.into();
                    // There is a possibility a field may have a valid totp url created in other app
                    // In that case, we need to generate token and set its data type
                    // kvd.generate_otp_on_check(&entry.parsed_otp_values);
                    kv.into()
                }));
                section_fields.insert(CUSTOM_FILEDS.clone(), all_custom_fields_kv_data);
            } else {
                section_names.push(CUSTOM_FILEDS.clone());
                section_fields.insert(
                    CUSTOM_FILEDS.clone(),
                    fields
                        .values()
                        .map(|kv| {
                            // let mut kvd: KeyValueData = kv.into();
                            // There is a possibility a field may have a valid totp url created in other app
                            // In that case, we need to generate token and set its data type
                            // kvd.generate_otp_on_check(&entry.parsed_otp_values);

                            kv.into()
                        })
                        .collect(),
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
            group_uuid: entry.parent_group_uuid,
            icon_id: entry.icon_id,

            last_modification_time: entry.times.last_modification_time,
            creation_time: entry.times.creation_time,
            last_access_time: entry.times.last_access_time,
            expires: entry.times.expires,
            expiry_time: entry.times.expiry_time,

            auto_type: entry.auto_type.clone(),

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
            parsed_fields: HashMap::default(),
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

        // section_names is list of all section names
        // Order of section and the fields order within a section are maintained for minimal
        // Entrytype data storage
        // See Entry's 'copy_to_custom_data' call flow where we store only the changed type information

        for section_name in entry_form_data.section_names.iter() {
            // For each section name found, we find all KVs and form EntryField
            if let Some(kvds) = entry_form_data.section_fields.get(section_name) {
                let mut fds: Vec<FieldDef> = vec![];
                for kvd in kvds {
                    // Here we are assuming we have unique field names for an entry
                    // If we allow duplicate field names, we may need to check whether the kvd is already considerd or not using
                    // entry_field.fields.contains_key(&kvd.key) and consider only the first or last value

                    // Each KV Data found for a section a KV is created and inserted to entry_filed.fields
                    entry_field.fields.insert(kvd.key.clone(), kvd.into());

                    // Also we preapare the data type info separately to store in EntryType sections
                    // All these values mostly will be the same what is sent to UI. Mainly in case of
                    // new fields, these are set in UI layer and we need to persist those
                    fds.push(kvd.into())
                }

                // Drop a section if it does not have any fields
                // Mostly this is possible if user removes all custom fields of a custom section
                // In case of standard sections, one or more field should be there except for the ADDITIONAL_ONE_TIME_PASSWORDS section
                if section_name == ADDITIONAL_ONE_TIME_PASSWORDS || !fds.is_empty() {
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
        entry.parent_group_uuid = entry_form_data.group_uuid;

        entry.entry_field = entry_field;
        entry.icon_id = entry_form_data.icon_id;
        entry.tags = join_tags(&entry_form_data.tags);
        entry.times.expires = entry_form_data.expires;
        entry.times.expiry_time = entry_form_data.expiry_time;

        entry.auto_type = entry_form_data.auto_type.clone();

        // Attachment references if any
        entry.binary_key_values = entry_form_data.binary_key_values.clone();

        entry
    }

    // Resolves all place holders for the entry fields
    pub(crate) fn place_holder_resolved_form_data(root: &Root, entry: &Entry) -> Self {
        let mut form_data = EntryFormData::from_entry(entry);
        form_data.parsed_fields =
            parsing::EntryPlaceHolderParser::resolve_place_holders(root, entry);
        form_data
    }

    // Extracts all entry field values as a map and apply any enrty field palceholder parsing
    pub(crate) fn entry_key_value_fields(
        kp: &KeepassFile,
        entry_uuid: &Uuid,
    ) -> Result<HashMap<String, String>> {
        let entry = kp
            .root
            .entry_by_id(entry_uuid)
            .ok_or(Error::NotFound("No entry Entry found for the id".into()))?;

        let mut kvs = entry.field_values();
        let parsed_fields = parsing::EntryPlaceHolderParser::resolve_place_holders(&kp.root, entry);

        if !parsed_fields.is_empty() {
            for (field_name, field_value) in kvs.iter_mut() {
                if let Some(parsed_field_val) = parsed_fields.get(&field_name.to_uppercase()) {
                    // field_value is &mut String and *field_value is used to update this
                    *field_value = parsed_field_val.clone();
                }
            }
        }

        Ok(kvs)
    }

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

impl Entry {
    pub(crate) fn extract_place_holders(&self) -> HashMap<String, String> {
        let mut entry_fields_with_place_holders: HashMap<String, String> = HashMap::default();

        // Checks whether any one of the entry field contain palce holder variable
        let parsing_required = self.entry_field.fields.values().into_iter().any(|kvd| {
            if !kvd.value.trim().is_empty() {
                parsing::place_holder_marker_found(&kvd.value)
            } else {
                false
            }
        });

        if parsing_required {
            // All non empty field values are collected to a HashMap irresespective whether the field
            // contain placeholder or not
            entry_fields_with_place_holders = self.entry_field.fields.values().into_iter().fold(
                entry_fields_with_place_holders,
                |mut acc, kvd| {
                    if !kvd.value.trim().is_empty() {
                        // We make all keys to UpperCase
                        acc.insert(kvd.key.to_uppercase(), kvd.value.to_string());
                    }
                    acc
                },
            );
        }

        entry_fields_with_place_holders
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
    pub parent_group_uuid:Uuid,
    pub title: Option<String>,
    pub secondary_title: Option<String>, //usually the user name
    pub icon_id: i32,
    pub history_index: Option<i32>,
    pub modified_time: Option<i64>,
    pub created_time: Option<i64>,
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
                // We use the entry's parent group uuid for its history
                parent_group_uuid: entry.parent_group_uuid(),
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
                modified_time: None,
                created_time: None,
            });
        }
        summary_list
    }

    // Gets the secondary title to show in addition to main title while displaying
    // an entry item in a list - a UI specific thing
    fn secondary_title(entry: &Entry, parsed_fields: &HashMap<String, String>) -> Option<String> {
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
            let val = entry.find_kv_field_value(t);
            if parsed_fields.is_empty() {
                val
            } else {
                parsed_fields
                    .get(&t.to_uppercase())
                    .map_or(val, |s| Some(s.to_string()))
            }
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
                .and_then(|kv| {
                    if parsed_fields.is_empty() {
                        Some(kv.value.clone())
                    } else {
                        parsed_fields
                            .get(&kv.key.to_uppercase())
                            .map_or_else(|| Some(kv.value.clone()), |s| Some(s.to_string()))
                    }
                });

            secondary_title
        }
    }

    pub fn entry_summary_data<'a>(
        kp: &'a KeepassFile,
        entry_category: &'a categories::EntryCategory,
    ) -> Vec<EntrySummary> {
        let entries: Vec<&Entry> = categories::entry_by_category(kp, entry_category);
        let mut summary_list: Vec<EntrySummary> = vec![];
        let title_upper = TITLE.to_uppercase();
        for e in entries {
            let parsed_fields = parsing::EntryPlaceHolderParser::resolve_place_holders(&kp.root, e);
            let title = parsed_fields
                .get(&title_upper)
                .map_or_else(|| e.find_kv_field_value(TITLE), |s| Some(s.to_string())); //e.find_kv_field_value(TITLE);
            let secondary_title = EntrySummary::secondary_title(e, &parsed_fields);
            summary_list.push(Self {
                uuid: e.uuid.to_string(),
                parent_group_uuid:e.parent_group_uuid(),
                title,
                secondary_title,
                icon_id: e.icon_id,
                history_index: None,
                #[allow(deprecated)]
                modified_time: Some(e.times.last_modification_time.timestamp()),
                #[allow(deprecated)]
                created_time: Some(e.times.creation_time.timestamp()),
            });
        }
        summary_list
    }

    // pub fn entry_summary_data(entries: Vec<&Entry>) -> Vec<EntrySummary> {
    //     let mut summary_list: Vec<EntrySummary> = vec![];
    //     for e in entries {
    //         let title = e.find_kv_field_value(TITLE);
    //         let secondary_title = EntrySummary::secondary_title(e);
    //         summary_list.push(Self {
    //             uuid: e.uuid.to_string(),
    //             title,
    //             secondary_title,
    //             icon_id: e.icon_id,
    //             history_index: None,
    //             modified_time: Some(e.times.last_modification_time.timestamp()),
    //             created_time: Some(e.times.creation_time.timestamp()),
    //         });
    //     }
    //     summary_list
    // }
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
    use crate::constants::entry_keyvalue_key::*;
    use crate::constants::entry_type_uuid;
    use crate::db_content::*;
    use crate::form_data::*;

    #[test]
    fn verify_place_holder_parsing() {
        let uuid = uuid::Builder::from_slice(&entry_type_uuid::LOGIN)
            .unwrap()
            .into_uuid();
        let mut entry = Entry::new_blank_entry_by_type_id(&uuid, None, None);

        entry.entry_field.fields.insert(
            "Title".into(),
            KeyValue {
                key: "Title".into(),
                value: "Test {USERNAME} Title".into(),
                protected: false,
                data_type: FieldDataType::default(),
            },
        );

        entry
            .entry_field
            .update_value(USER_NAME, "My first {URL} name");

        entry
            .entry_field
            .update_value(URL, "https://www.oracle.com");

        let mut root = Root::new();
        root.set_root_uuid(uuid::Uuid::new_v4());
        let root_group = Group::new_with_id();
        // root_group.uuid = root.root_uuid();
        root.insert_to_all_groups(root_group);

        let mut parent_group = Group::new_with_id();
        // parent_group.uuid = uuid::Uuid::new_v4();
        parent_group.parent_group_uuid = root.root_uuid();

        entry.parent_group_uuid = parent_group.uuid;

        root.insert_group(parent_group).unwrap();
        root.insert_entry(entry.clone()).unwrap();

        let form_data = EntryFormData::place_holder_resolved_form_data(&root, &entry);

        println!("Form data is {:?}", &form_data.parsed_fields);

        let resolved = form_data.parsed_fields.get("USERNAME").unwrap();
        assert_eq!("My first https://www.oracle.com name", resolved);
    }

    #[test]
    fn verify_creating_display_entry() {
        let uuid = uuid::Builder::from_slice(&entry_type_uuid::LOGIN)
            .unwrap()
            .into_uuid();
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

/*
fn form_data_from_entry(root: &Root, entry: &Entry) -> Self {
        let mut form_data = EntryFormData::from_entry(entry);

        let mut entry_fields_with_place_holders: HashMap<String, String> = HashMap::default();
        let mut parsing_required = false;
        if parsing::place_holder_marker_found(&form_data.title) {
            entry_fields_with_place_holders.insert("TITLE".into(), form_data.title.clone());
        }

        if parsing::place_holder_marker_found(&form_data.notes) {
            entry_fields_with_place_holders.insert("NOTES".into(), form_data.title.clone());
        }

        parsing_required = form_data
            .section_fields
            .values()
            .into_iter()
            .flatten()
            .any(|kvd| {
                if let Some(ref val) = kvd.value {
                    parsing::place_holder_marker_found(val)
                } else {
                    false
                }
            });

        if parsing_required {
            entry_fields_with_place_holders = form_data
                .section_fields
                .values()
                .into_iter()
                .flatten()
                .fold(entry_fields_with_place_holders, |mut acc, kvd| {
                    if let Some(ref val) = kvd.value {
                        if !val.trim().is_empty() {
                            acc.insert(kvd.key.to_uppercase(), val.to_string());
                        }
                    }
                    acc
                });
        }
        // entry_fields_with_place_holders = form_data
        //     .section_fields
        //     .values()
        //     .into_iter()
        //     .flatten()
        //     .fold(entry_fields_with_place_holders, |mut acc, kvd| {
        //         if let Some(ref val) = kvd.value {
        //             if parsing::place_holder_marker_found(val) {
        //                 acc.insert(kvd.key.to_uppercase(), val.to_string());
        //             }
        //         }
        //         acc
        //     });

        println!(
            "entry_fields_with_place_holders is {:?}",
            &entry_fields_with_place_holders
        );

        if !entry_fields_with_place_holders.is_empty() {
            let mut ef =
                parsing::EntryPlaceHolderParser::from(&mut entry_fields_with_place_holders);
            let r = ef.parse_main();
            println!(" Called r is {:?} and ef is {:?}", &r, &ef);

            let modified = ef.modified_fields();

            entry_fields_with_place_holders.retain(
                |k, _v| {
                    if modified.contains(k) {
                        true
                    } else {
                        false
                    }
                },
            );
        }

        println!(
            "2 entry_fields_with_place_holders is {:?}",
            &entry_fields_with_place_holders
        );

        form_data.parsed_fields = entry_fields_with_place_holders;
        form_data
    }

*/

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
