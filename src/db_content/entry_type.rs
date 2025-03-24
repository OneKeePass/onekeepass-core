use log::error;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::db_content::standard_entry_types::*;
use crate::error::Result;

use crate::util;

// EntryType,Section,FieldDef and FieldDataType are expected to be a versioned structs.
// These are serialized to custom data for user specific cutomizations - user can add or remove sections,fields.
// EntryType is always aliased to the latest EntryTypeV* struct
// Whenever there is a change in EntryType itself or its content structs - Section,FieldDef FieldDataType - we need
// to use the next version in the name of EntryType. Also we need to support old version of EntryType when we deserialize
// old custom data.
pub type EntryType = EntryTypeV1;
pub type Section = SectionV1;
pub type FieldDef = FieldDefV1;

#[derive(PartialEq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct EntryTypeV1 {
    pub(crate) uuid: Uuid,

    // This is the name used to identify an entry type
    pub(crate) name: String,

    // Name of a field which is used along Title in the entry listing ( more UI specific use)
    pub(crate) secondary_title: Option<String>,

    pub(crate) icon_name: Option<String>,

    // Each entry may have one or more sections.
    pub(crate) sections: Vec<SectionV1>,
}

impl EntryTypeV1 {
    pub fn standard_type_by_id(type_id: &Uuid) -> &EntryType {
        match UUID_TO_ENTRY_TYPE_MAP.get(type_id) {
            Some(t) => t,
            None => &*DEFAULT_ENTRY_TYPE,
        }
    }

    pub fn default_type<'a>() -> &'a EntryType {
        &*DEFAULT_ENTRY_TYPE
    }

    /// Gets all builtin standard section names if the entry type is a standard one. Otherwise an empty vec
    pub fn standard_section_names_by_id(&self) -> Vec<&str> {
        if let Some(et) = UUID_TO_ENTRY_TYPE_MAP.get(&self.uuid) {
            et.sections
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<&str>>()
        } else {
            vec![]
        }
    }

    // Gets all built-in standard field names from all sections if the entry type is a standard one
    pub fn standard_field_names_by_id(&self) -> Vec<&str> {
        let v = if let Some(et) = UUID_TO_ENTRY_TYPE_MAP.get(&self.uuid) {
            et.sections
                .iter()
                .flat_map(|s| &s.field_defs)
                .map(|x| x)
                .collect::<Vec<&FieldDefV1>>()
        } else {
            vec![]
        };
        v.iter().map(|f| f.name.as_str()).collect::<Vec<&str>>()
    }

    pub fn changed(&self, other: &EntryType) -> bool {
        // We check only changes in sections of these two EntryType
        // skipping other fields like 'name', secondary_title, icon_name for now as the incoming
        // EntryType instance in EntryFormData do not have these values

        // To be equal, both sections should have same number of sections with name and same vec of FieldDefs - order matter
        self.sections != other.sections
    }
}

// The VersionedEntryType ensures we are able to serialize and deserialize EntryType related values to and from
// custom data of the db file.
// Each variant name follows the following naming pattern
// DataFormatNameVx
//  e.g RmpV1 means the data format/serde algorthim used is 'Rmp' a MessagePack formated data
//      V1 means the EntryType and all its child structs of version 1
// EntryTypeV1 is aliased as EntryType to point to the latest EntryType used in all other modules
// Upgrading EntryType or its constituents or change in serialize and deserialize handlers means, we need
// to use new version for EntryType and other child structs.
// e.g Let us assume, we add a new field in EntryType, then we need to create EntryTypeV2 leaving EntryTypeV1 as such
// Now EntryTypeV2 should be type aliased as EntryType and need to introduce RmpV2 and son on
// Need to provide a From trait implementation to do entryTypeV1.into() EntryTypeV2

// Rmp (Rust MessagePack) is the one used as the data formatted as this serializes small size data

// Important:
// Needs to keep the order of Variants as rmp binary dataformat uses the order of enum variant
// in the seralized data - e.g RmpV1 is 0, RmpKeyedV1 - 1 and RmpListV1 - 2
// Any new variant should be added last and previous order should not be changed if we want to decode any previouly
// stored data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum VersionedEntryType {
    // Uses MessagePack dataformated EntryType
    RmpV1(EntryTypeV1),
    // Maps the EntryType UUID to the EntryType to store in MessagePack dataformat
    RmpKeyedV1(HashMap<Uuid, EntryTypeV1>),
    // Keeps a list of EntryTypes to store in MessagePack dataformat
    RmpListV1(Vec<EntryTypeV1>),
    //RmpV2(EntryTypeV2),
}
trait EntryDeserializer<T> {
    fn from_encoded(data: &str) -> T;
}

impl EntryDeserializer<EntryType> for VersionedEntryType {
    fn from_encoded(base64_str: &str) -> EntryType {
        match VersionedEntryType::deserialize_data(base64_str) {
            Ok(vet) => {
                match vet {
                    VersionedEntryType::RmpV1(et) => et,
                    x => {
                        error!("The VersionedEntryType found: {} is not expected.Returning the default", x.name());
                        EntryType::default_type().clone()
                    }
                }
            }
            Err(e) => {
                error!("Deserialization failed for EntryType with error {:?}. Will return default type",e);
                //println!("Deserialization failed for {} with error {:?}. Will return default type", name, e);
                EntryType::default_type().clone()
            }
        }
    }
}

impl EntryDeserializer<HashMap<Uuid, EntryType>> for VersionedEntryType {
    fn from_encoded(base64_str: &str) -> HashMap<Uuid, EntryType> {
        match VersionedEntryType::deserialize_data(base64_str) {
            Ok(vet) => match vet {
                VersionedEntryType::RmpKeyedV1(ets) => ets,
                x => {
                    error!("Unknown type {:?} and empty HashMap is returned", x);
                    HashMap::default()
                }
            },
            Err(e) => {
                error!("Conversion error {:?} and empty HashMap is returned", e);
                HashMap::default()
            }
        }
    }
}

impl EntryDeserializer<Vec<EntryType>> for VersionedEntryType {
    fn from_encoded(base64_str: &str) -> Vec<EntryType> {
        match VersionedEntryType::deserialize_data(base64_str) {
            Ok(vet) => match vet {
                VersionedEntryType::RmpListV1(ets) => ets,
                x => {
                    error!("Unknown type {:?} and empty HashMap is returned", x);
                    vec![]
                }
            },
            Err(e) => {
                error!("Conversion error {:?} and empty HashMap is returned", e);
                vec![]
            }
        }
    }
}

impl VersionedEntryType {
    pub fn name(&self) -> &str {
        match self {
            VersionedEntryType::RmpV1(_) => "RmpV1",
            VersionedEntryType::RmpKeyedV1(_) => "RmpKeyedV1",
            VersionedEntryType::RmpListV1(_) => "RmpListV1",
        }
    }

    fn from_entry_type(entry_type: &EntryType) -> VersionedEntryType {
        VersionedEntryType::RmpV1(entry_type.clone())
    }

    fn from_entry_type_list(entry_types: &Vec<EntryType>) -> VersionedEntryType {
        VersionedEntryType::RmpListV1(entry_types.clone())
    }

    fn deserialize_data(base64_str: &str) -> Result<VersionedEntryType> {
        deserialize_from_base64_str(base64_str, |buf| Ok(rmp_serde::from_slice(buf)?))
    }

    // fn serialize_data(&self) -> Result<Option<String>> {
    //     serialize_to_base64_str_no_prefix(self,|val| Ok(rmp_serde::to_vec(val)?))
    // }

    fn serilaize(&self) -> Option<String> {
        serialize_to_base64_str(self, |val| Ok(rmp_serde::to_vec(val)?))
            .ok()
            .flatten()
        //self.serialize_data().ok().flatten()
    }

    pub fn encode_entry_types_by_id(entry_types: &HashMap<Uuid, EntryType>) -> Option<String> {
        VersionedEntryType::RmpKeyedV1(entry_types.clone()).serilaize()
    }

    pub fn decode_entry_types_by_id(data: &str) -> HashMap<Uuid, EntryType> {
        VersionedEntryType::from_encoded(data)
    }

    // Called to consider only non standard fields or new custom sections in an entry type
    // This fn is called when there is a change in the incoming entry type's section data as the 'changed' fn is called before this
    fn modify_entry_type_before_encoding(
        incoming_entry_type: &EntryType,
        custom_entry_types: &HashMap<Uuid, EntryType>,
    ) -> Option<EntryType> {
        // predefined_et is a standard EntryType or user defined custom EntryType
        if let Some(predefined_et) = custom_entry_types
            .get(&incoming_entry_type.uuid)
            .or_else(|| UUID_TO_ENTRY_TYPE_MAP.get(&incoming_entry_type.uuid))
        {
            // An incoming entry_type may have more sections or fields than that are in the predefined entry_type
            let mut incoming_et = incoming_entry_type.clone();

            // Set to some default values to reduce size
            incoming_et.name = String::default();
            incoming_et.icon_name = None;
            incoming_et.secondary_title = None;

            for predefined_et_section in predefined_et.sections.iter() {
                // Find all fields from built-in entry type
                // let fnames = section.field_defs.iter().map(|f|&f.name).collect::<Vec<&String>>();
                // Find the matching section of the passed entry type
                let incoming_et_section_opt = incoming_et
                    .sections
                    .iter_mut()
                    .find(|s| s.name == predefined_et_section.name);
                if let Some(incoming_et_section) = incoming_et_section_opt {
                    // Remove all built-in fields from the passed one
                    incoming_et_section
                        .field_defs
                        .retain_mut(|f| !predefined_et_section.field_defs.contains(f))
                }
            }
            // As we have removed the built-in fields, a section may be empty and drop them from storing
            incoming_et.sections.retain(|sec| sec.field_defs.len() != 0);

            Some(incoming_et)
        } else {
            // Should not happen. Need to return default to be safe
            // log error
            Some((&*DEFAULT_ENTRY_TYPE).clone())
        }
    }

    // Called to merge all non standard fields in an entry type to the standard fields
    fn modify_entry_type_after_decoding(
        incoming_entry_type: &EntryType,
        custom_entry_types: &HashMap<Uuid, EntryType>,
    ) -> Option<EntryType> {
        if let Some(predefined_et) = custom_entry_types
            .get(&incoming_entry_type.uuid)
            .or_else(|| UUID_TO_ENTRY_TYPE_MAP.get(&incoming_entry_type.uuid))
        {
            let mut built_in_et = predefined_et.clone();

            // incoming_entry_type will have sections or custom fields that are not in the predefined entry_type
            for incoming_section in incoming_entry_type.sections.iter() {
                // Find the built-in section that matches with incoming section
                let built_in_section_opt = built_in_et
                    .sections
                    .iter_mut()
                    .find(|s| s.name == incoming_section.name);

                if let Some(built_in_section) = built_in_section_opt {
                    // The section is found in built-in Entrytype and we need to merge the decoded field defs to the
                    // existing fields of the section from the built-in (predefined_et) Entrytype
                    // Here incoming_section will have only any non prededefined fields and they are added
                    // to the end of the existing field defs
                    built_in_section
                        .field_defs
                        .extend(incoming_section.field_defs.clone().into_iter())
                } else {
                    // section is a custom section and move that to the built_in_et (clone of predefined Entrytype)
                    built_in_et.sections.push(incoming_section.clone());
                }
            }
            Some(built_in_et)
            //entry_type = built_in_et
        } else {
            // Should not happen. Need to return default to be safe
            // log error
            error!("Unexpected error: The call 'modify_entry_type_after_decoding' failed for the entry type {}", &incoming_entry_type.name);
            Some((&*DEFAULT_ENTRY_TYPE).clone())
        }
    }

    // Converts a list of EntryTypes from the 'base64_str_data' to a vec of base64_str where
    // each member is serilaized entry type
    pub fn encoded_entry_type_list_to_encoded_types(base64_str_data: &str) -> Vec<String> {
        let et_v: Vec<EntryType> = VersionedEntryType::from_encoded(base64_str_data);
        // Note: et_v is a vec of unadjusted EntryType as it the vec was formed earlier with modified EntryType
        // Returns a vec of base64_str representation of EntryType
        let list: Vec<String> = et_v
            .iter()
            .flat_map(|e| VersionedEntryType::from_entry_type(e).serilaize())
            .collect();
        list
    }

    pub fn encoded_types_to_encoded_type_list(types_encoded: Vec<String>) -> Option<String> {
        // Each item in types_encoded is a previuosly encoded EntryType which is already modified
        // to reduce size
        let entry_types: Vec<EntryType> = types_encoded
            .iter()
            .map(|e| VersionedEntryType::from_encoded(e))
            .collect();

        // The EntryTypes in the decoded entry_types vec are not adjusted one
        //
        VersionedEntryType::from_entry_type_list(&entry_types).serilaize()
    }

    pub fn _encode_entry_type_list(
        entry_types: &Vec<EntryType>,
        custom_entry_types: &HashMap<Uuid, EntryType>,
    ) -> Option<String> {
        let modified_ets: Vec<Option<EntryType>> = entry_types
            .iter()
            .map(|e| VersionedEntryType::modify_entry_type_before_encoding(e, custom_entry_types))
            .collect();

        let modified_ets: Vec<EntryType> = modified_ets.into_iter().map(|e| e.unwrap()).collect();

        VersionedEntryType::RmpListV1(modified_ets).serilaize()
    }

    pub fn _decode_entry_type_list(
        data: &str,
        custom_entry_types: &HashMap<Uuid, EntryType>,
    ) -> Vec<EntryType> {
        let mut et_v: Vec<EntryType> = VersionedEntryType::from_encoded(data);
        et_v.iter_mut().for_each(|e| {
            VersionedEntryType::modify_entry_type_after_decoding(e, custom_entry_types);
        });

        et_v
    }

    pub fn decode_entry_type(
        data: &str,
        custom_entry_types: &HashMap<Uuid, EntryType>,
    ) -> EntryType {
        // Deserilaize the base64 encoded binary data
        let entry_type: EntryType = VersionedEntryType::from_encoded(data);

        // If the decoded entry_type is the default one, we do not require to adjust the entry type's sections or fields
        if &entry_type == EntryType::default_type() {
            return entry_type;
        };

        VersionedEntryType::modify_entry_type_after_decoding(&entry_type, custom_entry_types)
            .unwrap()
    }

    pub fn encode_entry_type(
        entry_type: &EntryType,
        custom_entry_types: &HashMap<Uuid, EntryType>,
    ) -> Option<String> {
        VersionedEntryType::modify_entry_type_before_encoding(entry_type, custom_entry_types)
            .map(|e| VersionedEntryType::RmpV1(e).serilaize())
            .flatten()
    }
}

// Called to encode using RMP formatted binary, compress and encode to base64 string so that
// it can be stored in xml
fn serialize_to_base64_str<T, F>(val: &T, encoder: F) -> Result<Option<String>>
where
    T: Serialize + ?Sized,
    F: Fn(&T) -> Result<Vec<u8>>,
{
    let buf = encoder(val)?;
    //println!("EntryType Serialization: rmp serialized data size {}",buf.len());
    let buf = util::compress_with_fixed_timestamp(&buf)?;
    //println!( "EntryType Serialization: compressed data size {}",buf.len());
    //let base64_str = base64::encode(&buf);
    let base64_str = util::base64_encode(&buf);
    //println!("EntryType Serialization: final b64 data size {}",data.len());
    Ok(Some(base64_str))
}

// Successful decoded binary (base64 encoded data) should be a variant of VersionedEntryType or an error is returned
fn deserialize_from_base64_str<T, F>(input: &str, decoder: F) -> Result<T>
where
    F: Fn(&Vec<u8>) -> Result<T>,
{
    let buf = util::base64_decode(input)?;
    let buf = util::decompress(&buf)?;
    Ok(decoder(&buf)?)
}

// For 'rmp' serialization to work, add any new variant at the end though adding in any place may work
// When we add a new variant, the FieldDef deserialization works with any previous version without
// introducing FieldDef2. If we remove any variant, it may not work

#[derive(PartialEq, Debug, Copy, Clone, Serialize, Deserialize)]
pub enum FieldDataType {
    Text,
    Bool,
    Number,
    Date, // Day-Month-Year
    Month,
    Year,
    MonthYear,
    OneTimePassword,
}

impl Default for FieldDataType {
    fn default() -> Self {
        FieldDataType::Text
    }
}

// impl FieldDataType {
//     fn from_str(num_str: &str) -> Self {
//         let i = u32::from_str(num_str).unwrap_or(1);
//         FieldDataType::from_u32(i)
//     }

//     fn from_u32(num: u32) -> Self {
//         match num {
//             1 => FieldDataType::Text,
//             2 => FieldDataType::Bool,
//             3 => FieldDataType::Number,
//             4 => FieldDataType::Date,
//             4 => FieldDataType::MonthYear,
//             _ => FieldDataType::default(),
//         }
//     }
// }

#[derive(PartialEq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct FieldDefV1 {
    pub(crate) name: String,
    pub(crate) required: bool,
    pub(crate) require_protection: bool,
    pub(crate) data_type: FieldDataType,
}

impl FieldDefV1 {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            required: false,
            require_protection: false,
            data_type: FieldDataType::Text,
        }
    }

    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    pub fn set_required(mut self, required: bool) -> Self {
        self.required = required;
        self
    }

    pub fn set_require_protection(mut self, require_protection: bool) -> Self {
        self.require_protection = require_protection;
        self
    }

    pub fn set_data_type(mut self, data_type: FieldDataType) -> Self {
        self.data_type = data_type;
        self
    }

    // May need to be moved to Entry Type if we need to use type name in addition to field name
    // to form key of FIELD_HELPER_TEXT
    pub fn helper_text(&self) -> Option<String> {
        FIELD_HELPER_TEXT
            .get(self.name.as_str())
            .map(|s| s.to_string())
    }
}

#[derive(PartialEq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct SectionV1 {
    pub(crate) name: String,
    pub(crate) field_defs: Vec<FieldDefV1>,
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::build_uuid;
    use crate::constants::entry_type_name::LOGIN;
    use crate::constants::entry_type_uuid;
    use crate::db_content::entry_type::*;

    fn test_data() -> HashMap<Uuid, EntryType> {
        //let mut entry_types: HashMap<String, EntryType> = HashMap::default();
        let mut entry_types: HashMap<Uuid, EntryType> = HashMap::default();

        let et1 = EntryType {
            uuid: build_uuid!(entry_type_uuid::LOGIN),
            name: LOGIN.into(),
            secondary_title: None,
            icon_name: None,
            sections: vec![
                Section {
                    name: "Main".into(),
                    field_defs: vec![
                        FieldDef::new("Password1")
                            .required()
                            .set_require_protection(true),
                        //FieldDef::new("Password"),
                        FieldDef::new("UserName1").required(),
                        FieldDef::new("URL"),
                    ],
                },
                Section {
                    name: "Custom Fields".into(),
                    field_defs: vec![
                        FieldDef::new("Custom field1"),
                        FieldDef::new("What is FD_your name?"),
                        FieldDef::new("Routing number:"),
                    ],
                },
            ],
        };

        let et2 = EntryType {
            uuid: Uuid::new_v4(),
            name: "Login2".into(),
            secondary_title: Some("UserName".into()),
            icon_name: None,
            sections: vec![
                Section {
                    name: "Main".into(),
                    field_defs: vec![
                        FieldDef::new("Password2")
                            .required()
                            .set_require_protection(true),
                        //FieldDef::new("Password"),
                        FieldDef::new("UserName2").required(),
                        FieldDef::new("URL"),
                    ],
                },
                Section {
                    name: "Custom Fields".into(),
                    field_defs: vec![
                        FieldDef::new("Custom field1"),
                        FieldDef::new("What is FD_your name?"),
                        FieldDef::new("Routing number:"),
                    ],
                },
            ],
        };

        let et3 = EntryType {
            uuid: Uuid::new_v4(),
            name: "Login3".into(),
            secondary_title: Some("UserName".into()),
            icon_name: None,
            sections: vec![
                Section {
                    name: "Main".into(),
                    field_defs: vec![
                        FieldDef::new("Password3")
                            .required()
                            .set_require_protection(true),
                        //FieldDef::new("Password"),
                        FieldDef::new("UserName").required(),
                        FieldDef::new("URL"),
                    ],
                },
                Section {
                    name: "Custom Fields".into(),
                    field_defs: vec![
                        FieldDef::new("Custom field1"),
                        FieldDef::new("What is FD_your name?"),
                        FieldDef::new("Routing number:"),
                    ],
                },
            ],
        };
        entry_types.insert(et3.uuid.clone(), et3);

        //let et4 = ENTRY_TYPE_MAP.get(CREDIT_DEBIT_CARD).unwrap();
        let et4 = UUID_TO_ENTRY_TYPE_MAP
            .get(&build_uuid!(entry_type_uuid::CREDIT_DEBIT_CARD))
            .unwrap();
        entry_types.insert(et4.uuid.clone(), et4.clone());
        entry_types.insert(Uuid::new_v4(), et4.clone());

        entry_types.insert(et1.uuid.clone(), et1);
        entry_types.insert(et2.uuid.clone(), et2);

        entry_types
    }

    #[test]
    fn verify_optimized_encode_decode_entry_type() {
        let mut et1 = UUID_TO_ENTRY_TYPE_MAP
            .get(&build_uuid!(entry_type_uuid::LOGIN))
            .unwrap()
            .clone();

        let fd1 = FieldDef::new("Custom Field1")
            .required()
            .set_require_protection(true);

        // Simulate adding a custom field to one of standard Section
        let first_section = et1.sections.first_mut();
        first_section.map(|f| f.field_defs.push(fd1));

        // Simulate some additional sections
        let mut add_sections = vec![
            Section {
                name: "Main".into(),
                field_defs: vec![
                    FieldDef::new("Passwor1")
                        .required()
                        .set_require_protection(true),
                    //FieldDef::new("Password"),
                    FieldDef::new("UserName1").required(),
                    FieldDef::new("URL"),
                ],
            },
            Section {
                name: "Custom Fields".into(),
                field_defs: vec![
                    FieldDef::new("Custom field1"),
                    FieldDef::new("What is FD_your name?"),
                    FieldDef::new("Routing number:"),
                ],
            },
        ];

        et1.sections.append(&mut add_sections);
        //println!("et1 is {:?}", &et1);

        //let s = VersionedEntryType::encode_entry_type(&et1, &HashMap::default()).map_or("No Value".into(), |s| s);
        // let s = VersionedEntryType::encode_entry_type(&et1, &*UUID_TO_ENTRY_TYPE_MAP).unwrap();
        let s = VersionedEntryType::encode_entry_type(&et1, &HashMap::default()).unwrap();
        println!("Encoded str size is {} ", s.len());

        //let d = VersionedEntryType::decode_entry_type(&s, &*UUID_TO_ENTRY_TYPE_MAP);
        let d = VersionedEntryType::decode_entry_type(&s, &HashMap::default());
        //println!("d is {:?}", &d);

        assert_eq!(&et1 == &d, true);

        // let vd = VersionedEntryType::RmpV1(et1.clone());
        // let s = vd.into_name_prefixed_string().unwrap();
        // println!("Serialized str size is {} ", s.len());
    }

    #[test]
    fn verify_rmp_encode_decode() {
        let entry_types = test_data();
        let mut et1 = entry_types.iter().find(|_| true).unwrap().1.clone();
        println!("Sample et is for name {}", et1.name);

        let vd = VersionedEntryType::RmpV1(et1.clone());
        let s = vd.serilaize().unwrap();
        println!("Serialized str size is {} ", s.len());

        et1.name = String::default();
        if et1.name == String::default() {
            println!("Default name is set");
        }
        let vd = VersionedEntryType::RmpV1(et1.clone());
        let s = vd.serilaize().unwrap();
        println!("After name reset,Serialized str size is {} ", s.len());

        //println!("Serialized RmpV1 str size is {} and Serialized data {:?}",s.len(),&s);
        let vd: EntryType = VersionedEntryType::from_encoded(&s);
        //println!("Deserialized RmpV1 type {:?}", vd);
        assert_eq!(et1 == vd, true);

        let vd = VersionedEntryType::RmpKeyedV1(entry_types.clone());
        //println!(" vd is {:?}",vd);
        let s = vd.serilaize().unwrap();
        //println!("Serialized data is {}",s);
        println!("Serialized RmpUuidKeyedV1 str size is {} ", s.len());

        //let vd = VersionedEntryType::into_latest_entry_types(vd.name(), &s);
        let vd: HashMap<Uuid, EntryType> = VersionedEntryType::from_encoded(&s);
        //println!("Deserialized types {:?}", vd);
        assert_eq!(entry_types == vd, true);
    }
}
