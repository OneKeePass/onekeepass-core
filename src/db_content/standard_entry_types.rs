use std::collections::HashMap;

use crate::constants::entry_keyvalue_key::*;
use crate::constants::entry_type_name::*;
use crate::constants::entry_type_uuid;
use crate::constants::standard_in_section_names::*;
use crate::db_content::entry_type::{EntryType, FieldDataType, FieldDef, Section};

use lazy_static::lazy_static;
use uuid::Uuid;

// Use "use crate::build_uuid;" in any other module to use this macro
// See https://stackoverflow.com/questions/26731243/how-do-i-use-a-macro-across-module-files for more techniques
#[macro_export]
macro_rules! build_uuid {
    ($aname:expr) => {
        uuid::Builder::from_slice(&$aname).unwrap().into_uuid()
    };
}

// IMPORTANT: As we add more standard types, we need to ensure to add that name here
pub const STANDARD_TYPE_NAMES: &[&'static str] =
    &[LOGIN, CREDIT_DEBIT_CARD, BANK_ACCOUNT, WIRELESS_ROUTER];

//pub const STANDARD_TYPE_UUIDS:&[&'static Uuid] = &[&build_uuid!(entry_type_uuid::LOGIN) ];

lazy_static! {

    // Some standard field UI hepler texts. At this time, it is assumed that each field name
    // is unique across all Entry Types. If not so, we need change the key of this map to use
    // type name with field name to form a unique key
    pub static ref FIELD_HELPER_TEXT: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        m.insert("Additional URLs", "One or more additional URLs separated by a space");
        m.insert("CVC", "Card Verification Value/Number");
        m
    };

    pub static ref STANDARD_TYPE_UUIDS_BY_NAME: HashMap<&'static str, Uuid> = {
        let mut m = HashMap::new();
        m.insert(LOGIN,build_uuid!(entry_type_uuid::LOGIN));
        m.insert(CREDIT_DEBIT_CARD,build_uuid!(entry_type_uuid::CREDIT_DEBIT_CARD));
        m.insert(BANK_ACCOUNT,build_uuid!(entry_type_uuid::BANK_ACCOUNT));
        m.insert(WIRELESS_ROUTER,build_uuid!(entry_type_uuid::WIRELESS_ROUTER));
        m
    };

    pub static ref DEFAULT_ENTRY_TYPE: EntryType = EntryType {
        //try **(STANDARD_TYPE_UUIDS_BY_NAME.get(LOGIN).unwrap()),
        //uuid::Builder::from_slice(&entry_type_uuid::LOGIN).unwrap().build(),
        uuid: build_uuid!(entry_type_uuid::LOGIN),     
        name: LOGIN.into(),
        secondary_title: Some(USER_NAME.into()),
        icon_name:None,
        sections: vec![Section {
            name: LOGIN_DETAILS.into(),
            field_defs: vec![
                FieldDef::new(USER_NAME).required(),
                FieldDef::new(PASSWORD)
                    .required()
                    .set_require_protection(true),
                FieldDef::new(OTP).set_data_type(FieldDataType::OneTimePassword).set_require_protection(true),
                FieldDef::new(URL),
                FieldDef::new("Additional URLs"),
                //FieldDef::new("Date created").set_data_type(FieldDataType::Date),
            ],
            
        },
        Section {
            name: ADDITIONAL_ONE_TIME_PASSWORDS.into(),
            field_defs: vec![],}
        ],
    };

    pub static ref UUID_TO_ENTRY_TYPE_MAP: HashMap<uuid::Uuid, EntryType> = {
        let mut m = HashMap::new();
        m.insert(DEFAULT_ENTRY_TYPE.uuid, DEFAULT_ENTRY_TYPE.clone());
        m.insert(
            build_uuid!(entry_type_uuid::WIRELESS_ROUTER),
            EntryType {
                uuid: build_uuid!(entry_type_uuid::WIRELESS_ROUTER),
                name: WIRELESS_ROUTER.into(),
                secondary_title: None,
                icon_name:None,
                sections: vec![Section {
                    name: LOGIN_DETAILS.into(),
                    field_defs: vec![
                        FieldDef::new("Base Station Name or SSID").required(),
                        FieldDef::new(PASSWORD)
                            .required()
                            .set_require_protection(true),
                    ],
                }],
            },
        );

        m.insert(
            build_uuid!(entry_type_uuid::CREDIT_DEBIT_CARD),
            EntryType {
                uuid: build_uuid!(entry_type_uuid::CREDIT_DEBIT_CARD),
                name: CREDIT_DEBIT_CARD.into(),
                secondary_title: Some("Number".into()),
                icon_name:None,
                sections: vec![
                    Section {
                        name: LOGIN_DETAILS.into(),
                        field_defs: vec![
                            FieldDef::new(USER_NAME).required(),
                            FieldDef::new(PASSWORD)
                                .required()
                                .set_require_protection(true),
                                FieldDef::new(OTP).set_data_type(FieldDataType::OneTimePassword).set_require_protection(true),
                            FieldDef::new(URL)
                        ],
                    },
                    Section {
                        name: CARD_DETAILS.into(),
                        field_defs: vec![
                            FieldDef::new("Cardholder Name").required(),
                            FieldDef::new("Brand").required(),
                            FieldDef::new("Number").required(),
                            FieldDef::new("Expiration Month").set_data_type(FieldDataType::Month),
                            FieldDef::new("Expiration Year").set_data_type(FieldDataType::Year),
                            FieldDef::new("CVC")
                                .set_require_protection(true),
                                //.set_help_text("Card Verification Value/Number"),
                            FieldDef::new("PIN").set_require_protection(true),
                        ],
                    },
                    Section {
                        name: "Billing Address".into(),
                        field_defs: vec![
                            FieldDef::new("Address Line1"),
                            FieldDef::new("Address Line2"),
                            FieldDef::new("City"),
                            FieldDef::new("State"),
                            FieldDef::new("Zip Code"),
                            FieldDef::new("Country"),
                        ],
                    },
                    Section {
                        name: "Additional Details".into(),
                        field_defs: vec![
                            FieldDef::new("Issuing Bank"),
                            FieldDef::new("Credit limit"),
                            FieldDef::new("Contact Number"),
                            FieldDef::new("Contact email"),
                        ],
                    },
                ],
            },
        );

        m.insert(
            build_uuid!(entry_type_uuid::BANK_ACCOUNT),
        EntryType {
            uuid: build_uuid!(entry_type_uuid::BANK_ACCOUNT),
            name: BANK_ACCOUNT.into(),
            secondary_title: Some("Account holder".into()),
            icon_name:None,
            sections: vec![
                Section {
                    name: LOGIN_DETAILS.into(),
                    field_defs: vec![
                        FieldDef::new(USER_NAME).required(),
                        FieldDef::new(PASSWORD)
                            .required()
                            .set_require_protection(true),
                            FieldDef::new(OTP).set_data_type(FieldDataType::OneTimePassword).set_require_protection(true),
                        FieldDef::new(URL)
                    ],
                },
                Section {
                    name: "Account Details".into(),
                    field_defs: vec![
                        FieldDef::new("Account holder").required(),
                        FieldDef::new("Account type").required(),
                        FieldDef::new("Account number").required(),
                        FieldDef::new("Bank Code/Routing number"),
                        FieldDef::new("SWIFT"),
                    ],
                },
                Section {
                    name: "Bank Address".into(),
                    field_defs: vec![
                        FieldDef::new("Address Line1"),
                        FieldDef::new("Address Line2"),
                        FieldDef::new("City"),
                        FieldDef::new("State"),
                        FieldDef::new("Zip Code"),
                        FieldDef::new("Country"),
                        FieldDef::new("Phone Number"),
                    ],
                },
            ]
        }
        );
        m
    };
}

// Fixed orderd (most commonly used to least commonly used ?) standard type names
// Mostly to use in UI
// IMPORTANT: As we add more standard types, we need to ensure to add that name here
pub fn _standard_type_names_ordered() -> Vec<String> {
    // arg s in map() call is &&str, (&**s) gives &str
    //vec![LOGIN, CREDIT_DEBIT_CARD, BANK_ACCOUNT, WIRELESS_ROUTER]
    STANDARD_TYPE_NAMES.iter().map(|s| (&**s).into()).collect()
}

pub fn standard_type_uuids_names_ordered_by_id() -> Vec<(Uuid, String)> {
    // arg s in map() call is &&str, (&**s) gives &str and
    STANDARD_TYPE_NAMES
        .iter()
        .map(|s| {
            //&* gives &Uuid  and we use unwrap assuming STANDARD_TYPE_UUIDS_BY_NAME and STANDARD_TYPE_NAMES match
            let uuid = &*STANDARD_TYPE_UUIDS_BY_NAME.get(s).unwrap();
            (uuid.clone(), (&**s).into())
        })
        .collect()
}

pub fn standard_types_ordered_by_id() -> Vec<&'static EntryType> {
    STANDARD_TYPE_NAMES
        .iter()
        .map(|s| {
            //IMPORATNT: we use unwrap expecting that STANDARD_TYPE_UUIDS_BY_NAME and STANDARD_TYPE_NAMES match
            let uuid = STANDARD_TYPE_UUIDS_BY_NAME.get(s).unwrap();
            UUID_TO_ENTRY_TYPE_MAP
                .get(uuid)
                .map_or_else(|| &*DEFAULT_ENTRY_TYPE, |e| e)
        })
        .collect::<Vec<&EntryType>>()
}

/*

pub fn entry_type_field_defs_by_id(uuid: &Uuid) -> Vec<&FieldDef> {
    if let Some(et) = UUID_TO_ENTRY_TYPE_MAP.get(uuid) {
        et.sections
            .iter()
            .flat_map(|s| &s.field_defs)
            .map(|x| x)
            .collect::<Vec<&FieldDef>>()
    } else {
        vec![]
    }
}


pub fn standard_field_names_by_id(uuid: &Uuid) -> Vec<String> {
    let v = entry_type_field_defs_by_id(uuid);
    v.iter().map(|f| f.name.clone()).collect::<Vec<String>>()
}


pub fn standard_field_names_as_str_by_id(uuid: &Uuid) -> Vec<&str> {
    let v = entry_type_field_defs_by_id(uuid);
    v.iter().map(|f| f.name.as_str()).collect::<Vec<&str>>()
}

*/

/*
pub fn standard_field_names_as_str(name: &str) -> Vec<&str> {
    let v = entry_type_field_defs(name);
    v.iter().map(|f| f.name.as_str()).collect::<Vec<&str>>()
}


pub fn available_types() -> HashMap<String, EntryType> {
    ENTRY_TYPE_MAP.clone()
}

pub fn find_entry_type(name: &str) -> Option<&EntryType> {
    ENTRY_TYPE_MAP.get(name)
}

pub fn standard_section_names(name: &str) -> Vec<&str> {
    ENTRY_TYPE_MAP
        .get(name)
        .map(|e| e.standard_section_names())
        .map_or_else(|| vec![], |f| f)
}
*/
