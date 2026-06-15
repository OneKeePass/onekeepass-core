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
// This macros builds uuid from an array - [u8]
#[macro_export]
macro_rules! build_uuid {
    ($aname:expr) => {
        uuid::Builder::from_slice(&$aname).unwrap().into_uuid()
    };
}

// IMPORTANT:
// As we add more standard types, we need to ensure to add that name here
// In 'STANDARD_TYPE_UUIDS_BY_NAME' and in 'UUID_TO_ENTRY_TYPE_MAP'
// Also these names are to be added in 'src/main/onekeepass/frontend/constants.cljs'

// All standard types available for UI to use
pub const STANDARD_TYPE_NAMES: &[&'static str] = &[
    LOGIN,
    CREDIT_DEBIT_CARD,
    BANK_ACCOUNT,
    IDENTITY,
    PASSPORT,
    DRIVER_LICENSE,
    EMAIL_ACCOUNT,
    SSH_LOGIN,
    API_CREDENTIAL,
    DATABASE_CREDENTIAL,
    SOFTWARE_LICENSE,
    MEMBERSHIP,
    CRYPTO_WALLET,
    INSURANCE_POLICY,
    WIRELESS_ROUTER,
    AUTO_DB_OPEN,
    REMOTE_CONNECTION_SFTP,
    REMOTE_CONNECTION_WEBDAV,
];

//pub const STANDARD_TYPE_UUIDS:&[&'static Uuid] = &[&build_uuid!(entry_type_uuid::LOGIN) ];

lazy_static! {

    // Some standard field UI hepler texts. At this time, it is assumed that each field name
    // is unique across all Entry Types. If not so, we need change the key of this map to use
    // type name with field name to form a unique key
    pub static ref FIELD_HELPER_TEXT: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        m.insert("Additional URLs", "One or more additional URLs separated by a space");
        m.insert("CVC", "Card Verification Value/Number");
        // Date fields currently render as plain text on both desktop and mobile,
        // so a format hint is shown. The wording is kept type-neutral because the
        // helper-text key is the bare field name shared across entry types.
        m.insert("Date of Birth", "Enter date as YYYY-MM-DD");
        m.insert("Issue Date", "Enter date as YYYY-MM-DD");
        m.insert("Expiration Date", "Enter date as YYYY-MM-DD");
        m.insert("Created Date", "Enter date as YYYY-MM-DD");
        m.insert("Start Date", "Enter date as YYYY-MM-DD");
        m.insert("Purchase Date", "Enter date as YYYY-MM-DD");
        m.insert("Effective Date", "Enter date as YYYY-MM-DD");
        m.insert("Recovery Phrase", "Seed words separated by spaces");
        m.insert("Allowed Hosts", "One or more host patterns separated by a space");
        m
    };

    // Look up to get the entry type's UUID from its name
    pub static ref STANDARD_TYPE_UUIDS_BY_NAME: HashMap<&'static str, Uuid> = {
        let mut m = HashMap::new();
        m.insert(LOGIN,build_uuid!(entry_type_uuid::LOGIN));
        m.insert(CREDIT_DEBIT_CARD,build_uuid!(entry_type_uuid::CREDIT_DEBIT_CARD));
        m.insert(BANK_ACCOUNT,build_uuid!(entry_type_uuid::BANK_ACCOUNT));
        m.insert(WIRELESS_ROUTER,build_uuid!(entry_type_uuid::WIRELESS_ROUTER));
        m.insert(AUTO_DB_OPEN,build_uuid!(entry_type_uuid::AUTO_DB_OPEN));
        m.insert(REMOTE_CONNECTION_SFTP,build_uuid!(entry_type_uuid::REMOTE_CONNECTION_SFTP));
        m.insert(REMOTE_CONNECTION_WEBDAV,build_uuid!(entry_type_uuid::REMOTE_CONNECTION_WEBDAV));
        m.insert(IDENTITY,build_uuid!(entry_type_uuid::IDENTITY));
        m.insert(PASSPORT,build_uuid!(entry_type_uuid::PASSPORT));
        m.insert(DRIVER_LICENSE,build_uuid!(entry_type_uuid::DRIVER_LICENSE));
        m.insert(EMAIL_ACCOUNT,build_uuid!(entry_type_uuid::EMAIL_ACCOUNT));
        m.insert(SSH_LOGIN,build_uuid!(entry_type_uuid::SSH_LOGIN));
        m.insert(API_CREDENTIAL,build_uuid!(entry_type_uuid::API_CREDENTIAL));
        m.insert(DATABASE_CREDENTIAL,build_uuid!(entry_type_uuid::DATABASE_CREDENTIAL));
        m.insert(SOFTWARE_LICENSE,build_uuid!(entry_type_uuid::SOFTWARE_LICENSE));
        m.insert(MEMBERSHIP,build_uuid!(entry_type_uuid::MEMBERSHIP));
        m.insert(CRYPTO_WALLET,build_uuid!(entry_type_uuid::CRYPTO_WALLET));
        m.insert(INSURANCE_POLICY,build_uuid!(entry_type_uuid::INSURANCE_POLICY));
        m
    };

    pub static ref DEFAULT_ENTRY_TYPE: EntryType = EntryType {


        // onekeepass_core::db_content::entry_type::EntryTypeV  pub(crate) fn changed(&self, other: &EntryType) -> bool

        // It appears we can add more sections or field defs to the standard entry types as long as FieldDef or Section are not changed
        // We should be able to read the previously stored entry types data and use the latest defined standard entry type
        // This was tested briefly while introducing OTP to all , ADDITIONAL_URLS to BANK_ACCOUNT and CREDIT_DEBIT_CARD

        // Removed FieldDef.required() calls

        // Similarly we can drop a section or field def from standard entry type definition (Not yet tested)

        // Also see - pub(crate) fn changed(&self, other: &EntryType) -> bool of onekeepass_core::db_content::entry_type::EntryTypeV
        // Here we compare the entry type's section by section to identify any changes between incoming and standard type
        // Not sure how this impacts if we add new section or field def, though did not see any issue so far.

        uuid: build_uuid!(entry_type_uuid::LOGIN),
        name: LOGIN.into(),
        secondary_title: Some(USER_NAME.into()),
        icon_name:None,
        sections: vec![Section {
            name: LOGIN_DETAILS.into(),
            field_defs: vec![
                FieldDef::new(USER_NAME),
                FieldDef::new(PASSWORD).set_require_protection(true),
                FieldDef::new(OTP).set_data_type(FieldDataType::OneTimePassword).set_require_protection(true),
                FieldDef::new(URL),
                FieldDef::new(ADDITIONAL_URLS),
            ],
        },
        Section {
            name: ADDITIONAL_ONE_TIME_PASSWORDS.into(),
            field_defs: vec![],
        },
        Section {
            name: PASSKEY_DETAILS.into(),
            field_defs: vec![
                FieldDef::new(KPEX_PASSKEY_USERNAME),
                FieldDef::new(KPEX_PASSKEY_RELYING_PARTY),
                FieldDef::new(KPEX_PASSKEY_USER_HANDLE).set_require_protection(true),
                FieldDef::new(KPEX_PASSKEY_CREDENTIAL_ID).set_require_protection(true),
                FieldDef::new(KPEX_PASSKEY_PRIVATE_KEY_PEM).set_require_protection(true),
            ],
        },
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
                        FieldDef::new(SSID).required(),
                        FieldDef::new(PASSWORD)
                            .required()
                            .set_require_protection(true),
                    ],
                }],
            },
        );

        // Adding or removing more sections or field defs to the standard entry types - see comments above

        m.insert(
            build_uuid!(entry_type_uuid::CREDIT_DEBIT_CARD),
            EntryType {
                uuid: build_uuid!(entry_type_uuid::CREDIT_DEBIT_CARD),
                name: CREDIT_DEBIT_CARD.into(),
                secondary_title: Some(NUMBER.into()),
                icon_name:None,
                sections: vec![
                    Section {
                        name: LOGIN_DETAILS.into(),
                        field_defs: vec![
                            FieldDef::new(USER_NAME),
                            FieldDef::new(PASSWORD).set_require_protection(true),
                            FieldDef::new(OTP).set_data_type(FieldDataType::OneTimePassword).set_require_protection(true),
                            FieldDef::new(URL),
                            FieldDef::new(ADDITIONAL_URLS),
                        ],
                    },
                    Section {
                        name: ADDITIONAL_ONE_TIME_PASSWORDS.into(),
                        field_defs: vec![],
                    },
                    Section {
                        name: CARD_DETAILS.into(),
                        field_defs: vec![
                            FieldDef::new("Cardholder Name"),
                            FieldDef::new("Brand"),
                            FieldDef::new("Number"),
                            FieldDef::new("Expiration Month").set_data_type(FieldDataType::Month),
                            FieldDef::new("Expiration Year").set_data_type(FieldDataType::Year),
                            FieldDef::new("CVC").set_require_protection(true),
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

        // Adding or removing more sections or field defs to the standard entry types - see comments above

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
                            FieldDef::new(USER_NAME),
                            FieldDef::new(PASSWORD).set_require_protection(true),
                            FieldDef::new(OTP).set_data_type(FieldDataType::OneTimePassword).set_require_protection(true),
                            FieldDef::new(URL),
                            FieldDef::new(ADDITIONAL_URLS),
                        ],
                    },
                    Section {
                        name: ADDITIONAL_ONE_TIME_PASSWORDS.into(),
                        field_defs: vec![],
                    },
                    Section {
                        name: "Account Details".into(),
                        field_defs: vec![
                            FieldDef::new("Account holder"),
                            FieldDef::new("Account type"),
                            FieldDef::new("Account number"),
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

        m.insert(
            build_uuid!(entry_type_uuid::AUTO_DB_OPEN),
            EntryType {
                uuid: build_uuid!(entry_type_uuid::AUTO_DB_OPEN),
                name: AUTO_DB_OPEN.into(),
                secondary_title: Some(USER_NAME.into()),
                icon_name:None,
                sections: vec![Section {
                    name: LOGIN_DETAILS.into(),
                    field_defs: vec![
                        FieldDef::new(USER_NAME),
                        FieldDef::new(PASSWORD).set_require_protection(true),
                        FieldDef::new(URL),
                        FieldDef::new(IF_DEVICE),
                        // FieldDef::new(PRIORITY),
                        // FieldDef::new(SKIP_IF_NOT_EXISTS).set_data_type(FieldDataType::Bool),
                        // FieldDef::new(SKIP_IF_KEY_FILE_NOT_EXISTS).set_data_type(FieldDataType::Bool),
                    ],
                }],
            },
        );

        // SFTP remote-connection entry. Connection id = entry uuid; the SFTP
        // private key (when used) is stored as an entry attachment, not a
        // field.
        m.insert(
            build_uuid!(entry_type_uuid::REMOTE_CONNECTION_SFTP),
            EntryType {
                uuid: build_uuid!(entry_type_uuid::REMOTE_CONNECTION_SFTP),
                name: REMOTE_CONNECTION_SFTP.into(),
                secondary_title: Some(HOST.into()),
                icon_name: None,
                sections: vec![Section {
                    name: LOGIN_DETAILS.into(),
                    field_defs: vec![
                        FieldDef::new(HOST).required(),
                        FieldDef::new(PORT).set_data_type(FieldDataType::Number),
                        FieldDef::new(USER_NAME).required(),
                        FieldDef::new(PASSWORD).set_require_protection(true),
                        FieldDef::new(START_DIR),
                    ],
                }],
            },
        );

        // WebDAV remote-connection entry. Connection id = entry uuid.
        m.insert(
            build_uuid!(entry_type_uuid::REMOTE_CONNECTION_WEBDAV),
            EntryType {
                uuid: build_uuid!(entry_type_uuid::REMOTE_CONNECTION_WEBDAV),
                name: REMOTE_CONNECTION_WEBDAV.into(),
                secondary_title: Some(URL.into()),
                icon_name: None,
                sections: vec![Section {
                    name: LOGIN_DETAILS.into(),
                    field_defs: vec![
                        FieldDef::new(URL).required(),
                        FieldDef::new(USER_NAME).required(),
                        FieldDef::new(PASSWORD).set_require_protection(true),
                        FieldDef::new(ALLOW_UNTRUSTED_CERT).set_data_type(FieldDataType::Bool),
                    ],
                }],
            },
        );

        // ---- Extended standard entry templates ----
        // Identity, Passport and Driver License reuse the UUIDs reserved earlier
        // in entry_type_uuid. The remaining types use newly generated UUIDs.
        // Secondary titles use non-protected fields only, since the entry list
        // shows the secondary title's raw value (no masking except Credit Card).

        m.insert(
            build_uuid!(entry_type_uuid::IDENTITY),
            EntryType {
                uuid: build_uuid!(entry_type_uuid::IDENTITY),
                name: IDENTITY.into(),
                secondary_title: Some(FULL_NAME.into()),
                icon_name: None,
                sections: vec![
                    Section {
                        name: "Identity".into(),
                        field_defs: vec![
                            FieldDef::new(FULL_NAME),
                            FieldDef::new("First Name"),
                            FieldDef::new("Middle Name"),
                            FieldDef::new("Last Name"),
                            FieldDef::new(DATE_OF_BIRTH).set_data_type(FieldDataType::Date),
                            FieldDef::new("Gender"),
                            FieldDef::new(NATIONALITY),
                        ],
                    },
                    Section {
                        name: CONTACT.into(),
                        field_defs: vec![
                            FieldDef::new(EMAIL),
                            FieldDef::new("Phone Number"),
                            FieldDef::new("Alternate Phone"),
                        ],
                    },
                    Section {
                        name: "Address".into(),
                        field_defs: vec![
                            FieldDef::new("Address Line1"),
                            FieldDef::new("Address Line2"),
                            FieldDef::new("City"),
                            FieldDef::new(STATE_PROVINCE_REGION),
                            FieldDef::new(POSTAL_CODE),
                            FieldDef::new("Country"),
                        ],
                    },
                    Section {
                        name: "Sensitive Details".into(),
                        field_defs: vec![
                            FieldDef::new("National ID").set_require_protection(true),
                            FieldDef::new("Tax ID").set_require_protection(true),
                        ],
                    },
                ],
            },
        );

        m.insert(
            build_uuid!(entry_type_uuid::PASSPORT),
            EntryType {
                uuid: build_uuid!(entry_type_uuid::PASSPORT),
                name: PASSPORT.into(),
                secondary_title: Some(FULL_NAME.into()),
                icon_name: None,
                sections: vec![
                    Section {
                        name: "Passport Details".into(),
                        field_defs: vec![
                            FieldDef::new(FULL_NAME),
                            FieldDef::new("Passport Number").set_require_protection(true),
                            FieldDef::new(NATIONALITY),
                            FieldDef::new(DATE_OF_BIRTH).set_data_type(FieldDataType::Date),
                            FieldDef::new("Place of Birth"),
                            FieldDef::new("Sex"),
                        ],
                    },
                    Section {
                        name: "Issuance".into(),
                        field_defs: vec![
                            FieldDef::new("Issuing Country"),
                            FieldDef::new("Issuing Authority"),
                            FieldDef::new(ISSUE_DATE).set_data_type(FieldDataType::Date),
                            FieldDef::new(EXPIRATION_DATE).set_data_type(FieldDataType::Date),
                        ],
                    },
                    Section {
                        name: "Travel".into(),
                        field_defs: vec![
                            FieldDef::new("Visa Number"),
                            FieldDef::new("Known Traveler Number"),
                            FieldDef::new("Redress Number"),
                        ],
                    },
                    Section {
                        name: "Emergency Contact".into(),
                        field_defs: vec![
                            FieldDef::new("Name"),
                            FieldDef::new("Phone"),
                        ],
                    },
                ],
            },
        );

        m.insert(
            build_uuid!(entry_type_uuid::DRIVER_LICENSE),
            EntryType {
                uuid: build_uuid!(entry_type_uuid::DRIVER_LICENSE),
                name: DRIVER_LICENSE.into(),
                secondary_title: Some(FULL_NAME.into()),
                icon_name: None,
                sections: vec![
                    Section {
                        name: "License Details".into(),
                        field_defs: vec![
                            FieldDef::new(FULL_NAME),
                            FieldDef::new("License Number").set_require_protection(true),
                            FieldDef::new("Class"),
                            FieldDef::new(STATE_PROVINCE_REGION),
                            FieldDef::new("Country"),
                        ],
                    },
                    Section {
                        name: DATES.into(),
                        field_defs: vec![
                            FieldDef::new(ISSUE_DATE).set_data_type(FieldDataType::Date),
                            FieldDef::new(EXPIRATION_DATE).set_data_type(FieldDataType::Date),
                            FieldDef::new(DATE_OF_BIRTH).set_data_type(FieldDataType::Date),
                        ],
                    },
                    Section {
                        name: "Restrictions".into(),
                        field_defs: vec![
                            FieldDef::new("Restrictions"),
                            FieldDef::new("Endorsements"),
                        ],
                    },
                ],
            },
        );

        m.insert(
            build_uuid!(entry_type_uuid::SSH_LOGIN),
            EntryType {
                uuid: build_uuid!(entry_type_uuid::SSH_LOGIN),
                name: SSH_LOGIN.into(),
                secondary_title: Some(HOST.into()),
                icon_name: None,
                sections: vec![
                    Section {
                        name: CONNECTION.into(),
                        field_defs: vec![
                            FieldDef::new(HOST).required(),
                            FieldDef::new(PORT).set_data_type(FieldDataType::Number),
                            FieldDef::new(USER_NAME),
                            FieldDef::new(PASSWORD).set_require_protection(true),
                            FieldDef::new(START_DIR),
                        ],
                    },
                    Section {
                        name: "SSH Key".into(),
                        field_defs: vec![
                            FieldDef::new(PRIVATE_KEY).set_require_protection(true),
                            FieldDef::new("Private Key Passphrase").set_require_protection(true),
                            FieldDef::new("Public Key"),
                        ],
                    },
                    Section {
                        name: "SSH Agent".into(),
                        field_defs: vec![
                            FieldDef::new("Enable SSH Agent").set_data_type(FieldDataType::Bool),
                            FieldDef::new("Require Confirmation").set_data_type(FieldDataType::Bool),
                            FieldDef::new("Agent Lifetime"),
                            FieldDef::new("Allowed Hosts"),
                        ],
                    },
                    Section {
                        name: "Metadata".into(),
                        field_defs: vec![
                            FieldDef::new(ENVIRONMENT),
                            FieldDef::new("Region"),
                            FieldDef::new(PROVIDER),
                            FieldDef::new(ADMIN_URL),
                            FieldDef::new(ADDITIONAL_URLS),
                        ],
                    },
                ],
            },
        );

        m.insert(
            build_uuid!(entry_type_uuid::API_CREDENTIAL),
            EntryType {
                uuid: build_uuid!(entry_type_uuid::API_CREDENTIAL),
                name: API_CREDENTIAL.into(),
                secondary_title: Some("Service".into()),
                icon_name: None,
                sections: vec![
                    Section {
                        name: "Service".into(),
                        field_defs: vec![
                            FieldDef::new("Service"),
                            FieldDef::new(URL),
                            FieldDef::new(ENVIRONMENT),
                            FieldDef::new("Project"),
                        ],
                    },
                    Section {
                        name: "Credentials".into(),
                        field_defs: vec![
                            FieldDef::new("API Key").set_require_protection(true),
                            FieldDef::new("API Secret").set_require_protection(true),
                            FieldDef::new("Client ID"),
                            FieldDef::new("Client Secret").set_require_protection(true),
                            FieldDef::new("Token").set_require_protection(true),
                            FieldDef::new("Refresh Token").set_require_protection(true),
                        ],
                    },
                    Section {
                        name: "Lifecycle".into(),
                        field_defs: vec![
                            FieldDef::new("Created Date").set_data_type(FieldDataType::Date),
                            FieldDef::new(EXPIRATION_DATE).set_data_type(FieldDataType::Date),
                            FieldDef::new("Scopes"),
                        ],
                    },
                ],
            },
        );

        m.insert(
            build_uuid!(entry_type_uuid::DATABASE_CREDENTIAL),
            EntryType {
                uuid: build_uuid!(entry_type_uuid::DATABASE_CREDENTIAL),
                name: DATABASE_CREDENTIAL.into(),
                secondary_title: Some(HOST.into()),
                icon_name: None,
                sections: vec![
                    Section {
                        name: CONNECTION.into(),
                        field_defs: vec![
                            FieldDef::new("Database Type"),
                            FieldDef::new(HOST),
                            FieldDef::new(PORT).set_data_type(FieldDataType::Number),
                            FieldDef::new("Database Name"),
                            FieldDef::new(USER_NAME),
                            FieldDef::new(PASSWORD).set_require_protection(true),
                        ],
                    },
                    Section {
                        name: "Options".into(),
                        field_defs: vec![
                            FieldDef::new("SSL Required").set_data_type(FieldDataType::Bool),
                            FieldDef::new("Connection String").set_require_protection(true),
                            FieldDef::new(ADMIN_URL),
                        ],
                    },
                ],
            },
        );

        m.insert(
            build_uuid!(entry_type_uuid::SOFTWARE_LICENSE),
            EntryType {
                uuid: build_uuid!(entry_type_uuid::SOFTWARE_LICENSE),
                name: SOFTWARE_LICENSE.into(),
                secondary_title: Some("Product".into()),
                icon_name: None,
                sections: vec![
                    Section {
                        name: "Product".into(),
                        field_defs: vec![
                            FieldDef::new("Product"),
                            FieldDef::new("Vendor"),
                            FieldDef::new("Version"),
                            FieldDef::new("Website"),
                        ],
                    },
                    Section {
                        name: "License".into(),
                        field_defs: vec![
                            FieldDef::new("License Key").set_require_protection(true),
                            FieldDef::new("Licensed To"),
                            FieldDef::new("Seats").set_data_type(FieldDataType::Number),
                            FieldDef::new("Purchase Date").set_data_type(FieldDataType::Date),
                            FieldDef::new(EXPIRATION_DATE).set_data_type(FieldDataType::Date),
                        ],
                    },
                    Section {
                        name: "Support".into(),
                        field_defs: vec![
                            FieldDef::new("Support Email"),
                            FieldDef::new("Support URL"),
                            FieldDef::new("Order Number"),
                        ],
                    },
                ],
            },
        );

        m.insert(
            build_uuid!(entry_type_uuid::MEMBERSHIP),
            EntryType {
                uuid: build_uuid!(entry_type_uuid::MEMBERSHIP),
                name: MEMBERSHIP.into(),
                secondary_title: Some("Organization".into()),
                icon_name: None,
                sections: vec![
                    Section {
                        name: "Membership".into(),
                        field_defs: vec![
                            FieldDef::new("Organization"),
                            FieldDef::new("Member Number").set_require_protection(true),
                            FieldDef::new("Member Name"),
                            FieldDef::new("Level"),
                        ],
                    },
                    Section {
                        name: "Access".into(),
                        field_defs: vec![
                            FieldDef::new(USER_NAME),
                            FieldDef::new(PASSWORD).set_require_protection(true),
                            FieldDef::new(OTP)
                                .set_data_type(FieldDataType::OneTimePassword)
                                .set_require_protection(true),
                            FieldDef::new(URL),
                        ],
                    },
                    Section {
                        name: ADDITIONAL_ONE_TIME_PASSWORDS.into(),
                        field_defs: vec![],
                    },
                    Section {
                        name: DATES.into(),
                        field_defs: vec![
                            FieldDef::new("Start Date").set_data_type(FieldDataType::Date),
                            FieldDef::new(EXPIRATION_DATE).set_data_type(FieldDataType::Date),
                        ],
                    },
                    Section {
                        name: CONTACT.into(),
                        field_defs: vec![
                            FieldDef::new("Contact Number"),
                            FieldDef::new("Contact email"),
                        ],
                    },
                ],
            },
        );

        m.insert(
            build_uuid!(entry_type_uuid::CRYPTO_WALLET),
            EntryType {
                uuid: build_uuid!(entry_type_uuid::CRYPTO_WALLET),
                name: CRYPTO_WALLET.into(),
                secondary_title: Some("Wallet Name".into()),
                icon_name: None,
                sections: vec![
                    Section {
                        name: "Wallet Details".into(),
                        field_defs: vec![
                            FieldDef::new("Wallet Name"),
                            FieldDef::new("Wallet Type"),
                            FieldDef::new("Wallet Address"),
                            FieldDef::new("Blockchain"),
                        ],
                    },
                    Section {
                        name: "Secrets".into(),
                        field_defs: vec![
                            FieldDef::new("Recovery Phrase").set_require_protection(true),
                            FieldDef::new(PRIVATE_KEY).set_require_protection(true),
                            FieldDef::new("PIN").set_require_protection(true),
                            FieldDef::new("Passphrase").set_require_protection(true),
                        ],
                    },
                    Section {
                        name: LOGIN_DETAILS.into(),
                        field_defs: vec![
                            FieldDef::new(USER_NAME),
                            FieldDef::new(PASSWORD).set_require_protection(true),
                            FieldDef::new(OTP)
                                .set_data_type(FieldDataType::OneTimePassword)
                                .set_require_protection(true),
                            FieldDef::new(URL),
                            FieldDef::new(ADDITIONAL_URLS),
                        ],
                    },
                    Section {
                        name: ADDITIONAL_ONE_TIME_PASSWORDS.into(),
                        field_defs: vec![],
                    },
                ],
            },
        );

        m.insert(
            build_uuid!(entry_type_uuid::EMAIL_ACCOUNT),
            EntryType {
                uuid: build_uuid!(entry_type_uuid::EMAIL_ACCOUNT),
                name: EMAIL_ACCOUNT.into(),
                secondary_title: Some(EMAIL.into()),
                icon_name: None,
                sections: vec![
                    Section {
                        name: "Account".into(),
                        field_defs: vec![
                            FieldDef::new(EMAIL),
                            FieldDef::new("Display Name"),
                            FieldDef::new(PROVIDER),
                        ],
                    },
                    Section {
                        name: LOGIN_DETAILS.into(),
                        field_defs: vec![
                            FieldDef::new(USER_NAME),
                            FieldDef::new(PASSWORD).set_require_protection(true),
                            FieldDef::new(OTP)
                                .set_data_type(FieldDataType::OneTimePassword)
                                .set_require_protection(true),
                            FieldDef::new(URL),
                            FieldDef::new(ADDITIONAL_URLS),
                        ],
                    },
                    Section {
                        name: ADDITIONAL_ONE_TIME_PASSWORDS.into(),
                        field_defs: vec![],
                    },
                    Section {
                        name: "Server Settings".into(),
                        field_defs: vec![
                            FieldDef::new("IMAP Host"),
                            FieldDef::new("IMAP Port").set_data_type(FieldDataType::Number),
                            FieldDef::new("IMAP Security"),
                            FieldDef::new("SMTP Host"),
                            FieldDef::new("SMTP Port").set_data_type(FieldDataType::Number),
                            FieldDef::new("SMTP Security"),
                            FieldDef::new("POP3 Host"),
                            FieldDef::new("POP3 Port").set_data_type(FieldDataType::Number),
                        ],
                    },
                ],
            },
        );

        m.insert(
            build_uuid!(entry_type_uuid::INSURANCE_POLICY),
            EntryType {
                uuid: build_uuid!(entry_type_uuid::INSURANCE_POLICY),
                name: INSURANCE_POLICY.into(),
                secondary_title: Some(PROVIDER.into()),
                icon_name: None,
                sections: vec![
                    Section {
                        name: "Policy Details".into(),
                        field_defs: vec![
                            FieldDef::new(PROVIDER),
                            FieldDef::new("Policy Number").set_require_protection(true),
                            FieldDef::new("Policy Type"),
                        ],
                    },
                    Section {
                        name: "Coverage".into(),
                        field_defs: vec![
                            FieldDef::new("Coverage Amount"),
                            FieldDef::new("Premium"),
                            FieldDef::new("Deductible"),
                        ],
                    },
                    Section {
                        name: DATES.into(),
                        field_defs: vec![
                            FieldDef::new("Effective Date").set_data_type(FieldDataType::Date),
                            FieldDef::new(EXPIRATION_DATE).set_data_type(FieldDataType::Date),
                        ],
                    },
                    Section {
                        name: "Contacts".into(),
                        field_defs: vec![
                            FieldDef::new("Agent Name"),
                            FieldDef::new("Agent Phone"),
                            FieldDef::new("Agent Email"),
                            FieldDef::new("Claims Phone"),
                            FieldDef::new("Claims URL"),
                        ],
                    },
                    Section {
                        name: LOGIN_DETAILS.into(),
                        field_defs: vec![
                            FieldDef::new(USER_NAME),
                            FieldDef::new(PASSWORD).set_require_protection(true),
                            FieldDef::new(OTP)
                                .set_data_type(FieldDataType::OneTimePassword)
                                .set_require_protection(true),
                            FieldDef::new(URL),
                        ],
                    },
                    Section {
                        name: ADDITIONAL_ONE_TIME_PASSWORDS.into(),
                        field_defs: vec![],
                    },
                ],
            },
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
            //&* gives &Uuid and we use unwrap assuming STANDARD_TYPE_UUIDS_BY_NAME and STANDARD_TYPE_NAMES match
            let uuid = &*STANDARD_TYPE_UUIDS_BY_NAME.get(s).unwrap();
            (uuid.clone(), (&**s).into())
        })
        .collect()
}

pub fn standard_types_ordered_by_id() -> Vec<&'static EntryType> {
    STANDARD_TYPE_NAMES
        .iter()
        .map(|s| {
            // IMPORATNT: we use unwrap expecting that STANDARD_TYPE_UUIDS_BY_NAME and STANDARD_TYPE_NAMES match
            let uuid = STANDARD_TYPE_UUIDS_BY_NAME.get(s).unwrap();
            UUID_TO_ENTRY_TYPE_MAP
                .get(uuid)
                .map_or_else(|| &*DEFAULT_ENTRY_TYPE, |e| e)
        })
        .collect::<Vec<&EntryType>>()
}

// Gets the entry typ's UUID from its name
pub fn standard_type_uuid_by_name(type_name: &str) -> &Uuid {
    STANDARD_TYPE_UUIDS_BY_NAME.get(type_name).unwrap()
}

pub fn _auto_open_entry_type_opt() -> Option<&'static EntryType> {
    let uuid = build_uuid!(entry_type_uuid::AUTO_DB_OPEN);
    UUID_TO_ENTRY_TYPE_MAP.get(&uuid)
}

pub fn auto_open_entry_type() -> &'static EntryType {
    let uuid = build_uuid!(entry_type_uuid::AUTO_DB_OPEN);
    // IMPORATNT: we use unwrap expecting that AUTO_DB_OPEN is already set
    UUID_TO_ENTRY_TYPE_MAP.get(&uuid).unwrap()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // Guards the unwrap() calls in standard_types_ordered_by_id() and
    // standard_type_uuids_names_ordered_by_id(): every name listed in
    // STANDARD_TYPE_NAMES must resolve to a UUID and to an EntryType.
    #[test]
    fn every_standard_type_is_fully_registered() {
        for name in STANDARD_TYPE_NAMES {
            let uuid = STANDARD_TYPE_UUIDS_BY_NAME
                .get(name)
                .unwrap_or_else(|| panic!("'{name}' missing from STANDARD_TYPE_UUIDS_BY_NAME"));
            let entry_type = UUID_TO_ENTRY_TYPE_MAP
                .get(uuid)
                .unwrap_or_else(|| panic!("'{name}' missing from UUID_TO_ENTRY_TYPE_MAP"));
            assert_eq!(
                &entry_type.name, name,
                "EntryType.name does not match registry name for '{name}'"
            );
            assert_eq!(
                &entry_type.uuid, uuid,
                "EntryType.uuid does not match registry uuid for '{name}'"
            );
        }
    }

    #[test]
    fn standard_type_uuids_are_unique() {
        let mut seen = HashSet::new();
        for name in STANDARD_TYPE_NAMES {
            let uuid = STANDARD_TYPE_UUIDS_BY_NAME.get(name).unwrap();
            assert!(seen.insert(*uuid), "duplicate UUID for standard type '{name}'");
        }
    }

    // Entry KVs are flat, so a field name must be unique across all sections
    // within a single entry type (section names may coincide with field names,
    // which is fine - they live in different namespaces).
    #[test]
    fn field_names_unique_within_each_standard_type() {
        for name in STANDARD_TYPE_NAMES {
            let uuid = STANDARD_TYPE_UUIDS_BY_NAME.get(name).unwrap();
            let entry_type = UUID_TO_ENTRY_TYPE_MAP.get(uuid).unwrap();
            let mut seen = HashSet::new();
            for section in &entry_type.sections {
                for fd in &section.field_defs {
                    assert!(
                        seen.insert(fd.name.clone()),
                        "duplicate field '{}' in entry type '{name}'",
                        fd.name
                    );
                }
            }
        }
    }
}
