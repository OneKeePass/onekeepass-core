// FileSignature1, FileSignature2 and FileVersion32 in KeePassLib/Serialization/KdbxFile.cs
#[allow(dead_code)]
pub const SIG1: u32 = 0x9AA2_D903;
pub const SIG2: u32 = 0xB54B_FB67;
pub const VERSION_40: u32 = 0x0004_0000;
pub const VERSION_41: u32 = 0x0004_0001;

// Not supported versions
pub const OLD_SIG1: u32 = 0x9AA2_D903;
pub const OLD_SIG2: u32 = 0xB54B_FB65;
pub const VERSION_30: u32 = 0x0003_0000;
pub const VERSION_31: u32 = 0x0003_0001;
pub const VERSION_20: u32 = 0x0002_0000;

#[allow(dead_code)]
pub const VD_VER: u16 = 0x0100;
#[allow(dead_code)]
pub const HEADER_BLK_IDX: u64 = ::std::u64::MAX;
#[allow(dead_code)]
pub const SALSA20_IV: &[u8] = &[0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
#[allow(dead_code)]
pub const EMPTY: &[u8] = &[];

// Encrypted data is split into blocks of this size before prefixed with its hmac
pub const PAYLOAD_BLOCK_SIZE: u64 = 1048576; // (1MB = 1024 * 1024), 65536  1048576

/*
// Not yet used
Version 2:
    Otp changes
*/
#[allow(dead_code)]
pub const INTERNAL_VERSION: i32 = 2;

pub const GENERATOR_NAME: &str = "OneKeyPass";

pub const EMPTY_STR: &str = "";

pub const OTP_URL_PREFIX: &str = "otpauth://totp";

// pub const AUTO_OPEN_GROUP_NAME: &str = "AutoOpen";

pub const AUTO_OPEN_GROUP_UC_NAME: &str = "AUTOOPEN";

// All Custom Data keys are of pattern OKP_K*. This is used instead of some descriptive
// string to reduce number of bytes taken by the key name entries in db and thus overall size of db
// Any new key should have the next OKP_Kx.
// Do not change the existing key names and meaning to make sure for backward compatability

#[allow(dead_code)]
pub mod custom_data_key {
    pub const OKP_INTERNAL_VERSION: &str = "OKP_K1";

    pub const OKP_GROUP_AS_CATEGORY: &str = "OKP_K2";

    // Key for the name of the Entry type and value for this is the serialized uuid
    pub const OKP_ENTRY_TYPE: &str = "OKP_K3";

    // The value found corresponding to this custom data key is the serialized Entry type Data
    pub const OKP_ENTRY_TYPE_DATA: &str = "OKP_K4";

    // The value found corresponding to this custom data key is
    // the serialized HashMap of Entry type Data
    pub const OKP_ENTRY_TYPE_MAP_DATA: &str = "OKP_K5";

    // The value associated to this key is the list of serialized Entry type Data
    // that may be used in an entry's history entries
    pub const OKP_ENTRY_TYPE_LIST_DATA: &str = "OKP_K6";

    // The index in place of Entry type Data in the history entry
    pub const OKP_ENTRY_TYPE_DATA_INDEX: &str = "OKP_K7";
}

pub mod general_category_names {
    pub const ALL_ENTRIES: &str = "AllEntries";
    pub const FAVORITES: &str = "Favorites";
    pub const DELETED: &str = "Deleted";
}

#[allow(dead_code)]
pub mod standard_in_section_names {
    pub const LOGIN_DETAILS: &str = "Login Details";
    pub const ADDITIONAL_ONE_TIME_PASSWORDS: &str = "Additional One-Time Passwords";
    pub const CARD_DETAILS: &str = "Card Details";
    pub const PASSKEY_DETAILS: &str = "Passkey Details";

    // Section names shared by two or more of the standard entry types added for
    // the extended entry templates. Section names used by a single type are kept
    // as string literals at the type definition site.
    pub const CONNECTION: &str = "Connection";
    pub const DATES: &str = "Dates";
    pub const CONTACT: &str = "Contact";
}

#[allow(dead_code)]
pub mod entry_type_name {
    pub const LOGIN: &str = "Login";
    pub const WIRELESS_ROUTER: &str = "Wireless Router";
    pub const CREDIT_DEBIT_CARD: &str = "Credit/Debit Card";
    pub const BANK_ACCOUNT: &str = "Bank Account";

    pub const AUTO_DB_OPEN: &str = "Auto Database Open";

    // Remote-storage connection entry types. A user keeps SFTP / WebDAV server
    // credentials as regular kdbx entries; the remote_storage resolver looks
    // them up by entry uuid (= connection id). See Plans-Created/Remote-Storage.
    pub const REMOTE_CONNECTION_SFTP: &str = "SFTP Connection";
    pub const REMOTE_CONNECTION_WEBDAV: &str = "WebDAV Connection";

    pub const PASSPORT: &str = "Passport";
    pub const IDENTITY: &str = "Identity";
    pub const DRIVER_LICENSE: &str = "Driver License";

    pub const SSH_LOGIN: &str = "SSH Login";
    pub const SSH_KEY: &str = "SSH Key";
    pub const API_CREDENTIAL: &str = "API Credential";
    pub const DATABASE_CREDENTIAL: &str = "Database Credential";
    pub const SOFTWARE_LICENSE: &str = "Software License";
    pub const MEMBERSHIP: &str = "Membership";
    pub const CRYPTO_WALLET: &str = "Crypto Wallet";
    pub const EMAIL_ACCOUNT: &str = "Email Account";
    pub const INSURANCE_POLICY: &str = "Insurance Policy";

    //Medical Record,
}

// We can generate hex bytes like this using
// let uid = Uuid::new_v4();
// println!("{}",util::as_hex_array_formatted(uid.as_bytes()));
// println!("{}",uid.to_string());

// See the test fn 'generate_uuid()' in the mod tests at the bottom

#[allow(dead_code)]
pub mod entry_type_uuid {
    // ffef5f51-7efc-4373-9eb5-382d5b501768
    pub const LOGIN: &[u8] = &[
        0xFF, 0xEF, 0x5F, 0x51, 0x7E, 0xFC, 0x43, 0x73, 0x9E, 0xB5, 0x38, 0x2D, 0x5B, 0x50, 0x17,
        0x68,
    ];

    // 9e644c27-d00b-4aca-8355-5078c5a4fb44
    pub const WIRELESS_ROUTER: &[u8] = &[
        0x9E, 0x64, 0x4C, 0x27, 0xD0, 0x0B, 0x4A, 0xCA, 0x83, 0x55, 0x50, 0x78, 0xC5, 0xA4, 0xFB,
        0x44,
    ];

    // c83aa78a-3a8c-45fc-b0e1-08002d166544
    pub const CREDIT_DEBIT_CARD: &[u8] = &[
        0xC8, 0x3A, 0xA7, 0x8A, 0x3A, 0x8C, 0x45, 0xFC, 0xB0, 0xE1, 0x08, 0x00, 0x2D, 0x16, 0x65,
        0x44,
    ];
    // 713850b6-9457-45ca-a861-0402db2ca98f
    pub const BANK_ACCOUNT: &[u8] = &[
        0x71, 0x38, 0x50, 0xB6, 0x94, 0x57, 0x45, 0xCA, 0xA8, 0x61, 0x04, 0x02, 0xDB, 0x2C, 0xA9,
        0x8F,
    ];

    // 0ba6d80b-8b8d-4ccd-b0dc-840337951cb0
    pub const PASSPORT: &[u8] = &[
        0x0B, 0xA6, 0xD8, 0x0B, 0x8B, 0x8D, 0x4C, 0xCD, 0xB0, 0xDC, 0x84, 0x03, 0x37, 0x95, 0x1C,
        0xB0,
    ];

    // e5aff423-1044-40fe-9565-c0e8dde626c2
    pub const IDENTITY: &[u8] = &[
        0xE5, 0xAF, 0xF4, 0x23, 0x10, 0x44, 0x40, 0xFE, 0x95, 0x65, 0xC0, 0xE8, 0xDD, 0xE6, 0x26,
        0xC2,
    ];

    // 90ac9d76-7ea7-4176-b5d0-fabf8a9a0058
    pub const DRIVER_LICENSE: &[u8] = &[
        0x90, 0xAC, 0x9D, 0x76, 0x7E, 0xA7, 0x41, 0x76, 0xB5, 0xD0, 0xFA, 0xBF, 0x8A, 0x9A, 0x00,
        0x58,
    ];

    // 389368a9-73a9-4256-8247-321a2e60b2c7
    pub const AUTO_DB_OPEN: &[u8] = &[
        0x38, 0x93, 0x68, 0xA9, 0x73, 0xA9, 0x42, 0x56, 0x82, 0x47, 0x32, 0x1A, 0x2E, 0x60, 0xB2,
        0xC7,
    ];

    // c5a57a41-4cca-4a46-bac1-78a8803f4da0
    pub const REMOTE_CONNECTION_SFTP: &[u8] = &[
        0xC5, 0xA5, 0x7A, 0x41, 0x4C, 0xCA, 0x4A, 0x46, 0xBA, 0xC1, 0x78, 0xA8, 0x80, 0x3F, 0x4D,
        0xA0,
    ];

    // 0a14d76d-8c38-4c62-9ad7-390dc020a2af
    pub const REMOTE_CONNECTION_WEBDAV: &[u8] = &[
        0x0A, 0x14, 0xD7, 0x6D, 0x8C, 0x38, 0x4C, 0x62, 0x9A, 0xD7, 0x39, 0x0D, 0xC0, 0x20, 0xA2,
        0xAF,
    ];

    // 7319773d-c78a-463b-ab49-7585bb5909cc
    pub const SSH_LOGIN: &[u8] = &[
        0x73, 0x19, 0x77, 0x3D, 0xC7, 0x8A, 0x46, 0x3B, 0xAB, 0x49, 0x75, 0x85, 0xBB, 0x59, 0x09,
        0xCC,
    ];

    // 6421a61a-db18-413a-bdfb-715a5418216a
    pub const SSH_KEY: &[u8] = &[
        0x64, 0x21, 0xA6, 0x1A, 0xDB, 0x18, 0x41, 0x3A, 0xBD, 0xFB, 0x71, 0x5A, 0x54, 0x18, 0x21,
        0x6A,
    ];

    // 6c918f85-b693-44cc-a680-98e92fdd99ab
    pub const API_CREDENTIAL: &[u8] = &[
        0x6C, 0x91, 0x8F, 0x85, 0xB6, 0x93, 0x44, 0xCC, 0xA6, 0x80, 0x98, 0xE9, 0x2F, 0xDD, 0x99,
        0xAB,
    ];

    // 8f028cee-840f-42fe-8e59-ec2005be6472
    pub const DATABASE_CREDENTIAL: &[u8] = &[
        0x8F, 0x02, 0x8C, 0xEE, 0x84, 0x0F, 0x42, 0xFE, 0x8E, 0x59, 0xEC, 0x20, 0x05, 0xBE, 0x64,
        0x72,
    ];

    // a247a041-c670-4d8a-9330-281a4af269f9
    pub const SOFTWARE_LICENSE: &[u8] = &[
        0xA2, 0x47, 0xA0, 0x41, 0xC6, 0x70, 0x4D, 0x8A, 0x93, 0x30, 0x28, 0x1A, 0x4A, 0xF2, 0x69,
        0xF9,
    ];

    // 1ddd2485-29d6-4fc9-bae5-f2ffda3161e1
    pub const MEMBERSHIP: &[u8] = &[
        0x1D, 0xDD, 0x24, 0x85, 0x29, 0xD6, 0x4F, 0xC9, 0xBA, 0xE5, 0xF2, 0xFF, 0xDA, 0x31, 0x61,
        0xE1,
    ];

    // 96790d2d-3dcf-42a8-ad75-5c550cc88120
    pub const CRYPTO_WALLET: &[u8] = &[
        0x96, 0x79, 0x0D, 0x2D, 0x3D, 0xCF, 0x42, 0xA8, 0xAD, 0x75, 0x5C, 0x55, 0x0C, 0xC8, 0x81,
        0x20,
    ];

    // f8785455-d227-4ef6-a43f-f0459565724f
    pub const EMAIL_ACCOUNT: &[u8] = &[
        0xF8, 0x78, 0x54, 0x55, 0xD2, 0x27, 0x4E, 0xF6, 0xA4, 0x3F, 0xF0, 0x45, 0x95, 0x65, 0x72,
        0x4F,
    ];

    // 04952f8e-a9cf-4003-8f1c-6ea86af1515b
    pub const INSURANCE_POLICY: &[u8] = &[
        0x04, 0x95, 0x2F, 0x8E, 0xA9, 0xCF, 0x40, 0x03, 0x8F, 0x1C, 0x6E, 0xA8, 0x6A, 0xF1, 0x51,
        0x5B,
    ];
}

#[allow(dead_code)]
pub mod entry_keyvalue_key {
    pub const TITLE: &str = "Title";
    pub const NOTES: &str = "Notes";
    pub const USER_NAME: &str = "UserName";
    pub const PASSWORD: &str = "Password";
    pub const OTP: &str = "otp";
    pub const URL: &str = "URL";
    pub const ADDITIONAL_URLS: &str = "Additional URLs";

    pub const SSID: &str = "Base Station Name or SSID";

    pub const NUMBER: &str = "Number";

    pub const IF_DEVICE: &str = "IfDevice";

    // Fields used by the REMOTE_CONNECTION_SFTP / REMOTE_CONNECTION_WEBDAV
    // entry types. The remote-storage resolver maps these kvs onto
    // SftpConnectionConfig / WebdavConnectionConfig via from_kvs.
    pub const HOST: &str = "Host";
    pub const PORT: &str = "Port";
    pub const START_DIR: &str = "Start Dir";
    pub const ALLOW_UNTRUSTED_CERT: &str = "Allow Untrusted Cert";

    // pub const ENABLED: &str = "Enabled";
    // pub const PRIORITY: &str = "Priority";
    // pub const SKIP_IF_NOT_EXISTS: &str = "SkipIfNotExists";
    // pub const SKIP_IF_KEY_FILE_NOT_EXISTS: &str = "SkipIfKeyFileNotExists";

    // Field names shared by two or more of the extended standard entry types
    // (Identity, Passport, Driver License, SSH Login, etc.). Fields used by a
    // single type are kept as string literals at the type definition site,
    // matching the existing Credit/Debit Card and Bank Account definitions.
    pub const FIRST_NAME: &str = "First Name";
    pub const MIDDLE_NAME: &str = "Middle Name";
    pub const LAST_NAME: &str = "Last Name";
    pub const DATE_OF_BIRTH: &str = "Date of Birth";
    pub const NATIONALITY: &str = "Nationality";
    pub const EXPIRATION_DATE: &str = "Expiration Date";
    pub const ISSUE_DATE: &str = "Issue Date";
    pub const EMAIL: &str = "Email";
    pub const POSTAL_CODE: &str = "Postal Code";
    pub const STATE_PROVINCE_REGION: &str = "State / Province / Region";
    pub const ADMIN_URL: &str = "Admin URL";
    pub const ENVIRONMENT: &str = "Environment";
    pub const PRIVATE_KEY: &str = "Private Key";
    pub const PROVIDER: &str = "Provider";

    // SSH Key entry type fields. Referenced by both the type definition and the
    // ssh-agent key-source enumeration, so kept as shared constants.
    pub const PUBLIC_KEY: &str = "Public Key";
    pub const ADD_TO_SSH_AGENT: &str = "Add to SSH Agent";
    pub const REQUIRE_CONFIRMATION: &str = "Require Confirmation";
    pub const AGENT_LIFETIME: &str = "Agent Lifetime";

    // Passkey fields (KeePassXC-compatible)
    pub const KPEX_PASSKEY_USERNAME: &str = "KPEX_PASSKEY_USERNAME";
    pub const KPEX_PASSKEY_RELYING_PARTY: &str = "KPEX_PASSKEY_RELYING_PARTY";
    pub const KPEX_PASSKEY_USER_HANDLE: &str = "KPEX_PASSKEY_USER_HANDLE";
    pub const KPEX_PASSKEY_CREDENTIAL_ID: &str = "KPEX_PASSKEY_CREDENTIAL_ID";
    pub const KPEX_PASSKEY_PRIVATE_KEY_PEM: &str = "KPEX_PASSKEY_PRIVATE_KEY_PEM";
}

// Note:
// At this time mainly some essential xml elements are used in OKP app
// For example, tags such as Color, ForegroundColor, BackgroundColor ect are not considered

//#[allow(non_upper_case_globals)]
#[allow(dead_code)]
pub mod xml_element {
    pub const KEEPASS_FILE: &[u8] = b"KeePassFile";
    pub const META: &[u8] = b"Meta";
    pub const ROOT: &[u8] = b"Root";

    //Meta
    pub const GENERATOR: &[u8] = b"Generator";
    pub const DATABASE_NAME: &[u8] = b"DatabaseName";
    pub const DATABASE_NAME_CHANGED: &[u8] = b"DatabaseNameChanged"; //date time
    pub const DATABASE_DESCRIPTION: &[u8] = b"DatabaseDescription";
    pub const DATABASE_DESCRIPTION_CHANGED: &[u8] = b"DatabaseDescriptionChanged";
    pub const SETTINGS_CHANGED: &[u8] = b"SettingsChanged";

    pub const DEFAULT_USER_NAME: &[u8] = b"DefaultUserName";
    pub const DEFAULT_USER_NAME_CHANGED: &[u8] = b"DefaultUserNameChanged";

    pub const MASTER_KEY_CHANGED: &[u8] = b"MasterKeyChanged";
    pub const RECYCLE_BIN_ENABLED: &[u8] = b"RecycleBinEnabled";

    pub const RECYCLE_BIN_UUID: &[u8] = b"RecycleBinUUID";
    pub const RECYCLE_BIN_CHANGED: &[u8] = b"RecycleBinChanged";

    pub const ENTRY_TEMPLATE_GROUP: &[u8] = b"EntryTemplatesGroup";
    pub const ENTRY_TEMPLATE_GROUP_CHANGED: &[u8] = b"EntryTemplatesGroupChanged";

    pub const HISTORY_MAX_ITEMS: &[u8] = b"HistoryMaxItems";
    pub const MAINTENANCE_HISTORY_DAYS: &[u8] = b"MaintenanceHistoryDays";
    pub const HISTORY_MAX_SIZE: &[u8] = b"HistoryMaxSize";
    pub const LAST_SELECTED_GROUP: &[u8] = b"LastSelectedGroup";

    pub const MEMORY_PROTECTION: &[u8] = b"MemoryProtection";
    pub const PROTECT_TITLE: &[u8] = b"ProtectTitle";
    pub const PROTECT_USER_NAME: &[u8] = b"ProtectUserName";
    pub const PROTECT_PASSWORD: &[u8] = b"ProtectPassword";
    pub const PROTECT_URL: &[u8] = b"ProtectURL";
    pub const PROTECT_NOTES: &[u8] = b"ProtectNotes";

    pub const CUSTOM_ICONS: &[u8] = b"CustomIcons";
    pub const ICON: &[u8] = b"Icon";
    pub const DATA: &[u8] = b"Data";
    // NAME and LAST_MODIFICATION_TIME are added in VERSION_41 of CUSTOM_ICONS

    // It seems, 'KeePass' removes an entry or group completely and writes its UUID
    // here. This happens when RECYCLE_BIN_ENABLED is false ( By default it is false in KeePass app)
    // OneKeePass and other implementation like KeePassXC uses RECYCLE_BIN_ENABLED = true and
    // Gives the user an option later to empty recycle bin or undo
    // However, when groups or entries are deleted permanently, the uuids of those objectes
    // are added under DeletedObjects after removing the groups/entries content from db
    pub const DELETED_OBJECTS: &[u8] = b"DeletedObjects";
    pub const DELETED_OBJECT: &[u8] = b"DeletedObject";
    pub const DELETION_TIME: &[u8] = b"DeletionTime";

    //Some Common tags

    //Custom Data
    pub const CUSTOM_DATA: &[u8] = b"CustomData";
    pub const ITEM: &[u8] = b"Item";

    //Times
    pub const TIMES: &[u8] = b"Times";
    pub const LAST_MODIFICATION_TIME: &[u8] = b"LastModificationTime";
    pub const CREATION_TIME: &[u8] = b"CreationTime";
    pub const LAST_ACCESS_TIME: &[u8] = b"LastAccessTime";
    pub const EXPIRES: &[u8] = b"Expires";
    pub const EXPIRY_TIME: &[u8] = b"ExpiryTime";
    pub const LOCATION_CHANGED: &[u8] = b"LocationChanged";
    pub const USAGE_COUNT: &[u8] = b"UsageCount";

    //pub const :&[u8]  = b"";
    pub const NOTES: &[u8] = b"Notes";
    pub const TAGS: &[u8] = b"Tags";

    pub const GROUP: &[u8] = b"Group";
    pub const UUID: &[u8] = b"UUID";
    pub const NAME: &[u8] = b"Name";
    pub const ICON_ID: &[u8] = b"IconID";
    pub const LAST_TOP_VISIBLE_ENTRY: &[u8] = b"LastTopVisibleEntry";
    pub const IS_EXPANDED: &[u8] = b"IsExpanded";

    //

    //Entry
    pub const ENTRY: &[u8] = b"Entry";
    pub const BINARY: &[u8] = b"Binary";
    pub const STRING: &[u8] = b"String";
    pub const KEY: &[u8] = b"Key";
    pub const VALUE: &[u8] = b"Value"; //
    pub const HISTORY: &[u8] = b"History";
    pub const CUSTOM_ICON_UUID: &[u8] = b"CustomIconUUID";

    // AutoKey related
    // Entry level
    pub const AUTO_TYPE: &[u8] = b"AutoType";
    pub const ENABLED: &[u8] = b"Enabled";
    // empty means use the inherited default one (from group)
    pub const DEFAULT_SEQUENCE: &[u8] = b"DefaultSequence";
    // multiple association possible for an entry
    pub const ASSOCIATION: &[u8] = b"Association";
    pub const WINDOW: &[u8] = b"Window";
    // KeystrokeSequence cab be empty empty. If so, use the entry's default sequence
    pub const KEY_STROKE_SEQUENCE: &[u8] = b"KeystrokeSequence";

    // <EnableAutoType>null</EnableAutoType> when 'Inherit from parent is diabled'
    // <EnableAutoType>true</EnableAutoType> when 'enable' is selected

    pub const ENABLE_AUTO_TYPE: &[u8] = b"EnableAutoType"; // Group level ?

    // <DefaultAutoTypeSequence/> when default parent's AutoTypeSequence is enabled
    // <DefaultAutoTypeSequence>{USERNAME}</DefaultAutoTypeSequence> when custom AutoTypeSequence is used
    pub const DEFAULT_AUTO_TYPE_SEQUENCE: &[u8] = b"DefaultAutoTypeSequence"; // Group level

    pub const DATA_TRANSFER_OBFUSCATION: &[u8] = b"DataTransferObfuscation"; // entry level - not used ?

    //pub const KEEPASS_FILE_TAGS:&[&[u8]] = &[META,ROOT];
}

pub mod key_file_xml_element {
    pub const KEY_FILE: &[u8] = b"KeyFile";
    pub const KEY_FILE_META: &[u8] = b"Meta";
    pub const KEY_FILE_VERSION: &[u8] = b"Version";
    pub const KEY_FILE_KEY: &[u8] = b"Key";
    pub const KEY_FILE_DATA: &[u8] = b"Data";
    pub const KEY_FILE_DATA_HASH: &[u8] = b"Hash";
}

#[allow(dead_code)]
pub mod uuid {
    // KeePassLib/Cryptography/KeyDerivation/Argon2Kdf.cs
    // KeePass2.cpp

    // Type Argon2d
    pub const ARGON2_D_KDF: &[u8] = &[
        0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A,
        0x0C,
    ];

    // Type // Argon2id
    pub const ARGON2_ID_KDF: &[u8] = &[
        0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1,
        0xE6,
    ];

    // This is supporeted in old KeePass format 3 and we are not supporting
    // pub const AES_KDF: &[u8] = &[
    //     0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60, 0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F,
    //     0xEA,
    // ];

    pub const CHACHA20: &[u8] = &[
        0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5, 0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5,
        0x9A,
    ];
    pub const AES256: &[u8] = &[
        0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50, 0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A,
        0xFF,
    ];
}

//Types used in VariantDictionary VdType
#[allow(dead_code)]
pub mod vd_type {
    pub const NONE: u8 = 0x00;
    pub const UINT32: u8 = 0x04;
    pub const UINT64: u8 = 0x05;
    pub const BOOL: u8 = 0x08;
    pub const INT32: u8 = 0x0C;
    pub const INT64: u8 = 0x0D;
    pub const STRING: u8 = 0x18;
    pub const BYTEARRAY: u8 = 0x42;
}

#[allow(dead_code)]
pub mod vd_param {
    pub const UUID: &str = "$UUID";

    pub mod argon2 {
        pub const SALT: &str = "S";
        pub const PARALLELISM: &str = "P";
        pub const MEMORY: &str = "M";
        pub const ITERATIONS: &str = "I";
        pub const VERSION: &str = "V";
        pub const SECRETKEY: &str = "K";
        pub const ASSOCDATA: &str = "A";

        pub const DEFAULT_ITERATIONS: &[u8] = &[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        pub const DEFAULT_PARALLELISM: &[u8] = &[0x02, 0x00, 0x00, 0x00];
        pub const DEFAULT_MEMORY: &[u8] = &[0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00];
    }

    pub mod aes {
        pub const ROUNDS: &str = "R";
        pub const SEED: &str = "S";

        pub const DEFAULT_ROUNDS: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    }
}

// All ids from enum KdbxHeaderFieldID of KeePassLib/Serialization/KdbxFile.cs and Only KDBX 4 ids are considered
#[allow(dead_code)]
pub mod header_type {
    pub const END_OF_HEADER: u8 = 0;
    pub const COMMENT: u8 = 1;
    pub const CIPHER_ID: u8 = 2;
    pub const COMPRESSION_FLAGS: u8 = 3;
    pub const MASTER_SEED: u8 = 4;
    pub const ENCRYPTION_IV: u8 = 7;
    pub const KDF_PARAMETERS: u8 = 11;
    pub const PUBLIC_CUSTOM_DATA: u8 = 12;
}

#[allow(dead_code)]
pub mod inner_header_type {
    pub const END_OF_HEADER: u8 = 0x00;
    pub const STREAM_ID: u8 = 0x01;
    pub const STREAM_KEY: u8 = 0x02;
    pub const BINARY: u8 = 0x03;

    pub const BINARY_PROTECTED: u8 = 0x01;
    pub const BINARY_PLAIN: u8 = 0x00;

    pub const SALSA20_STREAM: u32 = 2; //LE Bytes (2 0 0 0)
    pub const CHACHA20_STREAM: u32 = 3; //LE Bytes (3 0 0 0)
}

#[cfg(test)]
#[allow(dead_code)]
#[allow(unused)]
mod tests {

    #[ignore]
    #[test]
    fn generate_uuid() {
        let uid = uuid::Uuid::new_v4();
        println!("{}", crate::util::as_hex_array_formatted(uid.as_bytes()));
        println!("{}", uid.to_string());
    }

    #[ignore]
    #[test]
    fn generate_uuid_as_bytes() {
        let uuid_str = "7c02bb82-79a7-4ac0-927d-114a00648238";
        let uuid = uuid::Uuid::parse_str(&uuid_str).unwrap();
        println!("{}", crate::util::as_hex_array_formatted(uuid.as_bytes()));
    }
}
