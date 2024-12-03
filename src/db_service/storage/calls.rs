use serde::{Deserialize, Serialize};

use super::{
    server_connection_config::{RemoteStorageTypeConfig, RemoteStorageTypeConfigs}, sftp::Sftp, webdav::Webdav, ConnectStatus, ServerDirEntry
};
use crate::error::Result;

// See https://crates.io/crates/enum_dispatch
// Here we use enum_dispatch macros to generate Enum based trait fn call which in  dispatches to the implementing struct

// Also see https://crates.io/crates/enum_delegate for similar functionalities

#[enum_dispatch::enum_dispatch(RemoteStorageOperationType)]
pub trait RemoteStorageOperation {
    // requires connection_info
    fn connect_and_retrieve_root_dir(&self) -> Result<ConnectStatus>;
    // requires connect_id
    fn connect_by_id_and_retrieve_root_dir(&self) -> Result<ConnectStatus>;
    // requires connect_id
    fn connect_by_id(&self) -> Result<RemoteStorageTypeConfig>;
    // requires connect_id, parent dir and used mainly to list content of root dir
    fn list_dir(&self) -> Result<ServerDirEntry>;     
    // requires connect_id, parent dir and sub dir
    fn list_sub_dir(&self) -> Result<ServerDirEntry>; 
    fn remote_storage_configs(&self) -> Result<RemoteStorageTypeConfigs>;
    fn update_config(&self,) -> Result<()>;
    fn delete_config(&self,) -> Result<()>;
}

// Sftp inside the enum variant 'Sftp(Sftp)' is the struct that implements the trait 'RemoteStorageOperation'

// Json string r#"{ "type":"Sftp", "connection_info":{"connection-id":"00000000-0000-0000-0000-000000000000", :name "somename", :host "host"... }}"#
// is converted to the enum variant Sftp(Sftp)

// When the trait fn is called on that enum variant, the call is dispatched to the underlying struct 'Sftp'
// See db-service::commands::Commands where the json str coming from UI layer is deserilaized to the enum variant 
// and then the relevant trait fn is called 

// e.g let e: RemoteStorageOperationType = serde_json::from_str(&s).unwrap();
//         e.connect_and_retrieve_root_dir()


#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")] 
#[enum_dispatch::enum_dispatch]
pub enum RemoteStorageOperationType {
    Sftp(Sftp),
    Webdav(Webdav),
}


// Another way of converting the struct to the enum variant and call the trait fn
// Example of converting the 'Sftp' to enum 
// let sftp = Sftp {.....};
// let e: RemoteStorageOperationType = sftp.into();
// e.connect_and_retrieve_root_dir()


