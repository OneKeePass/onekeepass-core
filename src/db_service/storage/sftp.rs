use async_trait::async_trait;
use log::info;
use once_cell::sync::Lazy;
use russh::{
    client::{self, Handle},
    ChannelId,
};
use russh_keys::*;
use russh_sftp::client::SftpSession;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::{
    async_service::async_runtime,
    error::{self, Error, Result},
    parse_operation_fields_if, receive_from_async_fn, reply_by_async_fn,
    util::system_time_to_seconds,
};

pub use super::server_connection_config::SftpConnectionConfig;
use super::{
    calls::RemoteStorageOperation,
    server_connection_config::{
        ConnectionConfigs, RemoteStorageTypeConfig, RemoteStorageTypeConfigs,
    },
    string_tuple3, ConnectStatus, RemoteFileMetadata, RemoteReadData, RemoteStorageType,
    ServerDirEntry,
};

macro_rules! reply_by_sftp_async_fn {
    ($fn_name:ident ($($arg1:tt:$arg_type:ty),*),$call:tt ($($arg:expr),*),$channel_ret_val:ty) => {
        reply_by_async_fn!(sftp_connections_store,$fn_name ($($arg1:$arg_type),*),$call ($($arg),*),$channel_ret_val);
    };
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Sftp {
    connection_info: Option<SftpConnectionConfig>,
    connection_id: Option<String>,
    parent_dir: Option<String>,
    sub_dir: Option<String>,
    file_name: Option<String>,
}

impl RemoteStorageOperation for Sftp {
    fn connect_and_retrieve_root_dir(&self) -> Result<ConnectStatus> {
        #[allow(unused_parens)]
        let (connection_info) = parse_operation_fields_if!(self, connection_info);
        let c = connection_info.clone();

        receive_from_async_fn!(
            SftpConnection::send_connect_and_retrieve_root_dir(c),
            ConnectStatus
        )?
    }

    fn list_sub_dir(&self) -> Result<ServerDirEntry> {
        let (connection_id, parent_dir, sub_dir) =
            parse_operation_fields_if!(self, connection_id, parent_dir, sub_dir);
        let (cn, pd, sd) = string_tuple3(&[connection_id, parent_dir, sub_dir]);
        receive_from_async_fn!(
            SftpConnection::send_list_sub_dir(cn, pd, sd),
            ServerDirEntry
        )?
        //list_sub_dir(connection_id, parent_dir, sub_dir)
    }

    fn remote_storage_configs(&self) -> Result<RemoteStorageTypeConfigs> {
        Ok(ConnectionConfigs::remote_storage_configs(RemoteStorageType::Sftp))
    }

    fn update_config(&self) -> Result<()> {
        #[allow(unused_parens)]
        let (connection_info) = parse_operation_fields_if!(self, connection_info);
        ConnectionConfigs::update_config(RemoteStorageTypeConfig::Sftp(connection_info.clone()))
    }

    fn delete_config(&self) -> Result<()> {
        #[allow(unused_parens)]
        let (connection_info) = parse_operation_fields_if!(self, connection_info);
        ConnectionConfigs::delete_config(RemoteStorageTypeConfig::Sftp(connection_info.clone()))
    }
}

//  Exposed functions

//////////

struct Client;

// This macro is to make async fn in traits work with dyn traits
// See https://docs.rs/async-trait/latest/async_trait/
#[async_trait]
impl client::Handler for Client {
    type Error = Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        info!("check_server_key: {:?}", server_public_key);
        Ok(true)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        //info!("data on channel {:?}: {}", channel, data.len());
        Ok(())
    }
}

struct SftpConnection {
    connection_id: Uuid,
    client_handle: Handle<Client>,
}

type SftpConnections = Arc<tokio::sync::Mutex<HashMap<String, SftpConnection>>>;

fn sftp_connections_store() -> &'static SftpConnections {
    static SFTP_CONNECTIONS_STORE: Lazy<SftpConnections> = Lazy::new(Default::default);
    &SFTP_CONNECTIONS_STORE
}

impl SftpConnection {
    // Called when user creates the config first time or when user selects a previously
    // connected SFTP connection
    pub(crate) async fn connect_and_retrieve_root_dir(
        mut connection_info: SftpConnectionConfig,
    ) -> Result<ConnectStatus> {
        connection_info.connection_id =
            ConnectionConfigs::generate_config_id_on_check(connection_info.connection_id); // ConnectionConfigs::generate_config_id_on_check(connection_info);

        let start_dir = connection_info
            .start_dir
            .clone()
            .map_or_else(|| "/".to_string(), |s| s);

        let sftp_connection = Self::connect(&connection_info).await?;
        let dirs = sftp_connection.list_dir(&start_dir).await;

        let store_key = connection_info.connection_id.to_string(); // connection_info.connection_id.to_string();

        // Store it for future reference
        let mut connections = sftp_connections_store().lock().await;
        connections.insert(store_key, sftp_connection);

        let conn_status = ConnectStatus {
            connection_id: connection_info.connection_id,
            dir_entries: Some(dirs?),
        };

        // Need to add to the configs list
        ConnectionConfigs::add_config(RemoteStorageTypeConfig::Sftp(connection_info))?;

        Ok(conn_status)
    }

    async fn connect(connection_info: &SftpConnectionConfig) -> Result<SftpConnection> {
        let SftpConnectionConfig {
            connection_id,
            host,
            port,
            private_key_full_file_name,
            user_name,
            password,
            // Omits the remaining fields
            .. 
        } = connection_info;

        let config = russh::client::Config::default();
        let sh = Client {};
        let mut client_handle =
            russh::client::connect(Arc::new(config), (host.clone(), port.clone()), sh).await?;

        let session_authenticated = if let Some(p) = private_key_full_file_name {
            // Note load_secret_key calls the fn decode_secret_key(&secret, password)
            // where secret is a String that has the text of the private key
            let key = load_secret_key(p, password.as_ref().map(|x| x.as_str()))?;
            client_handle
                .authenticate_publickey(user_name, Arc::new(key))
                .await?
        } else if let Some(pwd) = password {
            client_handle.authenticate_password(user_name, pwd).await?
        } else {
            false
        };

        if session_authenticated {
            Ok(SftpConnection {
                connection_id: *connection_id,
                client_handle,
            })
        } else {
            Err(Error::SftpServerAuthenticationFailed)
        }
    }

    async fn list_dir(&self, parent_dir: &str) -> Result<ServerDirEntry> {
        // Should this be stored in 'SftpConnection' and reused?
        let sftp = self.create_sftp_session().await?;

        let dir_info = sftp.read_dir(parent_dir).await?;
        let mut sub_dirs: Vec<String> = vec![];
        let mut files: Vec<String> = vec![];
        for e in dir_info {
            if e.file_type().is_dir() {
                sub_dirs.push(e.file_name());
            } else {
                files.push(e.file_name());
            }
        }
        // Should this be called explicitly  or is it closed by RawSftpSession's drop
        // If we store in SftpConnection, we should not call close()
        sftp.close().await?;

        Ok(ServerDirEntry {
            parent_dir: parent_dir.into(),
            sub_dirs,
            files,
        })
    }

    async fn list_sub_dir(&self, parent_dir: &str, sub_dir: &str) -> Result<ServerDirEntry> {
        // Should this be stored in 'SftpConnection' and reused?
        let sftp = self.create_sftp_session().await?;

        // For now we use this simple join of root and sub dir using sep "/"
        let full_dir = [parent_dir, sub_dir].join("/");

        let dir_info = sftp.read_dir(&full_dir).await?;

        let mut sub_dirs: Vec<String> = vec![];
        let mut files: Vec<String> = vec![];

        for e in dir_info {
            if e.file_type().is_dir() {
                sub_dirs.push(e.file_name());
            } else {
                files.push(e.file_name());
            }
        }
        // Should this be called explicitly  or is it closed by RawSftpSession's drop
        // If we store in SftpConnection, we should not call close()
        sftp.close().await?;

        Ok(ServerDirEntry {
            parent_dir: full_dir.into(),
            sub_dirs,
            files,
        })
    }

    async fn create_sftp_session(&self) -> Result<SftpSession> {
        let channel = self.client_handle.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await?;
        Ok(sftp)
    }

    async fn read(&self, parent_dir: &str, file_name: &str) -> Result<RemoteReadData> {
        let sftp = self.create_sftp_session().await?;
        let full_path = [parent_dir, file_name].join("/");

        // Copies the full file content to memory
        let contents = sftp.read(&full_path).await?;
        let md = sftp.metadata(&full_path).await?; // Callling metadata makes another server call

        // Copied from sftp.read implementation so that we can get metadata from file instance
        // let mut file = sftp.open(&full_path).await?;
        // let mut contents = Vec::new();
        // tokio::io::AsyncReadExt::read_to_end(&mut file, &mut contents).await?;
        // let md = file.metadata().await?;

        let accessed = md
            .accessed()
            .map_or_else(|_| None, |t| Some(system_time_to_seconds(t)));
        let modified = md
            .modified()
            .map_or_else(|_| None, |t| Some(system_time_to_seconds(t)));

        let rmd = RemoteFileMetadata {
            connection_id: self.connection_id,
            storage_type: RemoteStorageType::Sftp,
            full_file_name: full_path,
            size: md.size,
            accessed,
            modified,
            created: None,
        };

        Ok(RemoteReadData {
            data: contents,
            meta: rmd,
        })
    }

    async fn metadata(&self, parent_dir: &str, file_name: &str) -> Result<RemoteFileMetadata> {
        let sftp = self.create_sftp_session().await?;
        let full_path = [parent_dir, file_name].join("/");
        let md = sftp.metadata(&full_path).await?; // Callling metadata makes another server call

        // Copied from sftp.read implementation so that we can get metadata from file instance
        // let mut file = sftp.open(&full_path).await?;
        // let mut contents = Vec::new();
        // tokio::io::AsyncReadExt::read_to_end(&mut file, &mut contents).await?;
        // let md = file.metadata().await?;

        let accessed = md
            .accessed()
            .map_or_else(|_| None, |t| Some(system_time_to_seconds(t)));
        let modified = md
            .modified()
            .map_or_else(|_| None, |t| Some(system_time_to_seconds(t)));

        let rmd = RemoteFileMetadata {
            connection_id: self.connection_id,
            storage_type: RemoteStorageType::Sftp,
            full_file_name: full_path,
            size: md.size,
            accessed,
            modified,
            created: None,
        };
        Ok(rmd)
    }

    // All instance level send_* calls
    // This async fns are called in a spawn fn and that receives a oneshot channel and sends back the result

    // Called to send the result of async call back to the sync call
    pub(crate) async fn send_connect_and_retrieve_root_dir(
        tx: oneshot::Sender<Result<ConnectStatus>>,
        connection_info: SftpConnectionConfig,
    ) {
        let dir_listing = SftpConnection::connect_and_retrieve_root_dir(connection_info).await;
        let r = tx.send(dir_listing);
        if let Err(_) = r {
            log::error!("In connect_and_retrieve_root_dir send channel failed ");
        }
    }

    // Creats a fn with signature
    // pub(crate) async fn send_list_sub_dir(tx: oneshot::Sender<Result<ServerDirEntry>>, connection_id: String, parent_dir: String, sub_dir: String)
    reply_by_sftp_async_fn!(send_list_sub_dir (parent_dir:String,sub_dir:String), list_sub_dir (&parent_dir,&sub_dir), ServerDirEntry);

    reply_by_sftp_async_fn!(send_read(parent_dir:String,file_name:String),read(&parent_dir,&file_name),RemoteReadData);

    reply_by_sftp_async_fn!(send_metadata (parent_dir:String,fiile_name:String), metadata (&parent_dir,&fiile_name), RemoteFileMetadata);
}

/*

pub fn connect_and_retrieve_root_dir(
    connection_info: SftpConnectionConfig,
) -> Result<ConnectStatus> {
    // IMPORTANT Remove this
    ConnectionConfigs::test_read_config();

    // The macro creates a block where we call async fn in a spawn thread and wait for the result
    // Return the result on receving
    receive_from_async_fn!(
        SftpConnection::send_connect_and_retrieve_root_dir(connection_info),
        ConnectStatus
    )?
}

pub fn list_sub_dir(
    connection_id: &str,
    parent_dir: &str,
    sub_dir: &str,
) -> Result<ServerDirEntry> {
    let (cn, pd, sd) = string_tuple3(&[connection_id, parent_dir, sub_dir]);
    receive_from_async_fn!(
        SftpConnection::send_list_sub_dir(cn, pd, sd),
        ServerDirEntry
    )?
}

pub fn read(connection_id: &str, parent_dir: &str, file_name: &str) -> Result<RemoteReadData> {
    let (cn, pd, file) = string_tuple3(&[connection_id, parent_dir, file_name]);
    receive_from_async_fn!(SftpConnection::send_read(cn, pd, file), RemoteReadData)?
}

pub fn metadata(
    connection_id: &str,
    parent_dir: &str,
    file_name: &str,
) -> Result<RemoteFileMetadata> {
    let (cn, pd, file) = string_tuple3(&[connection_id, parent_dir, file_name]);
    receive_from_async_fn!(
        SftpConnection::send_metadata(cn, pd, file),
        RemoteFileMetadata
    )?
}

pub fn write() {}
// let c = self
        //     .connection_info
        //     .as_ref()
        //     .ok_or("connection_info cannot be nil")?
        //     .clone();

// let (Some(connection_id), Some(parent_dir), Some(sub_dir)) = (
        //     self.connection_id.as_ref(),
        //     self.parent_dir.as_ref(),
        //     self.sub_dir.as_ref(),
        // ) else {
        //     return Err(error::Error::DataError("Required fields are not found"));
        // };
macro_rules! parse_operation_fields {
    ($self:expr,$($field_vals:tt)*) => {
        let ( $(Some($field_vals)),* ) = ($($self.$field_vals.as_ref()),*) else {
            return Err(error::Error::DataError("Required fields are not found"))
        };
        Ok(($($field_vals)*,))

    };
}

*/
