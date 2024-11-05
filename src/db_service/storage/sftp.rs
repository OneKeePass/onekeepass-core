use async_trait::async_trait;
use log::info;
use once_cell::sync::Lazy;
use russh::{
    client::{self, Handle},
    ChannelId,
};
use russh_keys::*;
use russh_sftp::client::SftpSession;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::oneshot;

use crate::{
    async_service::async_runtime,
    error::{self, Error, Result},
    receive_from_async_fn, reply_by_async_fn, util::system_time_to_seconds,
};

pub use super::server_connection_config::SftpConnectionConfig;
use super::{
    string_tuple3, RemoteFileMetadata, RemoteReadData, RemoteStorageType,
    ServerDirEntry,
};

macro_rules! reply_by_sftp_async_fn {
    ($fn_name:ident ($($arg1:tt:$arg_type:ty),*),$call:tt ($($arg:expr),*),$channel_ret_val:ty) => {
        reply_by_async_fn!(sftp_connections_store,$fn_name ($($arg1:$arg_type),*),$call ($($arg),*),$channel_ret_val);
    };
}

/////// exposed functions

pub fn connect_to_server(connection_info: SftpConnectionConfig) -> Result<ServerDirEntry> {
    receive_from_async_fn!(
        SftpConnection::send_connect_to_server(connection_info),
        ServerDirEntry
    )?
}

pub fn list_sub_dir(
    connection_name: &str,
    parent_dir: &str,
    sub_dir: &str,
) -> Result<ServerDirEntry> {
    let (cn, pd, sd) = string_tuple3(&[connection_name, parent_dir, sub_dir]);
    receive_from_async_fn!(
        SftpConnection::send_list_sub_dir(cn, pd, sd),
        ServerDirEntry
    )?
}

pub fn read(connection_name: &str, parent_dir: &str, file_name: &str) -> Result<RemoteReadData> {
    let (cn, pd, file) = string_tuple3(&[connection_name, parent_dir, file_name]);
    receive_from_async_fn!(SftpConnection::send_read(cn, pd, file), RemoteReadData)?
}

pub fn metadata(
    connection_name: &str,
    parent_dir: &str,
    file_name: &str,
) -> Result<RemoteFileMetadata> {
    let (cn, pd, file) = string_tuple3(&[connection_name, parent_dir, file_name]);
    receive_from_async_fn!(
        SftpConnection::send_metadata(cn, pd, file),
        RemoteFileMetadata
    )?
}

pub fn write() {}

//////////

struct Client;

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
    client_handle: Handle<Client>,
}

type SftpConnections = Arc<tokio::sync::Mutex<HashMap<String, SftpConnection>>>;

fn sftp_connections_store() -> &'static SftpConnections {
    static SFTP_CONNECTIONS_STORE: Lazy<SftpConnections> = Lazy::new(Default::default);
    &SFTP_CONNECTIONS_STORE
}

impl SftpConnection {
    pub(crate) async fn connect_to_server(
        connection_info: SftpConnectionConfig,
    ) -> Result<ServerDirEntry> {
        let name = connection_info.name.clone();
        let start_dir = connection_info
            .start_dir
            .clone()
            .map_or_else(|| "/".to_string(), |s| s);

        let sftp_connection = Self::connect(connection_info).await?;
        let dirs = sftp_connection.list_dir(&start_dir).await;

        // Store it for future reference
        let mut connections = sftp_connections_store().lock().await;
        connections.insert(name, sftp_connection);

        dirs
    }

    async fn connect(connection_info: SftpConnectionConfig) -> Result<SftpConnection> {
        let SftpConnectionConfig {
            name,
            host,
            port,
            private_key,
            user_name,
            password,
            start_dir,
        } = connection_info;

        let config = russh::client::Config::default();
        let sh = Client {};
        let mut client_handle =
            russh::client::connect(Arc::new(config), (host.to_owned(), port), sh).await?;

        let session_authenticated = if let Some(p) = private_key {
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
            Ok(SftpConnection { client_handle })
        } else {
            Err(Error::SftpServerAuthenticationFailed)
        }
    }

    // Called to send the result of async call back to the sync call
    pub(crate) async fn send_connect_to_server(
        tx: oneshot::Sender<Result<ServerDirEntry>>,
        connection_info: SftpConnectionConfig,
    ) {
        let dir_listing = SftpConnection::connect_to_server(connection_info).await;
        let r = tx.send(dir_listing);
        if let Err(_) = r {
            log::error!("In connect_to_server send channel failed ");
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
            storage_type: RemoteStorageType::Sftp,
            full_file_name: full_path,
            size: md.size,
            accessed,
            modified,
            created: None,
        };
        Ok(rmd)
    }

    ////  All instance level send_* calls

    // Creats a fn with signature
    // pub(crate) async fn send_list_sub_dir(tx: oneshot::Sender<Result<ServerDirEntry>>, connection_name: String, parent_dir: String, sub_dir: String)
    reply_by_sftp_async_fn!(send_list_sub_dir (parent_dir:String,sub_dir:String), list_sub_dir (&parent_dir,&sub_dir), ServerDirEntry);

    reply_by_sftp_async_fn!(send_read(parent_dir:String,file_name:String),read(&parent_dir,&file_name),RemoteReadData);

    reply_by_sftp_async_fn!(send_metadata (parent_dir:String,fiile_name:String), metadata (&parent_dir,&fiile_name), RemoteFileMetadata);
}
