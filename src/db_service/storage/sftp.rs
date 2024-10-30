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
};

pub use super::server_connection_config::SftpConnectionConfig;
use super::ServerDirEntry;

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

pub fn connect_to_server(connection_info: SftpConnectionConfig) -> Result<ServerDirEntry> {
    let (tx, rx) = oneshot::channel::<Result<ServerDirEntry>>();
    async_runtime().spawn(SftpConnection::send_connect_to_server(tx, connection_info));

    let s = rx.blocking_recv().map_err(|e| {
        error::Error::UnexpectedError(format!("In connect_to_server receive channel error {}", e))
    })?;

    s
}

pub fn list_dir(connetion_name: &str, parent_dir: &str) -> Result<ServerDirEntry> {
    let (cn, pd) = (connetion_name.to_string(), parent_dir.to_string());
    let (tx, rx) = oneshot::channel::<Result<ServerDirEntry>>();
    async_runtime().spawn(SftpConnection::send_list_dir(tx, cn, pd));
    rx.blocking_recv().map_err(|e| {
        error::Error::UnexpectedError(format!("In list_dir receive channel error {}", e))
    })?
}

pub fn open() {}

pub fn write() {}

impl SftpConnection {

    pub(crate) async fn connect_to_server(
        connection_info: SftpConnectionConfig,
    ) -> Result<ServerDirEntry> {
        let name = connection_info.name.clone();
        let start_dir = connection_info.start_dir.clone().map_or_else(|| "/".to_string(), |s| s );

        let sftp_connection = Self::connect(connection_info).await?;
        let dirs = sftp_connection.list_dir(&start_dir).await;

        // Store it for future reference
        let mut connections = sftp_connections_store().lock().await;
        connections.insert(name, sftp_connection );

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
            // // Store the connection to sftp server for future use
            // let mut connections = sftp_connections_store().lock().await;
            // connections.insert(name, SftpConnection { client_handle });
            Ok(SftpConnection { client_handle })
        } else {
            Err(Error::SftpServerAuthenticationFailed)
        }
    }

    async fn list_dir(&self,parent_dir: &str) -> Result<ServerDirEntry> {

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

    async fn create_sftp_session(&self) -> Result<SftpSession> {
        let channel = self.client_handle.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await?;
        Ok(sftp)
    }

    pub(crate) async fn send_connect_to_server(tx: oneshot::Sender<Result<ServerDirEntry>>,connection_info: SftpConnectionConfig) {
       
        let dir_listing = SftpConnection::connect_to_server(connection_info).await;
        let r = tx.send(dir_listing);
        if let Err(_) = r {
            log::error!("In connect_to_server send channel failed ");
        }
    }

    pub(crate) async fn send_list_dir(
        tx: oneshot::Sender<Result<ServerDirEntry>>,
        connetion_name: String,
        parent_dir: String,
    ) {
        let connections = sftp_connections_store().lock().await;

        let r = if let Some(conn) = connections.get(&connetion_name) {
            conn.list_dir( &parent_dir).await
        } else {
            Err(error::Error::UnexpectedError(format!(
                "No previous connected sftp session is found for the name {}",
                &connetion_name
            )))
        };

        let r = tx.send(r);
        if let Err(_) = r {
            // Should not happen? But may happen if no receiver?
            log::error!("The 'send_list_dir' fn send channel call failed ");
        }
    }
}

mod async_calls {
    use std::sync::Arc;

    use russh::client::Handle;
    use russh_keys::*;
    use russh_sftp::client::SftpSession;
    use tokio::sync::oneshot;

    use super::{sftp_connections_store, Client, ServerDirEntry, SftpConnection};
    use crate::db_service::storage::server_connection_config::SftpConnectionConfig;
    use crate::error::{self, Error, Result};

    // Callled to get the dir content listing using the previously opened sftp connetion
    // The dir list result is sent to the calleer in the sender side of a channel
    pub(crate) async fn send_list_dir(
        tx: oneshot::Sender<Result<ServerDirEntry>>,
        connetion_name: String,
        parent_dir: String,
    ) {
        let connections = sftp_connections_store().lock().await;

        let r = if let Some(conn) = connections.get(&connetion_name) {
            list_dir(&conn.client_handle, &parent_dir).await
        } else {
            Err(error::Error::UnexpectedError(format!(
                "No previous connected sftp session is found for the name {}",
                &connetion_name
            )))
        };

        let r = tx.send(r);
        if let Err(_) = r {
            // Should not happen? But may happen if no receiver?
            log::error!("The 'send_list_dir' fn send channel call failed ");
        }
    }

    pub(crate) async fn connect_to_server(
        connection_info: SftpConnectionConfig,
    ) -> Result<ServerDirEntry> {
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
            let r = list_dir(
                &client_handle,
                start_dir.as_ref().map_or_else(|| "/", |s| s.as_str()),
            )
            .await?;
            // Store the connection to sftp server for future use
            let mut connections = sftp_connections_store().lock().await;
            connections.insert(name, SftpConnection { client_handle });
            Ok(r)
        } else {
            Err(Error::SftpServerAuthenticationFailed)
        }
    }

    async fn create_sftp_session(client_handle: &Handle<Client>) -> Result<SftpSession> {
        let channel = client_handle.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await?;
        Ok(sftp)
    }

    pub(crate) async fn list_dir(
        client_handle: &Handle<Client>,
        parent_dir: &str,
    ) -> Result<ServerDirEntry> {
        // let channel = session.channel_open_session().await?;
        // channel.request_subsystem(true, "sftp").await?;
        // let sftp = SftpSession::new(channel.into_stream()).await?;

        // //let root_dir = sftp.canonicalize(".").await?;
        // //info!("current path: {:?}", root_dir);

        // Should this be stored in 'SftpConnection' and reused?
        let sftp = create_sftp_session(client_handle).await?;

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
        sftp.close().await?;

        Ok(ServerDirEntry {
            parent_dir: parent_dir.into(),
            sub_dirs,
            files,
        })
    }
}

///////////

/*

pub mod sync {
    use tokio::sync::oneshot;

    use super::ServerDirEntry;
    use crate::async_service::async_runtime;
    use crate::db_service::storage::server_connection_config::SftpConnectionConfig;
    use crate::error::{self, Result};

    pub fn connect_to_server(connection_info: SftpConnectionConfig) -> Result<ServerDirEntry> {
        let (tx, rx) = oneshot::channel::<Result<ServerDirEntry>>();

        async_runtime().spawn(async move {
            let r = super::async_calls::connect_to_server(connection_info).await;
            let r = tx.send(r);
            if let Err(_) = r {
                log::error!("Send channel failed ");
            }
            r
        });

        let s = rx
            .blocking_recv()
            .map_err(|e| error::Error::UnexpectedError(format!("Receive channel error {}", e)))?;

        s
    }
}


*/

/*
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConnectionInfo {
    // user selected name for this connection
    pub name: String,
    pub host: String,
    pub port: u16,
    // required for authenticate_publickey when we use private key
    pub private_key_path: Option<String>,
    pub user_name: String,
    // required for authenticate_password when we use password
    pub password: Option<String>,
}


pub async fn connect_and_retrieve_root_dir(
    connection_info: ConnectionInfo,
) -> Result<ServerDirEntry> {
    let name = connection_info.name.clone();
    let connection = connect_to_server(connection_info).await?;
    let home_dir_info = list_dir(&connection, "/").await?;

    // Store the connection to sftp server for future use
    let mut connections = sftp_connections_store().lock().unwrap();
    connections.insert(
        name,
        SftpConnection {
            session: connection,
        },
    );

    Ok(home_dir_info)
}

async fn connect_to_server(connection_info: ConnectionInfo) -> Result<Handle<Client>> {
    let ConnectionInfo {
        name: _,
        host,
        port,
        private_key_path,
        user_name,
        password,
    } = connection_info;

    let config = russh::client::Config::default();
    let sh = Client {};
    let mut session = russh::client::connect(Arc::new(config), (host.to_owned(), port), sh).await?;

    let session_authenticated = if let Some(p) = private_key_path {
        // Note load_secret_key calls the fn decode_secret_key(&secret, password)
        // where secret is a String that has the text of the private key
        let key = load_secret_key(p, None)?;
        session
            .authenticate_publickey(user_name, Arc::new(key))
            .await?
    } else if let Some(pwd) = password {
        session.authenticate_password(user_name, pwd).await?
    } else {
        false
    };

    if session_authenticated {
        Ok(session)
    } else {
        Err(Error::SftpServerAuthenticationFailed)
    }
}

async fn list_dir(session: &Handle<Client>, parent_dir: &str) -> Result<ServerDirEntry> {
    let channel = session.channel_open_session().await?;
    channel.request_subsystem(true, "sftp").await?;
    let sftp = SftpSession::new(channel.into_stream()).await?;
    //let root_dir = sftp.canonicalize(".").await?;
    //info!("current path: {:?}", root_dir);

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

    Ok(ServerDirEntry {
        parent_dir: parent_dir.into(),
        sub_dirs,
        files,
    })
}

pub mod sync {
    use tokio::sync::oneshot;

    use super::{ConnectionInfo, ServerDirEntry};
    use crate::async_service::async_runtime;
    use crate::error::{self, Error, Result};

    pub fn connect_and_retrieve_root_dir(
        connection_info: &ConnectionInfo,
    ) -> Result<ServerDirEntry> {
        let c = connection_info.clone();

        let (tx, rx) = oneshot::channel::<Result<ServerDirEntry>>();
        //let r:tokio::task::JoinHandle<_> = async_runtime().spawn
        async_runtime().spawn(async move {
            let r = super::connect_and_retrieve_root_dir(c).await;
            let r = tx.send(r);
            if let Err(_) = r {
                log::error!("Send channel failed ");
            }
            r
        });

        let s = rx
            .blocking_recv()
            .map_err(|e| error::Error::UnexpectedError(format!("Receive channel error {}", e)))?;

        s
    }
}




pub fn connect_to_server(connection_info: SftpConnectionConfig) -> Result<ServerDirEntry> {
    let (tx, rx) = oneshot::channel::<Result<ServerDirEntry>>();

    // async_runtime().spawn(async move {
    //     let r = async_calls::connect_to_server(connection_info).await;
    //     let r = tx.send(r);
    //     if let Err(_) = r {
    //         log::error!("Send channel failed ");
    //     }
    //     r
    // });

    async_runtime().spawn(async move {
        let dir_listing = SftpConnection::connect_to_server(connection_info).await;
        let r = tx.send(dir_listing);
        if let Err(_) = r {
            log::error!("In connect_to_server send channel failed ");
        }
    });

    let s = rx.blocking_recv().map_err(|e| {
        error::Error::UnexpectedError(format!("In connect_to_server receive channel error {}", e))
    })?;

    s
}

pub fn list_dir(connetion_name: &str, parent_dir: &str) -> Result<ServerDirEntry> {
    let (cn, pd) = (connetion_name.to_string(), parent_dir.to_string());
    let (tx, rx) = oneshot::channel::<Result<ServerDirEntry>>();

    //async_runtime().spawn(async_calls::send_list_dir(tx, cn, pd));

    async_runtime().spawn(SftpConnection::send_list_dir(tx, cn, pd));
    rx.blocking_recv().map_err(|e| {
        error::Error::UnexpectedError(format!("In list_dir receive channel error {}", e))
    })?
}

*/
