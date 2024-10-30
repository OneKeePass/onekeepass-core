use std::{collections::HashMap, sync::Arc};

use log::info;
use once_cell::sync::Lazy;
use reqwest_dav::{
    list_cmd::ListEntity, Auth, Client, ClientBuilder, Depth,
};
use tokio::sync::oneshot;

use crate::{async_service::async_runtime, error::{self, Result}};

pub use super::server_connection_config::WebdavConnectionConfig;
use super::ServerDirEntry;

struct WebdavConnection {
    client: Client,
}

type WebdavConnections = Arc<tokio::sync::Mutex<HashMap<String, WebdavConnection>>>;

fn webdav_connections_store() -> &'static WebdavConnections {
    static WEBDAV_CONNECTIONS_STORE: Lazy<WebdavConnections> = Lazy::new(Default::default);
    &WEBDAV_CONNECTIONS_STORE
}

pub fn connect_to_server(connection_info: WebdavConnectionConfig) -> Result<ServerDirEntry> {
    let (tx, rx) = oneshot::channel::<Result<ServerDirEntry>>();
    async_runtime().spawn(WebdavConnection::send_connect_to_server(tx, connection_info));

    let s = rx.blocking_recv().map_err(|e| {
        error::Error::UnexpectedError(format!("In connect_to_server receive channel error {}", e))
    })?;

    s
}

pub fn list_dir(connetion_name: &str, parent_dir: &str) -> Result<ServerDirEntry> {
    let (cn, pd) = (connetion_name.to_string(), parent_dir.to_string());
    let (tx, rx) = oneshot::channel::<Result<ServerDirEntry>>();
    async_runtime().spawn(WebdavConnection::send_list_dir(tx, cn, pd));
    rx.blocking_recv().map_err(|e| {
        error::Error::UnexpectedError(format!("In list_dir receive channel error {}", e))
    })?
}



impl WebdavConnection {
    pub(crate) async fn connect_to_server(connection_info: WebdavConnectionConfig) -> Result<ServerDirEntry> {
        let agent = reqwest_dav::re_exports::reqwest::ClientBuilder::new()
            .danger_accept_invalid_certs(connection_info.allow_untrusted_cert)
            .build()?;

        info!("Agent is created...");

        // build a client
        let client = ClientBuilder::new()
            .set_agent(agent)
            .set_host(connection_info.root_url)
            .set_auth(Auth::Basic(connection_info.user_name, connection_info.password))
            .build()?;

        info!("Client is created...{:?}", &client);
        let webdav_connection = WebdavConnection{client};

        let dirs = webdav_connection.list_dir(".").await?;

        // Store it for future reference
        let mut connections = webdav_connections_store().lock().await;
        info!("Inserting webdav connection for {}",&connection_info.name);
        connections.insert(connection_info.name, webdav_connection);

        Ok(dirs)
    }

    // Caller needs to pass the relative path as parent_dir 
    // e.g "." "/dav" "/dav/databases" etc and these parent dir should exists. Oterwiese an error with 404 code raised
    async fn list_dir(&self,parent_dir: &str) -> Result<ServerDirEntry> {
        let dir_info = self.client.list(parent_dir, Depth::Number(1)).await?;

        let mut sub_dirs: Vec<String> = vec![];
        let mut files: Vec<String> = vec![];
        for e in dir_info {
            match e {
                ListEntity::File(f) => {
                    info!("List entry is a file and meta is {:?} ",f);
                    let n = f.href.split_once("/").map_or_else(|| ".", |v| v.1);
                    files.push(n.to_string());
                },
                ListEntity::Folder(f) => {
                    info!("List entry is a folder and meta is {:?} ",f);
                    let n = f.href.split_once("/").map_or_else(|| ".", |v| v.1);
                    sub_dirs.push(n.to_string());
                },
            }
        }

        Ok(ServerDirEntry {
            parent_dir: parent_dir.into(),
            sub_dirs,
            files,
        })
    }

    async fn send_connect_to_server(tx: oneshot::Sender<Result<ServerDirEntry>>,connection_info: WebdavConnectionConfig) {
       
        let dir_listing = WebdavConnection::connect_to_server(connection_info).await;
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
        let connections = webdav_connections_store().lock().await;

        let r = if let Some(conn) = connections.get(&connetion_name) {
            conn.list_dir( &parent_dir).await
        } else {
            Err(error::Error::UnexpectedError(format!(
                "No previous connected webdav session is found for the name {}",
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
