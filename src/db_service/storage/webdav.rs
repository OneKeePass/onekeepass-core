use std::{collections::HashMap, sync::Arc};

use log::{debug, info};
use once_cell::sync::Lazy;
use reqwest_dav::{list_cmd::ListEntity, Auth, Client, ClientBuilder, Depth};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use url::Url;
use uuid::Uuid;

use crate::{
    async_service::async_runtime,
    db_service::{callback_service::CallbackServiceProvider, storage::ConnectStatus},
    error::{self, Error, Result},
    parse_operation_fields_if, receive_from_async_fn, reply_by_async_fn,
};

pub use super::server_connection_config::WebdavConnectionConfig;
use super::{
    calls::RemoteStorageOperation, filter_entry, server_connection_config::{
        ConnectionConfigs, RemoteStorageTypeConfig, RemoteStorageTypeConfigs,
    }, string_tuple3, RemoteFileMetadata, RemoteReadData, RemoteStorageType, ServerDirEntry
};

macro_rules! reply_by_webdav_async_fn {
    ($fn_name:ident ($($arg1:tt:$arg_type:ty),*),$call:tt ($($arg:expr),*), $send_val:ty) => {
        reply_by_async_fn!(webdav_connections_store,$fn_name ($($arg1:$arg_type),*),$call ($($arg),*),$send_val);
    };
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Webdav {
    connection_info: Option<WebdavConnectionConfig>,
    connection_id: Option<String>,
    parent_dir: Option<String>,
    sub_dir: Option<String>,
    file_name: Option<String>,
}

impl RemoteStorageOperation for Webdav {
    fn connect_and_retrieve_root_dir(&self) -> Result<ConnectStatus> {
        #[allow(unused_parens)]
        let (connection_info) = parse_operation_fields_if!(self, connection_info);
        let c = connection_info.clone();
        receive_from_async_fn!(
            WebdavConnection::send_connect_and_retrieve_root_dir(c),
            ConnectStatus
        )?
    }

    fn connect_by_id_and_retrieve_root_dir(&self) -> Result<ConnectStatus> {
        #[allow(unused_parens)]
        let (connection_id) = parse_operation_fields_if!(self, connection_id);

        let c_id = connection_id.clone();

        // Call the async fn in a 'spawn' and wait for the result - Result<Result<RemoteStorageTypeConfig>>)
        receive_from_async_fn!(
            WebdavConnection::send_connect_by_id_and_retrieve_root_dir(c_id),
            ConnectStatus
        )?
    }

    fn connect_by_id(&self) -> Result<RemoteStorageTypeConfig> {
        #[allow(unused_parens)]
        let (connection_id) = parse_operation_fields_if!(self, connection_id);

        let c_id = connection_id.clone();

        // Call the async fn in a 'spawn' and wait for the result - Result<Result<RemoteStorageTypeConfig>>)
        let rc = receive_from_async_fn!(
            WebdavConnection::send_connect_by_id(c_id),
            RemoteStorageTypeConfig
        )?;

        rc
    }

    fn list_sub_dir(&self) -> Result<ServerDirEntry> {
        let (connection_id, parent_dir, sub_dir) =
            parse_operation_fields_if!(self, connection_id, parent_dir, sub_dir);

        let (cn, pd, sd) = string_tuple3(&[connection_id, parent_dir, sub_dir]);
        receive_from_async_fn!(
            WebdavConnection::send_list_sub_dir(cn, pd, sd),
            ServerDirEntry
        )?
    }

    fn remote_storage_configs(&self) -> Result<RemoteStorageTypeConfigs> {
        Ok(ConnectionConfigs::remote_storage_configs(
            RemoteStorageType::Webdav,
        ))
    }

    fn update_config(&self) -> Result<()> {
        #[allow(unused_parens)]
        let (connection_info) = parse_operation_fields_if!(self, connection_info);
        ConnectionConfigs::update_config(RemoteStorageTypeConfig::Webdav(connection_info.clone()))
    }

    fn delete_config(&self) -> Result<()> {
        #[allow(unused_parens)]
        let (connection_id) = parse_operation_fields_if!(self, connection_id);

        let u_id = uuid::Uuid::parse_str(connection_id)?;
        let r = ConnectionConfigs::delete_config_by_id(RemoteStorageType::Webdav, &u_id);
        CallbackServiceProvider::common_callback_service()
            .remote_storage_config_deleted(RemoteStorageType::Webdav, connection_id)?;

        r
    }

    // fn connect_by_id(&self) -> Result<RemoteStorageTypeConfig> {
    //     todo!()
    // }

    fn list_dir(&self) -> Result<ServerDirEntry> {
        todo!()
    }
}

struct WebdavConnection {
    client: Client,
}

type WebdavConnections = Arc<tokio::sync::Mutex<HashMap<String, WebdavConnection>>>;

fn webdav_connections_store() -> &'static WebdavConnections {
    static WEBDAV_CONNECTIONS_STORE: Lazy<WebdavConnections> = Lazy::new(Default::default);
    &WEBDAV_CONNECTIONS_STORE
}

pub fn connect_and_retrieve_root_dir(
    connection_info: WebdavConnectionConfig,
) -> Result<ConnectStatus> {
    receive_from_async_fn!(
        WebdavConnection::send_connect_and_retrieve_root_dir(connection_info),
        ConnectStatus
    )?
}

const WEBDAV_ROOT_DIR: &str = "/";

impl WebdavConnection {
    pub(crate) async fn connect_and_retrieve_root_dir(
        mut connection_info: WebdavConnectionConfig,
    ) -> Result<ConnectStatus> {
        connection_info.connection_id =
            ConnectionConfigs::generate_config_id_on_check(connection_info.connection_id);

        let webdav_connection = Self::connect(&connection_info).await?;

        let dirs = webdav_connection.list_dir(WEBDAV_ROOT_DIR).await?;

        let store_key = connection_info.connection_id.to_string();

        // Store it for future reference
        let mut connections = webdav_connections_store().lock().await;
        connections.insert(store_key, webdav_connection);

        let conn_status = ConnectStatus {
            connection_id: connection_info.connection_id,
            dir_entries: Some(dirs),
        };

        // Need to add to the configs list
        // TODO: Need to update if the existing config is changed
        ConnectionConfigs::add_config(RemoteStorageTypeConfig::Webdav(connection_info))?;

        Ok(conn_status)
    }

    // Called to create a new remote connection using the connection id and on successful connection
    // the root dir entries are returned
    async fn connect_by_id_and_retrieve_root_dir(connection_id: &str) -> Result<ConnectStatus> {
        // Makes connection to the remote storage and stores the connection in the local static map
        // Note webdav_connections_store().lock() called in this call
        let _r = Self::connect_by_id(connection_id).await?;

        // Previous lock call should have been unlocked by this time. Otherwise deadlock will happen
        let connections = webdav_connections_store().lock().await;

        // A successful connection should be available
        let webdav_connection = connections.get(connection_id).ok_or_else(|| {
            Error::DataError(
                "Previously saved WebDav Connection config is not found in configs for this id",
            )
        })?;

        let dirs = webdav_connection.list_dir(WEBDAV_ROOT_DIR).await?;

        let u_id = uuid::Uuid::parse_str(connection_id)?;
        let conn_status = ConnectStatus {
            connection_id: u_id,
            dir_entries: Some(dirs),
        };

        Ok(conn_status)
    }

    // Gets the connection config with this id and use that to connect the Webdav server if required  and stores
    // that connection for the future use
    async fn connect_by_id(connection_id: &str) -> Result<RemoteStorageTypeConfig> {
        let mut connections = webdav_connections_store().lock().await;

        let u_id = uuid::Uuid::parse_str(connection_id)?;

        let rc = ConnectionConfigs::find_remote_storage_config(&u_id, RemoteStorageType::Webdav)
            .ok_or_else(|| {
                Error::DataError(
                    "Previously saved WebDav Connection config is not found in configs for this id",
                )
            })?;

        if let Some(_c) = connections.get(connection_id) {
            return Ok(rc);
        }

        debug!("Previous connection is not available and will make new connection");

        let RemoteStorageTypeConfig::Webdav(ref connection_info) = rc else {
            // Should not happen
            return Err(Error::DataError(
                "Webdav Connection config is expected and not returned from configs",
            ));
        };

        let webdav_connection = Self::connect(connection_info).await?;

        // Store it for future reference
        connections.insert(connection_id.to_string(), webdav_connection);

        debug!("Created connection is stored in memory");

        Ok(rc)
    }

    async fn connect(connection_info: &WebdavConnectionConfig) -> Result<WebdavConnection> {
        let agent = reqwest_dav::re_exports::reqwest::ClientBuilder::new()
            .danger_accept_invalid_certs(connection_info.allow_untrusted_cert)
            .build()?;

        info!("Agent is created...");

        // build a client
        let client = ClientBuilder::new()
            .set_agent(agent)
            .set_host(connection_info.root_url.clone())
            .set_auth(Auth::Basic(
                connection_info.user_name.clone(),
                connection_info.password.clone(),
            ))
            .build()?;

        info!("Client is created...{:?}", &client);
        let webdav_connection = WebdavConnection { client };

        debug!("Listing root dir content to verify the client config info");

        let _dir_info = webdav_connection.client.list(".", Depth::Number(0)).await?;

        debug!("Connection verification is done");

        Ok(webdav_connection)
    }

    // Caller needs to pass the relative path as parent_dir
    // e.g "." "/dav" "/dav/databases" etc and these parent dir should exists. Oterwiese an error with 404 code raised
    async fn list_dir(&self, parent_dir: &str) -> Result<ServerDirEntry> {

        // A vec of all parts of this parent dir path
        // e.g "dav/db1" -> ["dav" "db1"]
        let paren_dir_parts = parent_dir
            .split("/")
            .filter(|s| filter_entry(s))
            .collect::<Vec<_>>();

        let dir_info = self.client.list(parent_dir, Depth::Number(1)).await?;

        let mut sub_dirs: Vec<String> = vec![];
        let mut files: Vec<String> = vec![];

        for e in dir_info {
            match e {
                ListEntity::File(list_file) => {
                    // info!("List entry is a file and meta is {:?} ", f);
                    // let n = f.href.split_once("/").map_or_else(|| ".", |v| v.1);
                    // files.push(n.to_string());

                    // Need to remove empty "" and mac OS specific dot files
                    let list_file_parts = &list_file
                        .href
                        .split("/")
                        .filter(|s| filter_entry(s))
                        .collect::<Vec<_>>();

                    // There is folder entry corresponding to the passed  'parent_dir' 
                    // when dot files are excluded and we need to exclude that
                    // e.g "dav/db1/.DS_Store"  ["dav" "db1" ".DS_Store"] -> after filtering ["dav" "db1"]
                    // and this needs to be excluded 

                    if !(&paren_dir_parts == list_file_parts) {
                        if let Some(last_comp) = list_file_parts.last() {
                            files.push(last_comp.to_string());
                        }
                    }
                }
                ListEntity::Folder(list_file) => {
                    // info!("List entry is a folder and meta is {:?} ", f);
                    // let n = f.href.split_once("/").map_or_else(|| ".", |v| v.1);
                    // sub_dirs.push(n.to_string());

                    let list_file_parts = &list_file
                        .href
                        .split("/")
                        .filter(|s| filter_entry(s))
                        .collect::<Vec<_>>();

                    // There is folder entry corresponding to the passed  'parent_dir'
                    // and we need to exclude that
                    // e.g "dav/db1" -> ["dav" "db1"] 
                    if !(&paren_dir_parts == list_file_parts) {
                        if let Some(last_comp) = list_file_parts.last() {
                            sub_dirs.push(last_comp.to_string());
                        }
                    }
                }
            }
        }

        Ok(ServerDirEntry {
            parent_dir: parent_dir.into(),
            sub_dirs,
            files,
        })
    }

    async fn list_sub_dir(&self, parent_dir: &str, sub_dir: &str) -> Result<ServerDirEntry> {
        // Assuming parent_dir is the relative dir without host info
        // For now we use this simple join of parent_dir and sub dir using sep "/"
        let full_dir = [parent_dir, sub_dir].join("/");

        self.list_dir(&full_dir).await

        // let dir_info = self.client.list(&full_dir, Depth::Number(1)).await?;

        // let mut sub_dirs: Vec<String> = vec![];
        // let mut files: Vec<String> = vec![];
        // for e in dir_info {
        //     match e {
        //         ListEntity::File(f) => {
        //             info!("List entry is a file and meta is {:?} ", f);
        //             let n = f.href.split_once("/").map_or_else(|| ".", |v| v.1);
        //             files.push(n.to_string());
        //         }
        //         ListEntity::Folder(f) => {
        //             info!("List entry is a folder and meta is {:?} ", f);
        //             let n = f.href.split_once("/").map_or_else(|| ".", |v| v.1);
        //             sub_dirs.push(n.to_string());
        //         }
        //     }
        // }

        // Ok(ServerDirEntry {
        //     parent_dir: parent_dir.into(),
        //     sub_dirs,
        //     files,
        // })
    }

    async fn read(&self, parent_dir: &str, file_name: &str) -> Result<RemoteReadData> {
        // In webdav, this is a relative path. E.g /parent_dir/file_name
        let full_path = [parent_dir, file_name].join("/");

        let response = self.client.get(&full_path).await?;
        // Copies the full file content to memory
        let contents: Vec<u8> = response.bytes().await?.into();

        // Need to use Depth::Number(0) to get the file info as Depth of "0" applies only to the resource
        let (size, modified) = if let Some(list_entity) = self
            .client
            .list(&full_path, Depth::Number(0))
            .await?
            .first()
        {
            match list_entity {
                ListEntity::File(f) => (
                    Some(f.content_length as u64),
                    // last_modified is DateTime<Utc>
                    Some(f.last_modified.timestamp() as u64),
                ),
                _ => (None, None),
            }
        } else {
            (None, None)
        };

        // Should we make full file name by combining the relative path 'full_path' with host str of self.client.host
        // see the implementation of self.client.start_request where the combined url is formed
        let url = Url::parse(&format!(
            "{}/{}",
            &self.client.host.trim_end_matches("/"),
            &full_path.trim_start_matches("/")
        ))?;

        let full_file_name = url.as_str().to_string();

        let rmd = RemoteFileMetadata {
            connection_id: Uuid::default(),
            storage_type: RemoteStorageType::Webdav,
            full_file_name,
            size,
            accessed: None,
            modified,
            created: None,
        };

        Ok(RemoteReadData {
            data: contents,
            meta: rmd,
        })
    }

    async fn send_connect_and_retrieve_root_dir(
        tx: oneshot::Sender<Result<ConnectStatus>>,
        connection_info: WebdavConnectionConfig,
    ) {
        let dir_listing = WebdavConnection::connect_and_retrieve_root_dir(connection_info).await;
        let r = tx.send(dir_listing);
        if let Err(_) = r {
            log::error!("In connect_to_server send channel failed ");
        }
    }

    pub(crate) async fn send_connect_by_id_and_retrieve_root_dir(
        tx: oneshot::Sender<Result<ConnectStatus>>,
        connection_id: String,
    ) {
        let dir_listing =
            WebdavConnection::connect_by_id_and_retrieve_root_dir(&connection_id).await;
        let r = tx.send(dir_listing);
        if let Err(_) = r {
            log::error!("In send_connect_by_id_and_retrieve_root_dir send channel failed ");
        }
    }

    pub(crate) async fn send_connect_by_id(
        tx: oneshot::Sender<Result<RemoteStorageTypeConfig>>,
        connection_id: String,
    ) {
        debug!("In send_connect_by_id");

        let conn_r = WebdavConnection::connect_by_id(&connection_id).await;
        let r = tx.send(conn_r);
        if let Err(_) = r {
            log::error!("In send_connect_by_id send channel failed ");
        }
    }

    reply_by_webdav_async_fn!(send_list_sub_dir(parent_dir:String,sub_dir:String), list_sub_dir (&parent_dir,&sub_dir),ServerDirEntry);

    reply_by_webdav_async_fn!(send_read(parent_dir:String,file_name:String),read(&parent_dir,&file_name),RemoteReadData);
}

/*

pub(crate) async fn connect_and_retrieve_root_dir(
        mut connection_info: WebdavConnectionConfig,
    ) -> Result<ConnectStatus> {
        connection_info.connection_id =
            ConnectionConfigs::generate_config_id_on_check(connection_info.connection_id); // ConnectionConfigs::generate_config_id_on_check(connection_info);

        let agent = reqwest_dav::re_exports::reqwest::ClientBuilder::new()
            .danger_accept_invalid_certs(connection_info.allow_untrusted_cert)
            .build()?;

        info!("Agent is created...");

        // build a client
        let client = ClientBuilder::new()
            .set_agent(agent)
            .set_host(connection_info.root_url)
            .set_auth(Auth::Basic(
                connection_info.user_name,
                connection_info.password,
            ))
            .build()?;

        info!("Client is created...{:?}", &client);
        let webdav_connection = WebdavConnection { client };

        // Keep the start dir for the UI side to use for root dir listing with an existing connection
        connection_info.start_dir = Some(".".to_string());

        let dirs = webdav_connection.list_dir(".").await?;

        let store_key = connection_info.connection_id.to_string();
        // Store it for future reference
        let mut connections = webdav_connections_store().lock().await;
        info!("Inserting webdav connection for {}", &connection_info.name);
        connections.insert(store_key, webdav_connection);

        let conn_status = ConnectStatus {
            connection_id: connection_info.connection_id,
            dir_entries: Some(dirs),
        };

        Ok(conn_status)
    }


pub fn list_sub_dir(
    connetion_name: &str,
    parent_dir: &str,
    sub_dir: &str,
) -> Result<ServerDirEntry> {
    let (cn, pd, sd) = (
        connetion_name.to_string(),
        parent_dir.to_string(),
        sub_dir.to_string(),
    );

    receive_from_async_fn!(
        WebdavConnection::send_list_sub_dir(cn, pd, sd),
        ServerDirEntry
    )?
}

pub fn read(connection_name: &str, parent_dir: &str, file_name: &str) -> Result<RemoteReadData> {
    let (cn, pd, file) = string_tuple3(&[connection_name, parent_dir, file_name]);
    receive_from_async_fn!(WebdavConnection::send_read(cn, pd, file), RemoteReadData)?
}


// Caller needs to pass the relative path as parent_dir
    // e.g "." "/dav" "/dav/databases" etc and these parent dir should exists. Oterwiese an error with 404 code raised
    async fn list_dir(&self, parent_dir: &str) -> Result<ServerDirEntry> {
        let dir_info = self.client.list(parent_dir, Depth::Number(1)).await?;

        let mut sub_dirs: Vec<String> = vec![];
        let mut files: Vec<String> = vec![];
        for e in dir_info {
            match e {
                ListEntity::File(f) => {
                    info!("List entry is a file and meta is {:?} ", f);
                    let n = f.href.split_once("/").map_or_else(|| ".", |v| v.1);
                    files.push(n.to_string());
                }
                ListEntity::Folder(f) => {
                    info!("List entry is a folder and meta is {:?} ", f);
                    let n = f.href.split_once("/").map_or_else(|| ".", |v| v.1);
                    sub_dirs.push(n.to_string());
                }
            }
        }

        Ok(ServerDirEntry {
            parent_dir: parent_dir.into(),
            sub_dirs,
            files,
        })
    }


pub fn connect_to_server(connection_info: WebdavConnectionConfig) -> Result<ServerDirEntry> {
    let (tx, rx) = oneshot::channel::<Result<ServerDirEntry>>();
    async_runtime().spawn(WebdavConnection::send_connect_to_server(
        tx,
        connection_info,
    ));

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

    async fn send_connect_to_server(
        tx: oneshot::Sender<Result<ServerDirEntry>>,
        connection_info: WebdavConnectionConfig,
    ) {
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
            conn.list_dir(&parent_dir).await
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



*/
