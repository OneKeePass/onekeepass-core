use std::sync::{Arc, Mutex};

use log::{debug, info};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::Result;

use super::RemoteStorageType;

pub fn read_configs() -> Result<()> {
    ConnectionConfigs::read_config()
}
// Called from the UI facing rust side when the app is initialized
pub fn set_config_reader_writer(reader_writer: ConnectionConfigReaderWriterType) {
    ConnectionConfigReaderWriterStore::init(reader_writer);
}

// Implemented in the ffi module
pub trait ConnectionConfigReaderWriter {
    fn read_string(&self) -> Result<String>;
    fn write_string(&self, data: &str) -> Result<()>;
}

// Need to use Arc (or Box) to hold the concrete implementation of the Trait object
// Mutex is required for any interior mututable operations
// This is a thread safe type

//pub type ConnectionConfigReaderWriterType = Arc<Mutex<dyn ConnectionConfigReaderWriter + Sync + Send>>;
pub type ConnectionConfigReaderWriterType = Arc<dyn ConnectionConfigReaderWriter + Sync + Send>;

static CONFIG_READER_WRITER_INSTANCE: once_cell::sync::OnceCell<ConnectionConfigReaderWriterType> =
    once_cell::sync::OnceCell::new();

// Stores the config reader and writer trait implementation
struct ConnectionConfigReaderWriterStore {}

type Crw = ConnectionConfigReaderWriterStore;

impl ConnectionConfigReaderWriterStore {
    fn init(kss: ConnectionConfigReaderWriterType) {
        let _r = CONFIG_READER_WRITER_INSTANCE.set(kss);
        debug!("ConnectionConfigReaderWriterStore - init call is completed and CONFIG_READER_WRITER_INSTANCE initalized ");
    }

    fn instance() -> &'static ConnectionConfigReaderWriterType {
        CONFIG_READER_WRITER_INSTANCE
            .get()
            .expect("Error: ConnectionConfigReaderWriterStore is not initialzed")
    }

    fn is_initialized() -> bool {
        CONFIG_READER_WRITER_INSTANCE.get().is_some()
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum RemoteStorageTypeConfig {
    Sftp(SftpConnectionConfig),
    Webdav(WebdavConnectionConfig),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum RemoteStorageTypeConfigs {
    Sftp(Vec<SftpConnectionConfig>),
    Webdav(Vec<WebdavConnectionConfig>),
}

trait ConnectionId {
    fn connection_id(&self) -> &Uuid;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SftpConnectionConfig {
    pub connection_id: Uuid,
    // user selected name for this connection
    pub name: String,
    pub host: String,
    pub port: u16,
    // required for authenticate_publickey when we use private key
    pub private_key: Option<String>,
    pub user_name: String,
    // required for authenticate_password when we use password
    pub password: Option<String>,
    // All files and sub dirs in this will be shown
    pub start_dir: Option<String>,
}

impl ConnectionId for SftpConnectionConfig {
    fn connection_id(&self) -> &Uuid {
        &self.connection_id
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebdavConnectionConfig {
    pub connection_id: Uuid,
    // user selected name for this connection
    pub name: String,
    // e.g https:://server.com/somefolder or  http:://server.com/somefolder
    pub root_url: String,
    pub user_name: String,
    pub password: String,
    pub allow_untrusted_cert: bool,
}

impl ConnectionId for WebdavConnectionConfig {
    fn connection_id(&self) -> &Uuid {
        &self.connection_id
    }
}

#[derive(Serialize, Deserialize)]
pub struct ConnectionConfigs {
    sftp_connections: Vec<SftpConnectionConfig>,
    webdav_connections: Vec<WebdavConnectionConfig>,
}

impl Default for ConnectionConfigs {
    fn default() -> Self {
        Self {
            sftp_connections: vec![],
            webdav_connections: vec![],
        }
    }
}

// In memory static store of the config data

type ConfigStore = Arc<Mutex<ConnectionConfigs>>;

fn config_store() -> &'static ConfigStore {
    static CONFIG_STORE: once_cell::sync::Lazy<ConfigStore> =
        once_cell::sync::Lazy::new(Default::default);
    &CONFIG_STORE
}

impl ConnectionConfigs {
    
    // pub fn set_config_reader_writer(reader_writer: ConnectionConfigReaderWriterType) {
    //     Crw::init(reader_writer);
    // }

    pub(crate) fn generate_config_id_on_check(connection_id: Uuid) -> Uuid {
        if connection_id == Uuid::default() {
            Uuid::new_v4()
        } else {
            connection_id
        }
    }

    pub(crate) fn remote_storage_configs(request: RemoteStorageType) -> RemoteStorageTypeConfigs {
        let configs = config_store().lock().unwrap();
        match request {
            RemoteStorageType::Sftp => {
                RemoteStorageTypeConfigs::Sftp(configs.sftp_connections.clone())
            }
            RemoteStorageType::Webdav => {
                RemoteStorageTypeConfigs::Webdav(configs.webdav_connections.clone())
            }
        }
    }

    pub(crate) fn add_config(request: RemoteStorageTypeConfig) -> Result<()> {
        // Need to be in a block so that the config_store().lock() is released before next lock call
        {
            let mut conns = config_store().lock().unwrap();

            match request {
                RemoteStorageTypeConfig::Sftp(config) => {
                    let configs = &mut conns.sftp_connections;
                    Self::internal_add_config(configs, config);
                }
                RemoteStorageTypeConfig::Webdav(config) => {
                    let configs = &mut conns.webdav_connections;
                    Self::internal_add_config(configs, config);
                }
            };
        }
        Self::write_config()?;

        Ok(())
    }

    pub(crate) fn delete_config(request: RemoteStorageTypeConfig) -> Result<()> {
        {
            let mut configs = config_store().lock().unwrap();
            match request {
                RemoteStorageTypeConfig::Sftp(config) => {
                    let conns = &mut configs.sftp_connections;
                    Self::interal_delete_config(&config.connection_id, conns);
                }
                RemoteStorageTypeConfig::Webdav(config) => {
                    let conns = &mut configs.webdav_connections;
                    Self::interal_delete_config(&config.connection_id, conns);
                }
            }
        }

        Self::write_config()?;

        Ok(())
    }

    pub(crate) fn update_config(request: RemoteStorageTypeConfig) -> Result<()> {
        {
            let mut configs = config_store().lock().unwrap();
            match request {
                RemoteStorageTypeConfig::Sftp(config) => {
                    let conns = &mut configs.sftp_connections;
                    Self::interal_update_config::<SftpConnectionConfig>(conns, config);
                }
                RemoteStorageTypeConfig::Webdav(config) => {
                    let conns = &mut configs.webdav_connections;
                    Self::interal_update_config::<WebdavConnectionConfig>(conns, config);
                }
            }
        }

        Self::write_config()?;

        Ok(())
    }

    fn internal_add_config<T: ConnectionId>(configs: &mut Vec<T>, m_config: T) {
        let found = configs
            .iter()
            .find(|v| v.connection_id() == m_config.connection_id());
        if found.is_none() {
            debug!(
                "Config with id {} is not found in the list and adding to the list ",
                &m_config.connection_id()
            );
            configs.push(m_config);
        }
    }

    fn interal_delete_config<T: ConnectionId>(connection_id: &Uuid, configs: &mut Vec<T>) {
        configs.retain(|e| e.connection_id() != connection_id);
    }

    fn interal_update_config<T: ConnectionId>(configs: &mut Vec<T>, m_config: T) {
        for x in configs {
            if x.connection_id() == m_config.connection_id() {
                *x = m_config;
                break;
            }
        }
    }

    // Called to read the previously persisted configs
    pub(crate) fn read_config() -> Result<()> {
        let json_str = Crw::instance().read_string()?;
        let config_read = Self::from(&json_str);

        let mut stored_config = config_store().lock().unwrap();
        *stored_config = config_read;

        Ok(())
    }

    fn write_config() -> Result<()> {
        debug!("Going to call store write");
        let conns = config_store().lock().unwrap();
        conns.write()?;
        Ok(())
    }

    // json_str should be parseable as json object
    fn from(json_str: &str) -> Self {
        if json_str.is_empty() {
            info!("App remote connections config is empty and default used ");
            Self::default()
        } else {
            serde_json::from_str(&json_str).unwrap_or_else(|_| {
                info!("App remote connections config parsing failed and returning the empty default config");
                let connection_config_new = Self::default();
                connection_config_new
            })
        }
    }

    fn to_json_string(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    // Called on this instance whenever sftp or webdav config is modified or added or deleted
    // The serialized data is persisted
    fn write(&self) -> Result<()> {
        let s = self.to_json_string()?;
        debug!("Configs str to write to a file {}", &s);
        let data = self.to_json_string()?;
        Crw::instance().write_string(&data)?;
        Ok(())
    }
}

/*

pub(crate) fn add_config(request: RemoteStorageTypeConfig) -> Result<()> {
        // Need to be in a block so that the config_store().lock() is released before next lock call
        {
            let mut conns = config_store().lock().unwrap();

            match request {
                RemoteStorageTypeConfig::Sftp(config) => {
                    let s_conns = &mut conns.sftp_connections;
                    let found = s_conns
                        .iter()
                        .find(|v| v.connection_id == config.connection_id);
                    if found.is_none() {
                        s_conns.push(config);
                    }
                }
                RemoteStorageTypeConfig::Webdav(config) => {
                    let s_conns = &mut conns.webdav_connections;
                    let found = s_conns
                        .iter()
                        .find(|v| v.connection_id == config.connection_id);
                    if found.is_none() {
                        debug!(
                            "Config with id {} is not found in the list and adding to the list ",
                            &config.connection_id
                        );
                        s_conns.push(config);
                    }
                }
            };
        }
        Self::write_config()?;

        Ok(())
    }


// Adds the new config on connection
    pub fn add_sftp_config(config: SftpConnectionConfig) -> Result<()> {
        {
            let mut conns = config_store().lock().unwrap();
            let s_conns = &mut conns.sftp_connections;
            let found = s_conns
                .iter()
                .find(|v| v.connection_id == config.connection_id);
            if found.is_none() {
                debug!(
                    "Config with id {} is not found in the list and adding to the list ",
                    &config.connection_id
                );
                s_conns.push(config);
                // TODO: Need to encrypt and store in a file
            }
        }

        {
            debug!("Going to call store write");
            let conns = config_store().lock().unwrap();
            conns.write()?;
        }

        Ok(())
    }


pub fn sftp_configs() -> Vec<SftpConnectionConfig> {
        let configs = config_store().lock().unwrap();
        configs.sftp_connections.clone()
    }

    pub fn webdav_configs() -> Vec<WebdavConnectionConfig> {
        let configs = config_store().lock().unwrap();
        configs.webdav_connections.clone()
    }


pub fn test_read_config() {
        debug!("Called test_read_config...");
        let c = Self::read("/");
        let mut s = config_store().lock().unwrap();
        *s = c;

        //debug!("Configs set as {:?}", &*s);
    }

    fn read(config_dir: &str) -> Self {
        let rw = ConnectionConfigReaderWriterStore::instance();
        let s = rw.read_string();

        // let rw = ConnectionConfigReaderWriterStore::instance().lock().unwrap();
        // let s = rw.read_string();

        // let config = config_store().lock().unwrap();

        // if let Some(rw) = config.reader_writer.as_ref() {
        //     let s = rw.read();
        // }

        let app_config_file_name = Path::new(config_dir).join("app_config.json");
        info!(
            "Remote connections app_config_file_name is {:?} ",
            &app_config_file_name
        );
        let json_str = fs::read_to_string(app_config_file_name).unwrap_or("".into());
        debug!("App config json_str is {}", &json_str);
        if json_str.is_empty() {
            info!("App remote connections config is empty and default used ");
            Self::default()
        } else {
            serde_json::from_str(&json_str).unwrap_or_else(|_| {
                let pref_new = Self::default();
                pref_new
            })
        }
    }


// Creates the connection id if required and returns the updated config
    // pub fn generate_config_id_on_check(mut config: SftpConnectionConfig) -> SftpConnectionConfig {
    //     if config.connection_id == Uuid::default() {
    //         config.connection_id = Uuid::new_v4();
    //     }
    //     config
    // }

pub fn generate_on_check(uuid_to_check: Uuid) -> Uuid {
        if uuid_to_check == Uuid::default() {
            Uuid::new_v4()
        } else {
            uuid_to_check
        }
    }
static CONFIGS: std::sync::OnceLock<ConnectionConfigs> = std::sync::OnceLock::new();

fn global() -> &'static ConnectionConfigs {
        if CONFIGS.get().is_none() {

            if CONFIGS.set(ConnectionConfigs::default()).is_err() {
                log::error!(
                    "Global CONFIGS object is initialized already. This probably happened concurrently."
                );
            }
        }
        // Panics if no global state object was set. ??
        CONFIGS.get().unwrap()
    }

*/
