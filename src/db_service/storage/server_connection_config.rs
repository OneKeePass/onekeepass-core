use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex},
};

use log::{debug, info};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::Result;


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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebdavConnectionConfig {
    // user selected name for this connection
    pub name: String,
    // e.g https:://server.com/somefolder or  http:://server.com/somefolder
    pub root_url: String,
    pub user_name: String,
    pub password: String,
    pub allow_untrusted_cert: bool,
}

#[derive(Serialize, Deserialize, Debug)]
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

//type MainStore = Arc<Mutex<HashMap<String, KdbxContext>>>;

type ConfigStore = Arc<Mutex<ConnectionConfigs>>;

fn config_store() -> &'static ConfigStore {
    static CONFIG_STORE: once_cell::sync::Lazy<ConfigStore> =
        once_cell::sync::Lazy::new(Default::default);
    &CONFIG_STORE
}

impl ConnectionConfigs {
    // Creates the connection id if required and returns the updated config
    pub fn generate_config_id_on_check(mut config: SftpConnectionConfig) -> SftpConnectionConfig {
        if config.connection_id == Uuid::default() {
            config.connection_id = Uuid::new_v4();
        }
        config
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

    pub fn write(&self) -> Result<()> {
        let s = self.to_json_string()?;
        debug!("Configs str to write to a file {}", &s);
        Ok(())
    }

    pub fn test_read_config() {
        debug!("Called test_read_config...");
        let c = Self::read("/");
        let mut s = config_store().lock().unwrap();
        *s = c;

        debug!("Configs set as {:?}", &*s);
    }

    fn read(config_dir: &str) -> Self {
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
}

/*

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
