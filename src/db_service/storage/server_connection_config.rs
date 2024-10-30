use std::{fs, path::Path};

use log::{debug, info};
use serde::{Deserialize, Serialize};

use crate::error::Result;


#[derive(Serialize, Deserialize, Debug)]
pub struct ConnectionConfig {
    sftp_connections:Vec<SftpConnectionConfig>,
    webdav_connections:Vec<WebdavConnectionConfig>,
}

#[derive(Serialize, Deserialize, Debug,Clone)]
pub struct SftpConnectionConfig {
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
    pub start_dir:Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WebdavConnectionConfig {
    // user selected name for this connection
    pub name: String,
    // e.g https:://server.com/somefolder or  http:://server.com/somefolder
    pub root_url:String,
    pub user_name: String,
    pub password: String,
    pub allow_untrusted_cert:bool,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            sftp_connections:vec![],
            webdav_connections:vec![],
        }
    }
}

impl ConnectionConfig {
    fn read(config_dir: &str) -> Self { 
        let app_config_file_name = Path::new(config_dir).join("app_config.json");
        info!("Remote connections app_config_file_name is {:?} ", &app_config_file_name);
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
    fn from(json_str:&str) -> Self {
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

    fn to_json_string(&self) -> Result<String>  {
        Ok(serde_json::to_string_pretty(self)?)
    }
}