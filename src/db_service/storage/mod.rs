use serde::{Deserialize, Serialize};

mod server_connection_config;
pub mod sftp;
pub mod webdav;

#[derive(Serialize, Deserialize, Debug)]
pub struct ServerDirEntry {
    // e.g "/" , "/dav"
    parent_dir: String,
    sub_dirs: Vec<String>,
    files: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum RemoteStorageType {
    Sftp,
    Webdav,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum RemoteStorageToRead {
    Sftp {
        connection_name: String,
        parent_dir: String,
        file_name: String,
    },
    Webdav {
        connection_name: String,
        parent_dir: String,
        file_name: String,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RemoteFileMetadata {
    storage_type: RemoteStorageType,
    // Should we add file_name here?
    //file_name:String,
    full_file_name: String,
    pub size: Option<u64>,
    pub created: Option<u64>,
    pub modified: Option<u64>,
    pub accessed: Option<u64>,
}

impl RemoteFileMetadata {
    // This is used as db_key 
    pub fn prefixed_full_file_name(&self) -> String {
        match self.storage_type {
            RemoteStorageType::Sftp => {
                format!("Sftp:{}", &self.full_file_name)
            }
            RemoteStorageType::Webdav => {
                format!("Webdav:{}", &self.full_file_name)
            }
        }
    }
}

pub struct RemoteReadData {
    pub data: Vec<u8>,
    pub meta: RemoteFileMetadata,
}

// Called to create an async function ('send_*') that in turn calls the corresponding
// internal async fn and send the result back in the passed oneshot send channel
// See 'receive_from_async_fn' macros where we create the oneshot channel and call the 'send_*' aync fn in a 'spawn' call

// Args are
// store   - determines to use sftp or webdav connections store
// fn_name - This is the name of the async funtion that is created
// arg1    - The arguments for that function
// channel_ret_val  - The type of the value returned in the channel in the inner async fn call
// inner_fn_name - This is the inner async funtion is that is called in turn for the actual operation and its return
//                 value if of type 'channel_ret_val'
// arg2    - The arguments for the inner function

#[macro_export]
macro_rules! reply_by_async_fn {
    ($store:ident, $fn_name:ident ($($arg1:tt:$arg_type:ty),*),$inner_fn_name:tt ($($arg2:expr),*),$channel_ret_val:ty) => {
        pub(crate) async fn $fn_name(
            tx: oneshot::Sender<Result<$channel_ret_val>>,
            connetion_name:String,
            $($arg1:$arg_type),*

        ) {
            let connections = $store().lock().await;

            let r = if let Some(conn) = connections.get(&connetion_name) {
                // e.g conn.connect_to_server(connection_info)
                conn.$inner_fn_name($($arg2),*).await
            } else {
                Err(error::Error::UnexpectedError(format!(
                    "No previous connected session is found for the connection name {}",
                    connetion_name
                )))
            };

            let r = tx.send(r);
            if let Err(_) = r {
                let name = stringify!($fn_name);
                // Should not happen? But may happen if no receiver?
                log::error!("The '{}' fn send channel call failed ", &name);
            }
        }
    };
}

// Called to create a block where we create an oneshot channel with (receiver,sender) and
// then calls the 'async fn send_*' passed in 'fn_name'
// path detrmines whether to use 'SftpConnection' or 'WebdavConnection'
// channel_ret_val  - The type of the value returned in the channel
// fn_name - This is the async funtion (of pattern like send_*) that is called in 'async_runtime().spawn()'
// arg - arguments for 'fn_name'
#[macro_export]
macro_rules! receive_from_async_fn {
    ($path:ident::$fn_name:ident ($($arg:tt),*),$channel_ret_val:ty) => {{
        let (tx, rx) = oneshot::channel::<Result<$channel_ret_val>>();
        async_runtime().spawn($path::$fn_name(tx, $($arg),*));
        let s = rx.blocking_recv().map_err(|e| {
            let name = stringify!($fn_name);
            error::Error::UnexpectedError(format!(
                "Receive channel error {} when calling inner async fn {} ", e,&name
            ))
        });
        s
    }};
}

fn string_tuple3(a: &[&str]) -> (String, String, String) {
    (a[0].to_string(), a[1].to_string(), a[2].to_string())
}

fn _tuple2<T>(a: &[T]) -> (&T, &T) {
    (&a[0], &a[1])
}

fn _string_tuple2(a: &[&str]) -> (String, String) {
    (a[0].to_string(), a[1].to_string())
}

fn extract_file_name(remote_full_path: &str) -> Option<String> {
    remote_full_path.split("/").last().map(|s| s.into())
    //remote_full_path.split("/").last().map_or_else(|| "No file".into(), |s| s.into())
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::SystemTime};

    use url::Url;

    use crate::db_service::storage::extract_file_name;

    #[test]
    fn verify_extract_file_name() {
        let fn1 = extract_file_name("https://192.168.1.4/dav/Test-OTP1.kdbx");
        println!("File name 1 is {:?}", &fn1);

        let fn2 = extract_file_name("/dav/Test-OTP1.kdbx");
        println!("File name 1 is {:?}", &fn2);

        let url = Url::parse("https://192.168.1.4:8080/Doc:Amm/").unwrap();

        let url = url.join("dav/").unwrap(); // should be "dav/" and not "dav"
        let url = url.join("Test-OTP1.kdbx").unwrap();

        println!("url is {}", &url);

        let mut p = PathBuf::from("https://192.168.1.4:8080/Doc:mm");
        p.push("dav");
        p.push("Test-OTP1.kdbx");

        println!("path is {:?}", &p.as_path());
        println!(
            "Encoded url {:?}",
            &urlencoding::encode(&p.as_os_str().to_str().unwrap())
        );
        println!(
            "Encoded2 url {:?}",
            &urlencoding::encode("https://192.168.1.4:8080/Doc:mm")
        );
    }
}
