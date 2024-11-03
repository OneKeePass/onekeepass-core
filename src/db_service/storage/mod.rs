use std::time::SystemTime;

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
pub struct RemoteFileMetadata {
    storage_type:RemoteStorageType,
    // Should we add file_name here?
    // file_name:String,
    full_file_name:String,
    size:Option<u64>,
    created:Option<u64>,
    modified:Option<u64>,
    accessed:Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RemoteReadData {
    data:Vec<u8>,
    meta:RemoteFileMetadata,
}

#[macro_export]
macro_rules! reply_by_async_fn {
    ($store:ident, $fn_name:ident ($($arg1:tt:$arg_type:ty),*), $send_val:ty,$call:tt ($($arg:expr),*)) => {
        pub(crate) async fn $fn_name(
            tx: oneshot::Sender<$send_val>,
            connetion_name:String,
            $($arg1:$arg_type),*

        ) {
            let connections = $store().lock().await;

            let r = if let Some(conn) = connections.get(&connetion_name) {
                conn.$call($($arg),*).await
            } else {
                Err(error::Error::UnexpectedError(format!(
                    "No previous connected session is found for the name {}",
                    connetion_name
                )))
            };

            let r = tx.send(r);
            if let Err(_) = r {
                let name = stringify!($call);
                // Should not happen? But may happen if no receiver?
                log::error!("The '{}' fn send channel call failed ", &name);
            }
        }
    };
}


#[macro_export]
macro_rules! receive_from_async_fn {
    ($channel_val:ty,$p:ident::$fn_name:ident ($($arg:tt),*) ) => {{
        let (tx, rx) = oneshot::channel::<$channel_val>();
        //async_runtime().spawn(SftpConnection::send_connect_to_server(tx, connection_info));
        async_runtime().spawn($p::$fn_name(tx, $($arg),*));
        let s = rx.blocking_recv().map_err(|e| {
            error::Error::UnexpectedError(format!(
                "In connect_to_server receive channel error {}",
                e
            ))
        });

        s
    }};
}

fn extract_file_name(remote_full_path: &str) -> Option<String> {
    remote_full_path.split("/").last().map(|s| s.into())
    //remote_full_path.split("/").last().map_or_else(|| "No file".into(), |s| s.into())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use url::Url;

    use crate::db_service::storage::extract_file_name;
    #[test]
    fn verify_extract_file_name() {
        let fn1 = extract_file_name("https://192.168.1.4/dav/Test-OTP1.kdbx");
        println!("File name 1 is {:?}", &fn1);

        let fn2 = extract_file_name("/dav/Test-OTP1.kdbx");
        println!("File name 1 is {:?}", &fn2);

        let url = Url::parse("https://192.168.1.4:8080/Doc:Amm/").unwrap();

        let url = url.join("dav/").unwrap();  // should be "dav/" and not "dav"
        let url = url.join("Test-OTP1.kdbx").unwrap();

        println!("url is {}",&url);

        let mut p = PathBuf::from("https://192.168.1.4:8080/Doc:mm");
        p.push("dav"); 
        p.push("Test-OTP1.kdbx");

        println!("path is {:?}",&p.as_path());
        println!("Encoded url {:?}",&urlencoding::encode(&p.as_os_str().to_str().unwrap()));
        println!("Encoded2 url {:?}",&urlencoding::encode("https://192.168.1.4:8080/Doc:mm"));

        
    }
}
