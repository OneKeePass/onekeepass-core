use log::debug;
use secstr::SecVec;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use onekeepass_core::{
    db_service as kp_service,
    db_service::{KeyStoreOperation, KeyStoreService},
};

pub fn init_key_main_store() {
    let kss = Arc::new(Mutex::new(KeyStoreServiceImpl::default()));
    // In case, we need to hold any reference at this module, then we need to Arc::clone
    // and use it
    KeyStoreOperation::init(kss);
    debug!("key_secure - key_main_store is initialized in init_key_main_store ");
}

pub fn init() {
    init_logging();
    init_key_main_store();
}

#[derive(Default)]
pub struct KeyStoreServiceImpl {
    store: HashMap<String, SecVec<u8>>,
}

impl KeyStoreService for KeyStoreServiceImpl {
    fn store_key(&mut self, db_key: &str, data: Vec<u8>) -> kp_service::Result<()> {
        // On successful loading of database, the keys are encrypted with Aes GCM cipher
        // and the encryption key for keys is stored in the KeyChain for macOS.
        // For now in case of Windows and Linux, we keep it locally

        debug!("store_key is called and data size {}", data.len());
        self.store.insert(db_key.into(), SecVec::new(data));
        debug!("Encrypted key is stored for other cfg");
        Ok(())
    }

    fn get_key(&self, db_key: &str) -> Option<Vec<u8>> {
        self.store.get(db_key).map(|v| Vec::from(v.unsecure()))
    }

    fn delete_key(&mut self, db_key: &str) -> kp_service::Result<()> {
        self.store.remove(db_key);
        debug!("Keys are deleted..");
        Ok(())
    }

    fn copy_key(&mut self, source_db_key: &str, target_db_key: &str) -> kp_service::Result<()> {
        if let Some(source_db_key) = self.store.get(source_db_key).cloned() {
            self.store.insert(target_db_key.into(), source_db_key);
            debug!("Keys are copied...");
        }
        Ok(())
    }
}

pub fn init_logging() {
    let _ = env_logger::builder()
        // Include all events in tests
        .filter_level(log::LevelFilter::max())
        // Ensure events are captured by `cargo test`
        .is_test(true)
        // Ignore errors initializing the logger if tests race to configure it
        .try_init();
}
