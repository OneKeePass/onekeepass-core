use log::debug;
use once_cell::sync::OnceCell;
use std::sync::{Arc, Mutex};

use crate::error::Result;

// Need to use Arc (or Box) to hold the concrete implementation of the Trait object
// Mutex is required for any interior mututable operations
// This is a thread safe type
pub type KeyStoreServiceType = Arc<Mutex<dyn KeyStoreService + Sync + Send>>;

static KEY_STORE_SERVICE_INSTANCE: OnceCell<KeyStoreServiceType> = OnceCell::new();

pub trait KeyStoreService {
    fn store_key(&mut self, db_key: &str, val: Vec<u8>) -> Result<()>;
    fn get_key(&self, db_key: &str) -> Option<Vec<u8>>;
    fn delete_key(&mut self, db_key: &str) -> Result<()>; // Return  Result<()>
    fn copy_key(&mut self, source_db_key: &str, target_db_key: &str) -> Result<()>;
}

pub struct KeyStoreOperation;

impl KeyStoreOperation {
    // Called from the UI facing rust side when the app is initialized
    // See key_secure::init_key_main_store fn in src-tauri and ffi layer for initialization call
    pub fn init(kss: KeyStoreServiceType) {
        let _r = KEY_STORE_SERVICE_INSTANCE.set(kss);
        debug!("key_secure - init call is completed and KEY_STORE_SERVICE_INSTANCE initalized ");
    }

    fn key_store_service_instance() -> &'static KeyStoreServiceType {
        KEY_STORE_SERVICE_INSTANCE
            .get()
            .expect("Error: KeyStoreService is not initialzed")
    }

    // Stores the ecryption key by calling platform specific implementation of key store calls
    pub fn store_key(db_key: &str, val: Vec<u8>) -> Result<()> {
        let mut store_service = Self::key_store_service_instance().lock().unwrap();
        store_service.store_key(db_key, val)
    }

    pub fn get_key(db_key: &str) -> Option<Vec<u8>> {
        let store_service = Self::key_store_service_instance().lock().unwrap();
        store_service.get_key(db_key)
    }

    pub fn delete_key(db_key: &str) -> Result<()> {
        let mut store_service = Self::key_store_service_instance().lock().unwrap();
        store_service.delete_key(db_key)
    }

    pub fn copy_key(source_db_key: &str, target_db_key: &str) -> Result<()> {
        let mut store_service = Self::key_store_service_instance().lock().unwrap();
        store_service.copy_key(source_db_key, target_db_key)
    }
}

// pub fn set_key_store_service_instance(kss: &KeyStoreServiceType) {
//     let _r = KEY_STORE_SERVICE_INSTANCE.set(kss.clone());
//     debug!("key_secure - set_key_store_service_instance call is completed and KEY_STORE_SERVICE_INSTANCE initalized ");
// }

// pub fn get_key_store_service_instance() -> &'static KeyStoreServiceType {
//     KEY_STORE_SERVICE_INSTANCE
//         .get()
//         .expect("Error: KeyStoreService is not initialzed")
// }
