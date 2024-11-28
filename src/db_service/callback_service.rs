use std::{path::PathBuf, sync::{Arc, OnceLock}};


// This module is used by fns in this crate to use any callback servcices
// implemented in the calling crate (e.g db-service-ffi)

// TODO: Should 'server_connection_config::ConnectionConfigReaderWriterStore' also be moved here ?

pub struct CallbackServiceProvider {
    common_callback_service: Arc<dyn CommonCallbackService>,
} 

pub trait CommonCallbackService: Send + Sync {
    fn sftp_private_key_file_full_path(&self,file_name:&str) -> PathBuf;
}

static CALLBACK_PROVIDER: OnceLock<CallbackServiceProvider> = OnceLock::new();

impl CallbackServiceProvider {
    pub(crate) fn shared() -> &'static CallbackServiceProvider {
        // Panics if no global state object was set. ??
        CALLBACK_PROVIDER.get().unwrap()
    }

    pub(crate) fn common_callback_service() -> &'static dyn CommonCallbackService {
        Self::shared().common_callback_service.as_ref()
    }

    // Need to be called from the 'db-service-ffi' crate onetime when the app is starting
    pub fn setup(common_callback_service: Arc<dyn CommonCallbackService>) {
        let provider = CallbackServiceProvider {
            common_callback_service,
        };

        if CALLBACK_PROVIDER.get().is_none() {
            if CALLBACK_PROVIDER.set(provider).is_err() {
                log::error!(
                    "Global CALLBACK_PROVIDER object is initialized already. This probably happened concurrently."
                );
            }
        }
    }
}

/*
//////////  

// TODO: Need to combine COMMON_CALLBACK_SERVICE_INSTANCE and CONFIG_READER_WRITER_INSTANCE

pub trait CommonCallbackService {
    fn sftp_private_key_file_full_path(&self,file_name:&str) -> PathBuf;
}

pub type CommonCallbackServiceType = std::sync::Arc<dyn CommonCallbackService + Sync + Send>;

// Called from the UI facing rust side when the app is initialized
pub fn init_common_callback_service_provider(provider: CommonCallbackServiceType) {
    let _r = COMMON_CALLBACK_SERVICE_INSTANCE.set(provider);
    log::debug!("init_common_callback_service_provider - init call is completed and COMMON_CALLBACK_SERVICE_INSTANCE initalized ");
}


static COMMON_CALLBACK_SERVICE_INSTANCE: std::sync::OnceLock<CommonCallbackServiceType> = std::sync::OnceLock::new();


pub(crate) fn common_callback_service() -> &'static CommonCallbackServiceType {
    COMMON_CALLBACK_SERVICE_INSTANCE
        .get()
        .expect("Error: COMMON_CALLBACK_SERVICE_INSTANCE is not initialzed")
}

////////////////////////// 


*/