use std::
    sync::{Arc, OnceLock}
;

use crate::error::Result;
// This module is used by fns in this crate to use any callback servcices
// implemented in the calling UI facing rust crate (e.g tauri, db_service_ffi)

pub struct CallbackServiceProvider {
    common_callback_service: Arc<dyn CommonCallbackService>,
}

pub trait CommonCallbackService: Send + Sync {
    // Called to load a given wordlist file from the app's resource dir
    fn load_wordlist(&self, wordlist_file_name: &str) -> Result<String>;
}

static CALLBACK_PROVIDER: OnceLock<CallbackServiceProvider> = OnceLock::new();

impl CallbackServiceProvider {
    // Need to be called from the UI facing rust layer (tauri or db_service_ffi crate) crate
    // onetime when the app is starting
    pub fn init(common_callback_service: Arc<dyn CommonCallbackService>) {
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
    fn shared() -> &'static CallbackServiceProvider {
        // Panics if no global state object was set. ??
        CALLBACK_PROVIDER.get().unwrap()
    }

    pub(crate) fn common_callback_service() -> &'static dyn CommonCallbackService {
        Self::shared().common_callback_service.as_ref()
    }
}
