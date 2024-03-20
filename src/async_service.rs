use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use log::{debug, error, info};

use once_cell::sync::{Lazy, OnceCell};
use serde::{Deserialize, Serialize};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::mpsc;
use tokio::time::{self};
use uuid::Uuid;

use crate::db_service::entry_form_current_otp;

#[derive(Default, Serialize, Deserialize, Debug)]
struct OtpTokenTtlInfo {
    period: u64,
    ttl: u64,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct OtpTokenTtlInfoByField {
    token_ttls: HashMap<String, OtpTokenTtlInfo>,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct OtpTokenReply {
    pub token: Option<String>,
    pub ttl: Option<u64>,
    //pub period: Option<u64>,
}

impl OtpTokenReply {
    fn new(token: Option<String>, ttl: Option<u64>) -> Self {
        Self { token, ttl }
    }
}

// Instead of 'EntryOtpTokenReply', we may need to use an enum with an variant for entry form otp tokens
// another variant for entry list otp tokens

// Collects all otp field replies for an entry
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct EntryOtpTokenReply {
    pub entry_uuid: Uuid,
    // OtpTokenReply for each otp filed found for this entry
    pub reply_field_tokens: HashMap<String, OtpTokenReply>,
}

// A singleton to hold sender channel and otp tokens for all fields for each entry
#[derive(Default, Debug)]
struct EntryOtpTokenTtl {
    //receiver_sender:Mutex<(EntryOtpTx,EntryOtpRx)>,
    sender: Mutex<Option<EntryOtpTx>>,
    entry_ttls: Mutex<HashMap<Uuid, OtpTokenTtlInfoByField>>,
}

impl EntryOtpTokenTtl {
    fn is_stopped(&self, entry_uuid: &Uuid) -> bool {
        !self.entry_ttls.lock().unwrap().contains_key(entry_uuid)
    }

    // Sets the initial otp info for an entry when we start polling
    fn set(&self, entry_uuid: &Uuid, otp_fields: OtpTokenTtlInfoByField) {
        let mut e: MutexGuard<'_, HashMap<Uuid, OtpTokenTtlInfoByField>> =
            self.entry_ttls.lock().unwrap();
        e.insert(*entry_uuid, otp_fields);
    }

    // Called during the stop polling call
    fn remove(&self, entry_uuid: &Uuid) {
        let mut e = self.entry_ttls.lock().unwrap();
        e.remove(entry_uuid);
    }

    fn remove_all(&self) {
        let mut e = self.entry_ttls.lock().unwrap();
        e.clear();
        debug!("All entry polling removed and size is {}", e.len());
    }

    // Called to ensure we have the latest token and ttl before starting the polling loop
    fn form_first_reply(&self, db_key: &str, entry_uuid: &Uuid) -> EntryOtpTokenReply {
        let mut reply_field_tokens: HashMap<String, OtpTokenReply> = HashMap::new();

        let mut e = self.entry_ttls.lock().unwrap();

        if let Some(ttl_info_by_field) = e.get_mut(entry_uuid) {
            for (otp_field_name, token_info) in ttl_info_by_field.token_ttls.iter_mut() {
                // generate new token for this field
                match entry_form_current_otp(db_key, entry_uuid, otp_field_name) {
                    Ok(current_otp) => {
                        token_info.ttl = current_otp.ttl;
                        reply_field_tokens.insert(
                            otp_field_name.clone(),
                            OtpTokenReply::new(Some(current_otp.token), Some(token_info.ttl)),
                        );
                    }
                    Err(e) => {
                        error!("Token generation error {}", e);
                    }
                }
            }
        }
        EntryOtpTokenReply {
            entry_uuid: entry_uuid.clone(),
            reply_field_tokens,
        }
    }

    // forms the periodic reply for each otp field for this entry
    fn form_reply(&self, db_key: &str, entry_uuid: &Uuid) -> EntryOtpTokenReply {
        let mut reply_field_tokens: HashMap<String, OtpTokenReply> = HashMap::new();

        let mut e = self.entry_ttls.lock().unwrap();

        if let Some(ttl_info_by_field) = e.get_mut(entry_uuid) {
            for (otp_field_name, otp_info) in ttl_info_by_field.token_ttls.iter_mut() {
                // next ttl is determined decrementing 1 sec. Make sure we are not decrementing below 0!
                if otp_info.ttl != 0 {
                    otp_info.ttl -= 1;
                } else {
                    error!("otp_info.ttl is already zero. This is not expected");
                }

                if otp_info.ttl == 0 {
                    // Reset the ttl
                    // otp_info.ttl = otp_info.period;

                    // generate new token for this field
                    match entry_form_current_otp(db_key, entry_uuid, otp_field_name) {
                        Ok(current_otp) => {
                            // Reset the ttl to the latest.
                            // Typically most of the time current_otp.ttl = otp_info.period
                            // By the following reseting, we ensure the ttl is uptodate
                            otp_info.ttl = current_otp.ttl;
                            reply_field_tokens.insert(
                                otp_field_name.clone(),
                                OtpTokenReply::new(Some(current_otp.token), Some(otp_info.ttl)),
                            );
                        }
                        Err(e) => {
                            error!("Token generation error {}", e);
                        }
                    }
                } else {
                    // Send only ttl update
                    reply_field_tokens.insert(
                        otp_field_name.clone(),
                        OtpTokenReply::new(None, Some(otp_info.ttl)),
                    );
                }
            }
        }
        EntryOtpTokenReply {
            entry_uuid: entry_uuid.clone(),
            reply_field_tokens,
        }
    }
}

type EntryOtpTx = mpsc::Sender<EntryOtpTokenReply>;

pub type EntryOtpRx = mpsc::Receiver<EntryOtpTokenReply>;

type EntryOtpTokenStore = Arc<EntryOtpTokenTtl>;

fn entry_opt_token_store() -> &'static EntryOtpTokenStore {
    static ENTRY_OTP_TOKEN_STORE: Lazy<EntryOtpTokenStore> = Lazy::new(Default::default);
    &ENTRY_OTP_TOKEN_STORE
}

// Called to create mpsc channels
// The Receiver end is returned to the caller
pub fn init_entry_channels() -> EntryOtpRx {
    let (tx, rx): (EntryOtpTx, EntryOtpRx) = mpsc::channel(32);

    // This also works
    // entry_opt_token_store().sender.lock().unwrap().replace(tx);

    let mut s = entry_opt_token_store().sender.lock().unwrap();
    if let Some(_s1) = &*s {
        error!("Error: Existing sender are found. init_entry_channels is called multiple time?");
    }
    // Sender side is stored and receiver side is returned
    *s = Some(tx);
    rx
}

// Called to start updating all otp fields of an entry periodically
pub fn start_polling_entry_otp_fields(
    db_key: &str,
    previous_entry_uuid: Option<&Uuid>,
    entry_uuid: &Uuid,
    otp_fields: OtpTokenTtlInfoByField,
) {
    // If we see this error, we may need to fix by making sure
    // stop_polling_all_entries_otp_fields before this call
    if !entry_opt_token_store().is_stopped(entry_uuid) {
        error!(
            "Already an otp poll thread is running for the entry uuid {}. No new polling started",
            &entry_uuid
        );
        return;
    }

    if let Some(previous_entry) = previous_entry_uuid {
        entry_opt_token_store().remove(previous_entry);
    }

    entry_opt_token_store().set(entry_uuid, otp_fields);

    // Start the polling in a thread of Tokio runtime
    async_runtime().spawn(poll_token_generation(
        db_key.to_string(),
        entry_uuid.clone(),
    ));
}

// Called to remove updating all otp fields of all entries that are set previously
pub fn stop_polling_all_entries_otp_fields() {
    entry_opt_token_store().remove_all();
}

// Called to remove updating all otp fields of an entry
pub fn stop_polling_entry_otp_fields(entry_uuid: &Uuid) {
    entry_opt_token_store().remove(entry_uuid);
}

async fn poll_token_generation(db_key: String, entry_uuid: Uuid) {
    debug!("Started polling for entry_uuid {}", &entry_uuid);

    let sender;
    // Lock needs to be dropped by using a block
    // Otherwise, we see the error - future is not `Send` as this value is used across an await
    {
        let tx = entry_opt_token_store().sender.lock().unwrap();
        sender = (&*tx).clone();
    }

    let replys = entry_opt_token_store().form_first_reply(&db_key, &entry_uuid);

    if let Some(ref t) = sender {
        t.send(replys).await.unwrap();
    }

    let mut interval = time::interval(time::Duration::from_secs(1));
    // approximately 0ms will elapse as the first tick completes immediately.
    // This is important. Otherwise the ttl and token update will not be in sync in 'form_reply'
    interval.tick().await; // Oth tick

    loop {
        interval.tick().await;

        // time::sleep(time::Duration::from_secs(1)).await;

        if entry_opt_token_store().is_stopped(&entry_uuid) {
            debug!(
                "Polling is stopped for entry {} and exiting the loop",
                &entry_uuid
            );
            break;
        }

        let replys = entry_opt_token_store().form_reply(&db_key, &entry_uuid);
        if let Some(ref t) = sender {
            t.send(replys).await.unwrap();
        }
    }
}

// --------------------------------------------------------

static TOKIO_RUNTIME: OnceCell<Runtime> = OnceCell::new();

pub fn start_runtime() {
    let runtime = Builder::new_multi_thread()
        //.worker_threads(4)
        .thread_name("otp-token-ttl-update")
        .thread_stack_size(3 * 1024 * 1024)
        .enable_all()
        .build()
        .unwrap();

    debug!("Core TOKIO_RUNTIME is built...");

    TOKIO_RUNTIME.set(runtime).unwrap();

    info!("Core TOKIO_RUNTIME is set...");
}

// TODO:  Need to add graceful shutdown of all channels and Runtime itself(how?)
fn _shutdown_runtime() {
    if TOKIO_RUNTIME.get().is_some() {
        // We cann't make this call as async_runtime() is &, but shutdown_background requires full ownership
        // to be moved from OnceCell
        //async_runtime().shutdown_background()
    }
}

pub fn async_runtime() -> &'static Runtime {
    TOKIO_RUNTIME
        .get()
        .expect("Tokio runtime is not initialized")
}
