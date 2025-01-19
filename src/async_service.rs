use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use log::{debug, error, info};

use once_cell::sync::Lazy;
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

#[derive(Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum AsyncResponse {
    EntryOtpToken(EntryOtpTokenReply),
    Tick(TickReply),
    ServiceStopped,
}

#[derive(Default, Serialize, Deserialize)]
pub struct TickReply {
    timer_id: TimerID,
}

// Collects all otp field replies for an entry
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct EntryOtpTokenReply {
    pub entry_uuid: Uuid,
    // OtpTokenReply for each otp filed found for this entry
    pub reply_field_tokens: HashMap<String, OtpTokenReply>,
}

pub type TimerID = u32;

type TimerCancelled = bool;

type EntryOtpTx = mpsc::Sender<AsyncResponse>;

pub type EntryOtpRx = mpsc::Receiver<AsyncResponse>;

const TIME_ID_START: u32 = 2001;

// A singleton to hold sender channel and otp tokens for all fields for each entry
struct MainAsyncData {
    // A simple incrementing number is used as timer id for now
    // Assumption is that we will be creating limited number of timers
    timer_id_counter: AtomicU32,
    entry_ttls: Mutex<HashMap<Uuid, OtpTokenTtlInfoByField>>,
    periodic_timers: Mutex<HashMap<TimerID, TimerCancelled>>,
    sender: Mutex<Option<EntryOtpTx>>,
}

impl Default for MainAsyncData {
    fn default() -> Self {
        Self {
            // If the timer is created on the backend, all ids will be >= 2001
            // 1 to 2000 are reserved for the client generated timer ids
            timer_id_counter: AtomicU32::new(TIME_ID_START),
            entry_ttls: Mutex::default(),
            periodic_timers: Mutex::default(),
            sender: Mutex::default(),
        }
    }
}

impl MainAsyncData {
    fn next_timer_id(&self) -> TimerID {
        // fetch_add adds to the current value, returning the previous value
        // So the first value is the intial value 5000
        self.timer_id_counter.fetch_add(1, Ordering::Relaxed)
    }

    fn init_timer_id(&self, timer_id: Option<TimerID>) -> TimerID {
        //debug!("Start counter timer id {:?}",&self.timer_id_counter);

        let id = timer_id.unwrap_or_else(|| self.next_timer_id());

        //debug!("After counter timer id {:?}, key id {} ",&self.timer_id_counter, &id);

        let mut timers = self.periodic_timers.lock().unwrap();

        // false indicates the timer is not yet cancelled
        timers.insert(id.clone(), false);
        id
    }

    fn prepare_stopping_services(&self) {
        // All aync loops waiting on these will break from the loop and exit the async fn
        self.remove_all_timers();
        self.remove_all_entry_otp_polling_data();
        self.timer_id_counter.swap(TIME_ID_START, Ordering::Relaxed);
    }

    fn remove_timer(&self, timer_id: &TimerID) {
        let mut timers = self.periodic_timers.lock().unwrap();
        timers.remove(timer_id);
    }

    fn remove_all_timers(&self) {
        let mut timers = self.periodic_timers.lock().unwrap();
        timers.clear()
    }

    fn is_timer_cancelled(&self, timer_id: &TimerID) -> TimerCancelled {
        let timers = self.periodic_timers.lock().unwrap();
        // On cancellation of a timer, it is removed from the map
        // Should we use contains check only?
        if let Some(v) = timers.get(timer_id) {
            *v
        } else {
            true
        }
    }

    fn sender(&self) -> Option<EntryOtpTx> {
        let t = self.sender.lock().unwrap();
        (&*t).clone()
    }

    fn remove_sender(&self) {
        let mut t = self.sender.lock().unwrap();
        *t = None
    }

    fn is_entry_polling_stopped(&self, entry_uuid: &Uuid) -> bool {
        !self.entry_ttls.lock().unwrap().contains_key(entry_uuid)
    }

    // Sets the initial otp info for an entry when we start polling
    fn init_entry_otp_polling_data(&self, entry_uuid: &Uuid, otp_fields: OtpTokenTtlInfoByField) {
        let mut e: MutexGuard<'_, HashMap<Uuid, OtpTokenTtlInfoByField>> =
            self.entry_ttls.lock().unwrap();
        e.insert(*entry_uuid, otp_fields);
    }

    // Called during the stop polling call
    fn remove_entry_otp_polling_data(&self, entry_uuid: &Uuid) {
        let mut e = self.entry_ttls.lock().unwrap();
        e.remove(entry_uuid);
    }

    fn remove_all_entry_otp_polling_data(&self) {
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

type MainAsyncDataStore = Arc<MainAsyncData>;

fn main_async_data_store() -> &'static MainAsyncDataStore {
    static ENTRY_OTP_TOKEN_STORE: Lazy<MainAsyncDataStore> = Lazy::new(Default::default);
    &ENTRY_OTP_TOKEN_STORE
}

// Called to create mpsc channels
// The Receiver end is returned to the caller
pub fn init_entry_channels() -> EntryOtpRx {
    let (tx, rx): (EntryOtpTx, EntryOtpRx) = mpsc::channel(32);

    // This also works
    // entry_opt_token_store().sender.lock().unwrap().replace(tx);

    let mut s = main_async_data_store().sender.lock().unwrap();
    if let Some(_s1) = &*s {
        error!("Error: Existing sender are found. init_entry_channels is called multiple time?");
    }
    // Sender side is stored and receiver side is returned
    *s = Some(tx);
    rx
}

// Called by UI layer to start updating all otp fields of an entry periodically
// Arg 'OtpTokenTtlInfoByField' has the period and ttl info passed from UI for each otp field that has 
// parseable otp url - See Entry's parse_all_otp_fields fn and KeyValueData's current_opt_token field
pub fn start_polling_entry_otp_fields(
    db_key: &str,
    entry_uuid: &Uuid,
    otp_fields: OtpTokenTtlInfoByField,
) {
    // If we see this error, we may need to fix by making sure
    // stop_polling_all_entries_otp_fields before this call
    if !main_async_data_store().is_entry_polling_stopped(entry_uuid) {
        error!(
            "Already an otp poll thread is running for the entry uuid {}. No new polling started",
            &entry_uuid
        );
        return;
    }
    main_async_data_store().init_entry_otp_polling_data(entry_uuid, otp_fields);

    // Start the polling in a thread of Tokio runtime
    // spawn expects a aeg of type : Future + Send + 'static
    async_runtime().spawn(poll_token_generation(
        db_key.to_string(),
        entry_uuid.clone(),
    ));
}

/*
pub fn start_polling_entry_otp_fields(
    db_key: &str,
    previous_entry_uuid: Option<&Uuid>,
    entry_uuid: &Uuid,
    otp_fields: OtpTokenTtlInfoByField,
) {
    // If we see this error, we may need to fix by making sure
    // stop_polling_all_entries_otp_fields before this call
    if !main_async_data_store().is_stopped(entry_uuid) {
        error!(
            "Already an otp poll thread is running for the entry uuid {}. No new polling started",
            &entry_uuid
        );
        return;
    }

    if let Some(previous_entry) = previous_entry_uuid {
        main_async_data_store().remove(previous_entry);
    }

    main_async_data_store().set(entry_uuid, otp_fields);

    // Start the polling in a thread of Tokio runtime
    // spawn expects a aeg of type : Future + Send + 'static
    async_runtime().spawn(poll_token_generation(
        db_key.to_string(),
        entry_uuid.clone(),
    ));
}
*/

// Called to remove updating all otp fields of all entries that are set previously
pub fn stop_polling_all_entries_otp_fields() {
    main_async_data_store().remove_all_entry_otp_polling_data();
}

// Called to remove updating all otp fields of an entry
pub fn stop_polling_entry_otp_fields(entry_uuid: &Uuid) {
    main_async_data_store().remove_entry_otp_polling_data(entry_uuid);
}

// Called to create a repeat timer that sends a periodic tick
pub fn start_periodic_timer(period_in_milli_seconds: u64, timer_id: Option<TimerID>) -> TimerID {
    let id = main_async_data_store().init_timer_id(timer_id);
    async_runtime().spawn(run_periodic_timer(period_in_milli_seconds, id.clone()));
    id
}

// Called to create a timer that sends a tick on its period expiration
pub fn set_timeout(period_in_milli_seconds: u64, timer_id: Option<TimerID>) -> TimerID {
    debug!(
        "In coming set_timeout period {}, timer_id {:?}",
        &period_in_milli_seconds, &timer_id
    );
    let id = main_async_data_store().init_timer_id(timer_id);
    // Spawn the timeout
    async_runtime().spawn(run_specified_timeout(period_in_milli_seconds, id.clone()));

    id
}

// Called to cancel a timer that is started earlier
pub fn cancel_timer(timer_id: &TimerID) {
    main_async_data_store().remove_timer(timer_id);
}

// This is used only during dev time, particularly when async services
// are sending events to the front end via rust middle layer - see 'init_async_listeners' (db-service-ffi/src/event_dispatcher.rs)
// This ensures that no active messages are sent to the UI layer from backend async loops while
// metro dev server is being refreshed during dev time

// Called to stop all async services
pub fn shutdown_async_services() {
    info!("shutdown_async_services is called");
    main_async_data_store().prepare_stopping_services();
    info!("Prepared to stop all sending loops...");

    // In case of iOS, we should not stop receiver side aync listeners in 'init_async_listeners'
    // and also shoud not shutdown the tokio runtime

    if cfg!(target_os = "android") {
        async_runtime().spawn(send_stop_service_message());
        shutdown_runtime();
    }
}

// -----------------------------------------------------------------------------------------------

async fn send_stop_service_message() {
    if let Some(tx) = main_async_data_store().sender() {
        let r = tx.send(AsyncResponse::ServiceStopped).await;
        if r.is_err() {
            error!("Unexpected error in sending service stop message ");
        }
    }
    info!("Send ServiceStopped message to the receiving side");
    main_async_data_store().remove_sender();
}

// Sends a tick to the listener on the timer expiration
async fn send_timer_reply(timer_id: &TimerID) {
    // send reply
    if let Some(tx) = main_async_data_store().sender() {
        let r = tx
            .send(AsyncResponse::Tick(TickReply {
                timer_id: timer_id.clone(),
            }))
            .await;
        if r.is_err() {
            error!("Unexpected error in sending timer id {}", &timer_id);
        }
    }
}

// On expiration of the timeout, tick will be sent to the caller by message
async fn run_specified_timeout(period_in_milli_seconds: u64, timer_id: TimerID) {
    time::sleep(time::Duration::from_millis(period_in_milli_seconds)).await;

    if main_async_data_store().is_timer_cancelled(&timer_id) {
        return;
    }

    main_async_data_store().remove_timer(&timer_id);

    // send reply
    send_timer_reply(&timer_id).await;
}

// On expiration of the timeout, tick will be sent to the caller by message and repeats
async fn run_periodic_timer(period_in_milli_seconds: u64, timer_id: TimerID) {
    if main_async_data_store().is_timer_cancelled(&timer_id) {
        return;
    }

    loop {
        time::sleep(time::Duration::from_millis(period_in_milli_seconds)).await;

        if main_async_data_store().is_timer_cancelled(&timer_id) {
            debug!("Timer with id {} is cancelled ", &timer_id);
            break;
        }

        // send reply till this timer is cancelled from UI
        send_timer_reply(&timer_id).await;
    }
}

// async fn is a future
// await call asynchronously waits for the completion of another operation and doesn’t block the current thread
async fn poll_token_generation(db_key: String, entry_uuid: Uuid) {
    debug!("Started polling for entry_uuid {}", &entry_uuid);

    let sender;
    // Lock needs to be dropped by using a block
    // Otherwise, we see the error - future is not `Send` as this value is used across an await
    {
        let tx = main_async_data_store().sender.lock().unwrap();
        sender = (&*tx).clone();
    }

    let replys = main_async_data_store().form_first_reply(&db_key, &entry_uuid);

    let replys = AsyncResponse::EntryOtpToken(replys);

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

        if main_async_data_store().is_entry_polling_stopped(&entry_uuid) {
            debug!(
                "Polling is stopped for entry {} and exiting the loop",
                &entry_uuid
            );
            break;
        }

        let replys = main_async_data_store().form_reply(&db_key, &entry_uuid);
        let replys = AsyncResponse::EntryOtpToken(replys);
        if let Some(ref t) = sender {
            t.send(replys).await.unwrap();
        }
    }
}
// --------------------------------------------------------

// As this is global, all access to this variable need to use 'unsafe' block
// Otherwise we will see compile error 'this operation is unsafe and requires an unsafe function or block'
// We may need to use Mutex to be thread safe for all access to this variable
static mut OKP_TOKIO_RUNTIME: Option<Runtime> = None;

// Assumed this is called once in a single thread
// See src-tauri/src/app_state.rs  AppState::init_app fn
// See src/udl_uniffi_exports.rs   db_service_initialize fn
pub fn start_runtime() {

    // This is not expected except during dev time if 'start_runtime' is 
    // called by reloading UI layer code. However, in both tauri layer and in
    // Swift/Kotlin layer, we ensure that this fn is called once
    if let Some(_r) = unsafe { OKP_TOKIO_RUNTIME.as_ref() } {
        info!("OKP_TOKIO_RUNTIME is already running and going to shutdown before restarting");
        shutdown_runtime();
    }

    let runtime = Builder::new_multi_thread()
        //.worker_threads(4)
        .thread_name("okp-async-service")
        .thread_stack_size(3 * 1024 * 1024)
        .enable_all()
        .build()
        .unwrap();

    debug!("Core OKP_TOKIO_RUNTIME is built...");

    unsafe { OKP_TOKIO_RUNTIME.replace(runtime) };

    info!("Core OKP_TOKIO_RUNTIME is set...");
}

// May be called from multiple threads and this Runtime ref is shared 
pub fn async_runtime() -> &'static Runtime {
    unsafe { OKP_TOKIO_RUNTIME.as_ref().unwrap() }
}

// Single thread
pub fn shutdown_runtime() {
    if let Some(runtime) = unsafe { OKP_TOKIO_RUNTIME.take() } {
        info!("Shutdown OKP_TOKIO_RUNTIME started");
        runtime.shutdown_timeout(tokio::time::Duration::from_secs(1));
        info!("Shutdown OKP_TOKIO_RUNTIME done");
    }
}

// --------------------------------------------------------

/*
static TOKIO_RUNTIME: OnceCell<Runtime> = OnceCell::new();

pub fn start_runtime() {

    let rt = TOKIO_RUNTIME.get();
    debug!("TOKIO_RUNTIME is {:?}",rt);

    let runtime = Builder::new_multi_thread()
        //.worker_threads(4)
        .thread_name("okp-async-service")
        .thread_stack_size(3 * 1024 * 1024)
        .enable_all()
        .build()
        .unwrap();

    debug!("Core TOKIO_RUNTIME is built...");

    TOKIO_RUNTIME.set(runtime).unwrap();

    info!("Core TOKIO_RUNTIME is set...");
}

// TODO:  Need to add graceful shutdown of all channels and Runtime itself(how?)
// One example see https://github.com/rousan/AndroidWithRust/blob/master/app/src/main/rust/bridge/runtime/mod.rs
// Also we may need to use something similar to 'entry_opt_token_store'
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

*/

//-----------------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{AsyncResponse, EntryOtpTokenReply};

    #[test]
    fn test1() {
        let e = EntryOtpTokenReply::default();
        let m = AsyncResponse::EntryOtpToken(e);

        let r = serde_json::to_string_pretty(&m);

        println!("r is {}", r.unwrap());
    }
}
