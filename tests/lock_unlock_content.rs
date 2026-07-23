mod common;

use std::io::Read;

use onekeepass_core::db_service::{self, *};

fn temp_path(name: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(name);
    p.to_str().unwrap().to_string()
}

// Builds a NewDatabase via serde (fields are pub(crate)) starting from Default so
// kdf/cipher_id get valid defaults, then injects the file path + password.
fn make_new_db(db_key: &str, password: &str) -> NewDatabase {
    let mut v = serde_json::to_value(NewDatabase::default()).unwrap();
    v["database_name"] = serde_json::json!("LockTest");
    v["database_file_name"] = serde_json::json!(db_key);
    v["password"] = serde_json::json!(password);
    serde_json::from_value(v).unwrap()
}

// Memory-security lock: verify that lock_kdbx encrypts + removes the
// decrypted content AND attachment bytes from RAM, and that both unlock paths
// (credential + biometric) faithfully restore them.
#[test]
fn lock_unlock_content_round_trip() {
    common::init();

    let db_key = temp_path("okp_lock_test.kdbx");
    let _ = std::fs::remove_file(&db_key);

    let password = "test-pass-1234";
    let created = create_kdbx(make_new_db(&db_key, password));
    assert!(created.is_ok(), "create_kdbx failed: {:?}", created);

    // Add an attachment with known bytes.
    let attach_src = temp_path("okp_attach_src.bin");
    let attach_bytes: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    std::fs::write(&attach_src, &attach_bytes).unwrap();
    let info = db_service::upload_entry_attachment(&db_key, &attach_src).unwrap();
    let data_hash = info.data_hash;

    // Baseline: content is present and readable.
    let baseline = serde_json::to_string(&db_service::get_db_settings(&db_key).unwrap()).unwrap();
    assert!(!db_service::is_db_locked(&db_key).unwrap());

    // --- Lock: content must be encrypted and removed from RAM ---
    db_service::lock_kdbx(&db_key).unwrap();
    assert!(db_service::is_db_locked(&db_key).unwrap(), "should be locked");
    assert!(
        db_service::get_db_settings(&db_key).is_err(),
        "content must be gone from RAM while locked"
    );
    // lock again is idempotent
    db_service::lock_kdbx(&db_key).unwrap();

    // --- Unlock via credentials: wrong password stays locked ---
    assert!(
        db_service::unlock_kdbx(&db_key, Some("wrong"), None).is_err(),
        "wrong password should fail"
    );
    assert!(
        db_service::is_db_locked(&db_key).unwrap(),
        "still locked after a failed unlock"
    );

    // --- Unlock via credentials: correct password restores content ---
    db_service::unlock_kdbx(&db_key, Some(password), None).unwrap();
    assert!(!db_service::is_db_locked(&db_key).unwrap(), "should be unlocked");
    let after_cred = serde_json::to_string(&db_service::get_db_settings(&db_key).unwrap()).unwrap();
    assert_eq!(baseline, after_cred, "content changed across credential lock/unlock");

    // Attachment bytes must survive the credential lock/unlock.
    assert_eq!(
        read_attachment(&db_key, &data_hash),
        attach_bytes,
        "attachment bytes changed across credential lock/unlock"
    );

    // --- Unlock via the biometric path restores content + attachments too ---
    db_service::lock_kdbx(&db_key).unwrap();
    assert!(db_service::get_db_settings(&db_key).is_err());
    db_service::unlock_kdbx_on_biometric_authentication(&db_key).unwrap();
    assert!(!db_service::is_db_locked(&db_key).unwrap());
    let after_bio = serde_json::to_string(&db_service::get_db_settings(&db_key).unwrap()).unwrap();
    assert_eq!(baseline, after_bio, "content changed across biometric lock/unlock");
    assert_eq!(
        read_attachment(&db_key, &data_hash),
        attach_bytes,
        "attachment bytes changed across biometric lock/unlock"
    );

    // Cleanup
    let _ = db_service::close_kdbx(&db_key);
    let _ = std::fs::remove_file(&db_key);
    let _ = std::fs::remove_file(&attach_src);
}

// Reads an attachment's bytes back by writing it to a temp file (the public path).
fn read_attachment(db_key: &str, data_hash: &u64) -> Vec<u8> {
    let out = db_service::save_attachment_as_temp_file(db_key, "okp_attach_out.bin", data_hash)
        .unwrap();
    let mut f = std::fs::File::open(&out).unwrap();
    let mut buf = vec![];
    f.read_to_end(&mut buf).unwrap();
    let _ = std::fs::remove_file(&out);
    buf
}
