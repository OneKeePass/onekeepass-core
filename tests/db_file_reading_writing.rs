mod common;
use onekeepass_core::db_service::{self, *};

// NOTE:
// At this time, these tests used as dev time help and are ignored for the public use.
// Later #[ignore] will be removed once removing dev specific tests

#[ignore]
#[test]
fn verify_read_db_file() {
    println!("Test is called");
    common::init_logging();
    common::init_key_main_store();
    //let r = load_kdbx("/Users/jeyasankar/Documents/OneKeePass/KP/Test1-KP254-Attachment.kdbx", "ss", None); //
    // let r = load_kdbx(
    //     "/Users/jeyasankar/Documents/OneKeePass/JeyFix/TJ-fixit.kdbx",
    //     Some("ss"),
    //     None,
    // );
    let db_key = "/Users/jeyasankar/Documents/OneKeePass/Testcsv.kdbx";
    // let db_key = "/Users/jeyasankar/Documents/OneKeePass/KP/KP-Database2.kdbx";
    let r = load_kdbx(db_key, Some("ss"), None);

    println!("load_kdbx is called r is  {}", r.is_ok());
    if r.is_err() {
        println!("load_kdbx is error is   {:?}", r);
    }

    let settings = db_service::get_db_settings(db_key).unwrap();

    let json_str = serde_json::to_string_pretty(&settings).unwrap();
    log::debug!("{}", json_str);
}

#[ignore]
#[test]
fn verify_read_write_db_file() {
    common::init_logging();
    common::init_key_main_store();
    let db_key = "/Users/jeyasankar/Documents/OneKeePass/Testcsv.kdbx";

    // Copy the kdbx file to a temp location and use that as db_key

    let r = load_kdbx(db_key, Some("ss"), None);

    if r.is_err() {
        println!("load_kdbx is error is   {:?}", r);
    }
    assert!(r.is_ok());

    // Add some changes to db
    let mut settings = db_service::get_db_settings(db_key).unwrap();

    let json_str = serde_json::to_string_pretty(&settings).unwrap();
    log::debug!("{}", json_str);

    settings.set_database_name("Changed");
    db_service::set_db_settings(db_key, settings).unwrap();

    // Save the chnages
    let _kdbx_saved = db_service::save_kdbx_with_backup(db_key, None, true).unwrap();
    assert!(true);

    // Read back and verify the changes

    let r = load_kdbx(db_key, Some("ss"), None);

    if r.is_err() {
        println!("2 load_kdbx is error is   {:?}", r);
    }
    assert!(r.is_ok());
}

#[ignore]
#[test]
fn verify_read_db_and_export_xml() {
    common::init_logging();
    common::init_key_main_store();

    // let db_key = "/Users/jeyasankar/Documents/OneKeePass/Test-Obj-del-OKP1.kdbx";
    let db_key = "/Users/jeyasankar/Documents/OneKeePass/Test-Obj-del-OKP1-CH1.kdbx";
    // let db_key = "/Users/jeyasankar/Documents/OneKeePass/MyOTP1-kp2.kdbx";
    // let db_key = "/Users/jeyasankar/Documents/OneKeePass/KP/KP-Database1.kdbx";
    let r = load_kdbx(db_key, Some("ss"), None);

    if r.is_err() {
        println!("load_kdbx is error is   {:?}", r);
    }

    assert!(r.is_ok());

    let r = db_service::export_as_xml(db_key, "Test1.xml");
    //println!("db_service::export_as_xml error is   {:?}", r);
    assert!(r.is_ok(), "db_service::export_as_xml error is   {:?}", r);

    println!("Xml is written");
}

#[ignore]
#[test]
fn verify_db_merge() {
    common::init_logging();
    common::init_key_main_store();

    let target_db_key = "/Users/jeyasankar/Documents/OneKeePass/TextXC1.kdbx";
    // let db_key = "/Users/jeyasankar/Documents/OneKeePass/MyOTP1-kp2.kdbx";
    let r = load_kdbx(target_db_key, Some("ss"), None);

    if r.is_err() {
        println!("load_kdbx is error is   {:?}", r);
    }

    assert!(r.is_ok());

    let source_db_key = "/Users/jeyasankar/Documents/OneKeePass/TextXC1-1.kdbx";
    // let db_key = "/Users/jeyasankar/Documents/OneKeePass/MyOTP1-kp2.kdbx";
    let r = load_kdbx(source_db_key, Some("ss"), None);

    if r.is_err() {
        println!("load_kdbx is error is   {:?}", r);
    }

    assert!(r.is_ok());

    // let target_db_key = "not found";

    db_service::merge_databases(target_db_key, source_db_key, Some("ss"), None).unwrap();

    assert!(true);
}

#[ignore]
#[test]
fn verify_read_save_as_db_file() {
    common::init_key_main_store();
    let db_key = "/Users/jeyasankar/Documents/OneKeePass/Test1-Auto.kdbx";
    let r = load_kdbx(&db_key, Some("ss"), None);
    assert!(r.is_ok());

    let database_file_name = "/Users/jeyasankar/Documents/OneKeePass/Test1-Auto-sa.kdbx";
    let wr = save_as_kdbx(db_key, database_file_name).unwrap();
    println!("Save As call is done {}", &wr.database_name);

    // Read back
    let r = load_kdbx(&database_file_name, Some("ss"), None);
    assert!(r.is_ok());
}

#[ignore]
#[test]
fn verify_entry_1() {
    // get_entry_form_data_by_id
    common::init();
    //let db_key = "/Users/jeyasankar/Documents/OneKeePass/JeyFix/TJ-fixit.kdbx";
    let db_key = "/Users/jeyasankar/Documents/OneKeePass/Test-OTP2.kdbx";

    let r = load_kdbx(db_key, Some("ss"), None);
    assert!(r.is_ok());

    //"3b8a5c10-3ec2-4afa-ab8b-e46aa43b1a18" or "3b8a5c103ec24afaab8be46aa43b1a18"
    let entry_uuid_str = "991c0ddc-2531-4ec1-96e2-580687d376da";
    let entry_uuid = uuid::Uuid::parse_str(entry_uuid_str).unwrap();

    let entry_form = get_entry_form_data_by_id(db_key, &entry_uuid);
    assert!(entry_form.is_ok());
    let entry_form = entry_form.unwrap();

    //println!("entry_form is {:?}",entry_form);
}
