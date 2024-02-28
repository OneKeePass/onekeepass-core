mod common;
use onekeepass_core::db_service::*;

#[test]
fn verify_read_db_file() {
    println!("Test is called");
    common::init_logging();
    common::init_key_main_store();
    //let r = load_kdbx("/Users/jeyasankar/Documents/OneKeePass/KP/Test1-KP254-Attachment.kdbx", "ss", None); //
    let r = load_kdbx(
        "/Users/jeyasankar/Documents/OneKeePass/JeyFix/TJ-fixit.kdbx",
        Some("ss"),
        None,
    );
    //let r = load_kdbx("/Users/jeyasankar/Documents/OneKeePass/Test-OTP1.kdbx", Some("ss"), None);

    println!("load_kdbx is called r is  {}", r.is_ok());
    if r.is_err() {
        println!("load_kdbx is error is   {:?}", r);
    }
}

#[test]
fn verify_entry_1() {
    // get_entry_form_data_by_id
    common::init();
    let db_key = "/Users/jeyasankar/Documents/OneKeePass/JeyFix/TJ-fixit.kdbx";
    let r = load_kdbx(db_key, Some("ss"), None);
    assert!(r.is_ok());
    let entry_uuid_str = "3b8a5c10-3ec2-4afa-ab8b-e46aa43b1a18";
    let entry_uuid = uuid::Uuid::parse_str(entry_uuid_str).unwrap();
    
    let entry_form = get_entry_form_data_by_id(db_key, &entry_uuid);
    assert!(entry_form.is_ok());
    let entry_form = entry_form.unwrap();

    //println!("entry_form is {:?}",entry_form);

    
}

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
