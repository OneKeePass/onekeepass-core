use crate::db_content::Entry;
use crate::error::{Error, Result};
use log::error;
use regex::Regex;

/// A simple search that searches in all fields of an entry
/// Returns true if there is a case sensitive match of term in any part of a field
pub fn term_search_all_entry_fields(term: &str, entry: &Entry) -> Result<bool> {
    search_term_with_options(term, true, entry)
}

// Searches the term with some regex options
// For now only case insensitive or case sensitive option is used to search all
// entry fields. Later we can use some advanced search options
// using 'SourceToSearch' and 'SearchOption' - See commented code below

pub fn search_term_with_options(term: &str, case_insensitive: bool, entry: &Entry) -> Result<bool> {
    if term.trim().is_empty() {
        return Ok(false);
    }

    // See https://docs.rs/regex/1.10.5/regex/#grouping-and-flags - case-insensitive flag explained there
    let modified_term = if case_insensitive {
        "(?i)".to_owned() + term
    } else {
        term.to_string()
    };

    // println!("Modified term to match is {}",&modified_term);

    let re = match Regex::new(&modified_term) {
        Ok(reg) => reg,
        Err(e) => {
            error!("{}", e);
            return Err(Error::RegexError(e));
        }
    };

    let matched = false
    // If there is a match in any of fields - title, user, password, url, notes, all custom fields..
    ||  entry.entry_field.get_key_values().iter().any( |k|  re.is_match(&k.value))
    // Check if there is any match in the tags
    || re.is_match(&entry.tags)
    // If there is a match in any attachment's name
    || entry.binary_key_values.iter().any( |k|  re.is_match(&k.key));

    Ok(matched)
}

#[cfg(test)]
mod tests {
    use crate::db_content::{Entry, FieldDataType, KeyValue};
    use crate::searcher::*;

    #[ignore]
    #[test]
    fn verify_simple_search() {
        let mut e = Entry::new();
        e.tags = "Banks;Money deposit;Tag3".into();

        e.entry_field.insert_key_value(KeyValue {
            key: "Title".into(),
            value: "BOA".into(),
            protected: false,
            data_type: FieldDataType::default(),
        });
        e.entry_field.insert_key_value(KeyValue {
            key: "User Name".into(),
            value: "mainuser".into(),
            protected: false,
            data_type: FieldDataType::default(),
        });
        e.entry_field.insert_key_value(KeyValue {
            key: "Password".into(),
            value: "changeIt".into(),
            protected: true,
            data_type: FieldDataType::default(),
        });
        e.entry_field.insert_key_value(KeyValue {
            key: "Test Custom Key".into(),
            value: "Test Custom Value - Custom".into(),
            protected: false,
            data_type: FieldDataType::default(),
        });
        e.entry_field.insert_key_value(KeyValue {
            key: "Test Custom Key 2".into(),
            value: "Test Custom Value Protected".into(),
            protected: true,
            data_type: FieldDataType::default(),
        });

        // Matches part of BOA
        let found = term_search_all_entry_fields("BO".into(), &e).unwrap();
        assert_eq!(found, true);

        // Casesensitive search and will not match any field
        // let found = term_search_all_entry_fields("boa".into(), &e).unwrap();
        // assert_eq!(found, false);

        // Matching in Tags field
        let found = term_search_all_entry_fields("Banks".into(), &e).unwrap();
        assert_eq!(found, true);

        let found = term_search_all_entry_fields(" ".into(), &e).unwrap();
        //println!("found is {}", found );
        assert_eq!(found, false);

        let found = term_search_all_entry_fields("user\\".into(), &e);
        assert_eq!(found.is_err(), true);
        if let Err(e) = found {
            println!("found is {}", e);
        }
    }

    #[ignore]
    #[test]
    fn verify_case_insensitive_search() {
        let mut e = Entry::new();
        e.tags = "Banks;Money deposit;Tag3".into();

        e.entry_field.insert_key_value(KeyValue {
            key: "Title".into(),
            value: "BOA".into(),
            protected: false,
            data_type: FieldDataType::default(),
        });
        e.entry_field.insert_key_value(KeyValue {
            key: "User Name".into(),
            value: "mainuser".into(),
            protected: false,
            data_type: FieldDataType::default(),
        });
        e.entry_field.insert_key_value(KeyValue {
            key: "Password".into(),
            value: "changeIt".into(),
            protected: true,
            data_type: FieldDataType::default(),
        });
        e.entry_field.insert_key_value(KeyValue {
            key: "Url".into(),
            value: "https://github.com/account".into(),
            protected: false,
            data_type: FieldDataType::default(),
        });
        e.entry_field.insert_key_value(KeyValue {
            key: "Test Custom Key".into(),
            value: "Test Custom Value - Custom".into(),
            protected: false,
            data_type: FieldDataType::default(),
        });
        e.entry_field.insert_key_value(KeyValue {
            key: "Test Custom Key 2".into(),
            value: "Test Custom Value Protected".into(),
            protected: true,
            data_type: FieldDataType::default(),
        });

        // Matches part of BOA
        let found = search_term_with_options("BO".into(), true, &e).unwrap();
        assert_eq!(found, true);

        // Matches part of BOA
        let found = search_term_with_options("bo".into(), true, &e).unwrap();
        assert_eq!(found, true);

        // Casesensitive search and will not match any field
        let found = search_term_with_options("boa".into(), false, &e).unwrap();
        assert_eq!(found, false);

        // Matching in Tags field - Cases Insensitive
        let found = search_term_with_options("Banks".into(), true, &e).unwrap();
        assert_eq!(found, true);
        //Matching in Tags field - Cases Insensitive
        let found = search_term_with_options("banks".into(), true, &e).unwrap();
        assert_eq!(found, true);

        // Password value changeIt - It part
        let found = search_term_with_options("it".into(), true, &e).unwrap();
        //println!("found is {}", found );
        assert_eq!(found, true);

        // Url
        let found = search_term_with_options("Github.com".into(), true, &e).unwrap();
        //println!("found is {}", found );
        assert_eq!(found, true);

        // Url
        let found = search_term_with_options("Github.com".into(), false, &e).unwrap();
        //println!("found is {}", found );
        assert_eq!(found, false);

        // Url
        let found = search_term_with_options("https://github.com/login".into(), true, &e).unwrap();
        //println!("found is {}", found );
        assert_eq!(found, true);

        // Empty term is not matched for anything
        let found = search_term_with_options(" ".into(), true, &e).unwrap();
        assert_eq!(found, false);

        // let found = term_search_all_entry_fields("user\\".into(), &e);
        // assert_eq!(found.is_err(), true);
        // if let Err(e) = found {
        //     println!("found is {}", e);
        // }
    }

    #[ignore]
    #[test]
    fn test1() {
        let term = "(?i)Github"; //"https://github.com/login"

        let re = Regex::new(&term).unwrap();

        let s = "https://github.com/login";

        let m = re.is_match(&s);

        println!("m is {}", m);
    }

    // --- Non-ignored unit tests ---

    fn make_test_entry() -> Entry {
        let mut e = Entry::new();
        e.tags = "Banks;Finance".into();
        e.entry_field.insert_key_value(KeyValue {
            key: "Title".into(),
            value: "MyBank".into(),
            protected: false,
            data_type: FieldDataType::default(),
        });
        e.entry_field.insert_key_value(KeyValue {
            key: "UserName".into(),
            value: "alice".into(),
            protected: false,
            data_type: FieldDataType::default(),
        });
        e.entry_field.insert_key_value(KeyValue {
            key: "Password".into(),
            value: "Secr3t!".into(),
            protected: true,
            data_type: FieldDataType::default(),
        });
        e.entry_field.insert_key_value(KeyValue {
            key: "URL".into(),
            value: "https://mybank.com".into(),
            protected: false,
            data_type: FieldDataType::default(),
        });
        e
    }

    #[test]
    fn search_matches_title_case_insensitive() {
        let e = make_test_entry();
        assert!(search_term_with_options("mybank", true, &e).unwrap());
        assert!(search_term_with_options("MYBANK", true, &e).unwrap());
    }

    #[test]
    fn search_does_not_match_title_wrong_case_sensitive() {
        let e = make_test_entry();
        // "MyBank" matches exactly (case-sensitive)
        assert!(search_term_with_options("MyBank", false, &e).unwrap());
        // "ALICE" does not match "alice" when case-sensitive
        assert!(!search_term_with_options("ALICE", false, &e).unwrap());
    }

    #[test]
    fn search_matches_tag_case_insensitive() {
        let e = make_test_entry();
        assert!(search_term_with_options("Banks", true, &e).unwrap());
        assert!(search_term_with_options("finance", true, &e).unwrap());
    }

    #[test]
    fn search_matches_protected_password_field() {
        let e = make_test_entry();
        assert!(search_term_with_options("Secr3t", true, &e).unwrap());
    }

    #[test]
    fn search_matches_url_field() {
        let e = make_test_entry();
        assert!(search_term_with_options("mybank.com", true, &e).unwrap());
    }

    #[test]
    fn search_empty_term_returns_false() {
        let e = make_test_entry();
        assert!(!search_term_with_options("", true, &e).unwrap());
    }

    #[test]
    fn search_whitespace_only_returns_false() {
        let e = make_test_entry();
        assert!(!search_term_with_options("   ", true, &e).unwrap());
    }

    #[test]
    fn search_no_match_returns_false() {
        let e = make_test_entry();
        assert!(!search_term_with_options("xyznonexistent", true, &e).unwrap());
    }

    #[test]
    fn search_invalid_regex_returns_error() {
        let e = make_test_entry();
        let result = search_term_with_options("user\\", true, &e);
        assert!(result.is_err());
    }

    #[test]
    fn search_matches_attachment_name() {
        use crate::db_content::BinaryKeyValue;
        let mut e = Entry::new();
        e.binary_key_values.push(BinaryKeyValue {
            key: "resume.pdf".into(),
            value: String::default(),
            index_ref: 0,
            data_hash: 0,
            data_size: 0,
        });
        assert!(search_term_with_options("resume", true, &e).unwrap());
        assert!(!search_term_with_options("cover_letter", true, &e).unwrap());
    }

    #[test]
    fn term_search_all_entry_fields_is_case_insensitive() {
        let e = make_test_entry();
        assert!(term_search_all_entry_fields("mybank", &e).unwrap());
        assert!(term_search_all_entry_fields("ALICE", &e).unwrap());
    }
}

// #[derive(Serialize, Deserialize)]
// pub enum SourceToSearch {
//     //AllEntryInfo,
//     EntryTitle,
//     UserName,
//     Password,
//     Url,
//     Notes,
//     Tags,
//     CustomFields,
//     GroupName,
//     GroupTag,
// }

// impl SourceToSearch {
//     fn all_entry_info() -> Vec<SourceToSearch> {
//         vec![Self::EntryTitle,Self::UserName,Self::Password,]
//     }
// }

// #[derive(Serialize, Deserialize)]
// pub struct SearchOption {
//     case_sensitive:bool,
//     include_history_entries:bool,
//     include_deleted_entries:bool,
//     sources_to_search:Vec<SourceToSearch>,
// }

//pub fn search_term_with_options(term: &str, search_option:SearchOption,entry: &Entry,group:&Group) -> Result<bool> {
