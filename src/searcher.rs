
use crate::db_content::Entry;
use crate::error::{Error, Result};
use log::error;
use regex::Regex;

/// A simple search that searches in all fields of an entry
/// Returns true if there is a case sensitive match of term in any part of a field
pub fn term_search_all_entry_fields(term: &str, entry: &Entry) -> Result<bool> {

    search_term_with_options(term,true,entry)
    /*
    // TODO: May need to form regular expression to make sure term is not a empty string
    if term.trim().is_empty() {
        return Ok(false);
    }
    let re = match Regex::new(term) {
        Ok(reg) => reg,
        Err(e) => {
            error!("{}", e);
            return Err(Error::RegexError(e));
        }
    };

    //||  entry.key_values.iter().any( |k|  re.is_match(&k.value))

    // Check if there is any match in the tags
    let matched = re.is_match(&entry.tags)
    // If there is a match in any of fields - title, user, password, url, notes, all custom fields..
    ||  entry.entry_field.get_key_values().iter().any( |k|  re.is_match(&k.value))
    // If there is a match in any attachment's name
    || entry.binary_key_values.iter().any( |k|  re.is_match(&k.key));

    Ok(matched)
     */
}

// Searches the term with some regex options
// For now only case insensitive or case sensitive option is used to search all 
// entry fields. Later we can use some advanced search options 
// using 'SourceToSearch' and 'SearchOption' - See commented code below

pub fn search_term_with_options(term: &str, case_insensitive:bool,entry: &Entry) -> Result<bool> {

    if term.trim().is_empty() {
        return Ok(false);
    }
    
    // See https://docs.rs/regex/1.10.5/regex/#grouping-and-flags - case-insensitive flag explained there
    let modified_term = if case_insensitive {
        "(?i)".to_owned()+term 
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
        let found = search_term_with_options("BO".into(),true, &e).unwrap();
        assert_eq!(found, true);

        // Matches part of BOA
        let found = search_term_with_options("bo".into(),true, &e).unwrap();
        assert_eq!(found, true);

        // Casesensitive search and will not match any field
        let found = search_term_with_options("boa".into(),false, &e).unwrap();
        assert_eq!(found, false);

        // Matching in Tags field - Cases Insensitive
        let found = search_term_with_options("Banks".into(),true, &e).unwrap();
        assert_eq!(found, true);
        //Matching in Tags field - Cases Insensitive
        let found = search_term_with_options("banks".into(),true, &e).unwrap();
        assert_eq!(found, true);

        // Password value changeIt - It part
        let found = search_term_with_options("it".into(),true,&e).unwrap();
        //println!("found is {}", found );
        assert_eq!(found, true);

        // Url
        let found = search_term_with_options("Github.com".into(),true,&e).unwrap();
        //println!("found is {}", found );
        assert_eq!(found, true);

        // Url
        let found = search_term_with_options("Github.com".into(),false,&e).unwrap();
        //println!("found is {}", found );
        assert_eq!(found, false);

        // Url
        let found = search_term_with_options("https://github.com/login".into(),true,&e).unwrap();
        //println!("found is {}", found );
        assert_eq!(found, true);


        // Empty term is not matched for anything
        let found = search_term_with_options(" ".into(),true, &e).unwrap();
        assert_eq!(found, false);

        // let found = term_search_all_entry_fields("user\\".into(), &e);
        // assert_eq!(found.is_err(), true);
        // if let Err(e) = found {
        //     println!("found is {}", e);
        // }
    }


    #[test]
    fn test1() {
        let term = "(?i)Github"; //"https://github.com/login"
        

        let re = Regex::new(&term).unwrap();


        let s = "https://github.com/login";

        let m = re.is_match(&s);

        println!( "m is {}", m);

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

