use crate::db_content::Entry;
use crate::error::{Error, Result};
use log::error;
use regex::Regex;

/// A simple search that searches in all fields of an entry
/// Returns true if there is a case sensitive match of term in any part of a field
pub fn term_search_all_entry_fields(term: &str, entry: &Entry) -> Result<bool> {
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
}

#[cfg(test)]
mod tests {
    use crate::db_content::{Entry, FieldDataType, KeyValue};
    use crate::searcher::*;
    #[test]
    fn verify_simple_search() {
        let mut e = Entry::new();
        e.tags = "Banks;Money deposit;Tag3".into();
        // e.key_values.push(KeyValue {
        //     key: "Title".into(),
        //     value: "BOA".into(),
        //     protected: false,
        // });
        // e.key_values.push(KeyValue {
        //     key: "User Name".into(),
        //     value: "mainuser".into(),
        //     protected: false,
        // });
        // e.key_values.push(KeyValue {
        //     key: "Password".into(),
        //     value: "changeIt".into(),
        //     protected: true,
        // });
        // e.key_values.push(KeyValue {
        //     key: "Test Custom Key".into(),
        //     value: "Test Custom Value - Custom".into(),
        //     protected: false,
        // });
        // e.key_values.push(KeyValue {
        //     key: "Test Custom Key 2".into(),
        //     value: "Test Custom Value Protected".into(),
        //     protected: true,
        // });

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
        let found = term_search_all_entry_fields("boa".into(), &e).unwrap();
        assert_eq!(found, false);

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
}
