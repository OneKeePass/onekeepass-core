use serde::Serialize;
use uuid::Uuid;

use crate::constants::entry_keyvalue_key::ADDITIONAL_URLS;
use crate::constants::entry_keyvalue_key::PASSWORD;
use crate::constants::entry_keyvalue_key::TITLE;
use crate::constants::entry_keyvalue_key::URL;
use crate::constants::entry_keyvalue_key::USER_NAME;
use crate::db_content::KeepassFile;
use crate::db_service::call_kdbx_context_mut_action;
use crate::db_service::call_main_content_action;
use crate::db_service::KdbxContext;
use crate::error::Error;
use crate::error::Result;
use crate::form_data::parsing::EntryPlaceHolderParser;
use crate::form_data::EntrySummary;
use crate::util;

use url::Url;

// NOTE: To use this macro in this module, we need to import all fns that used in that macros as well to this module
use crate::main_content_action;

#[derive(Default, Serialize, Debug)]
pub struct MatchedDbEntries {
    db_name: String,
    db_key: String,
    entry_summaries: Vec<EntrySummary>,
}

#[derive(Default, Serialize, Debug)]
pub struct BasicEntryCredentialInfo {
    username: Option<String>,
    password: Option<String>,
}

pub fn find_matching_in_enabled_db_entries(
    enabled_db_keys: &Vec<String>,
    input_url: &str,
) -> Result<Vec<MatchedDbEntries>> {
    Ok(enabled_db_keys
        .iter()
        .filter_map(|db_key| {
            let r = find_matching_entries_in_db(db_key, input_url).ok();
            r
        })
        .collect::<Vec<_>>())
}

// For now we retreive only the username and password for browser extension use
pub fn basic_entry_credential_info(
    db_key: &str,
    entry_uuid: &Uuid,
) -> Result<BasicEntryCredentialInfo> {
    let action = |k: &KeepassFile| match k.root.entry_by_id(entry_uuid) {
        Some(e) => {
            let info = BasicEntryCredentialInfo {
                username: e.find_kv_field_value(USER_NAME).clone(),
                password: e.find_kv_field_value(PASSWORD).clone(),
            };
            Ok(info)
        }
        None => Err(Error::NotFound(format!(
            "No entry is found for the id {}",
            entry_uuid
        ))),
    };

    main_content_action!(db_key, action)
}

fn any_additional_urls_matching(input_url: &str, additional_urls: &str) -> bool {
    let urls: Vec<&str> = additional_urls.split_whitespace().collect();
    urls.iter().any(|au| url_matched(input_url, au))
}

fn find_matching_entries_in_db(db_key: &str, input_url: &str) -> Result<MatchedDbEntries> {
    // log::debug!("find_matching_entries_in_db Going to find match for input_url {}",&input_url);
    let action = |k: &KeepassFile| {
        let entries = k.collect_all_active_entries();
        let db_name = k.meta.database_name().clone();
        let entry_summaries = entries
            .iter()
            .filter_map(|e| {
                let (parsed_fields, entry_fields) =
                    EntryPlaceHolderParser::place_holder_resolved_entry_fields(&k.root, e);

                let Some(entry_field_url) = entry_fields.get(URL) else {
                    return None;
                };

                let entry_field_url_matched = url_matched(input_url, entry_field_url);

                // log::debug!("find_matching_entries_in_db Finding matching for the entry_field_url {} and matched? {} ",&entry_field_url,&matched);

                if !entry_field_url_matched {
                    // Check the additional urls if any
                    let matched = if let Some(urls) = entry_fields.get(ADDITIONAL_URLS) {
                        any_additional_urls_matching(input_url, urls)
                    } else {
                        entry_field_url_matched
                    };

                    // The final matched flag should be true to consider
                    if !matched {
                        // No match either with entry url or with additional url 
                        return None;
                    }
                }

                let title = entry_fields.get(TITLE).cloned();
                let secondary_title = EntrySummary::secondary_title(e, &parsed_fields);

                Some(EntrySummary {
                    uuid: e.uuid.to_string(),
                    parent_group_uuid: e.parent_group_uuid(),
                    title,
                    secondary_title,
                    icon_id: e.icon_id,
                    history_index: None,
                    modified_time: Some(e.times.last_modification_time.and_utc().timestamp()),
                    created_time: Some(e.times.creation_time.and_utc().timestamp()),
                })
            })
            .collect::<Vec<EntrySummary>>();
        let matched_db_entries = MatchedDbEntries {
            db_name,
            db_key: db_key.to_string(),
            entry_summaries,
        };
        Ok(matched_db_entries)
    };

    main_content_action!(db_key, action)
}

fn url_matched(input: &str, entry_field_val: &str) -> bool {
    let Ok(input_url) = Url::parse(input) else {
        return false;
    };

    let Ok(entry_url) = Url::parse(entry_field_val) else {
        return false;
    };


    // log::debug!("entry_url.scheme {:?}, entry_url.domain {:?}, entry_url.path {}",entry_url.scheme(),entry_url.domain(),entry_url.path() );

    input_url.scheme() == entry_url.scheme()
        && input_url.domain() == entry_url.domain()
        && input_url.path() == entry_url.path()
}

#[cfg(test)]
mod tests {
    use crate::db_service::browser_extension::url_matched;
    #[ignore]
    #[test]
    fn verify_url_matching() {
        let r = url_matched(
            "https://gemini.google.com/app/",
            "https://gemini.google.com/app/",
        );
        println!("r is {}", r);

        let r = url_matched(
            "https://gemini.google.com/app/",
            "https://gemini.google.com/app",
        );
        println!("r2 is {}", r);
    }
}


/*

fn main() {
    let text = "apple banana cherry";
    let fruits: Vec<&str> = text.split_whitespace().collect();
    println!("{:?}", fruits); // Output: ["apple", "banana", "cherry"]
}


fn main() {
    let text = "apple\tbanana\ncherry";
    let fruits: Vec<&str> = text.split(|c: char| c.is_whitespace()).collect();
    println!("{:?}", fruits); // Output: ["apple", "banana", "cherry"]
}

*/