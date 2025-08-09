use serde::Deserialize;
use serde::Serialize;

use crate::constants::entry_keyvalue_key::TITLE;
use crate::constants::entry_keyvalue_key::URL;
use crate::db_content::KeepassFile;
use crate::db_service::call_kdbx_context_mut_action;
use crate::db_service::call_main_content_action;
use crate::db_service::KdbxContext;
use crate::error::Result;
use crate::form_data::parsing::EntryPlaceHolderParser;
use crate::form_data::EntrySummary;
use crate::util;

use url::Url;

// NOTE: To use this macro in this module, we need to import all fns that used in that macros as well to this module
use crate::main_content_action;

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct MatchedDbEntries {
    db_name: String,
    entry_summaries: Vec<EntrySummary>,
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

fn find_matching_entries_in_db(db_key: &str, input_url: &str) -> Result<MatchedDbEntries> {
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

                let matched = url_matched(input_url, entry_field_url);

                if !matched {
                    return None;
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
    }
}
