use crate::custom_icons::{CustomIconData, CustomIconSummary};
use crate::db_content::KeepassFile;
use crate::db_service::{
    call_kdbx_context_mut_action, call_main_content_action, call_main_content_mut_action,
    KdbxContext,
};
#[cfg(feature = "favicon")]
use crate::error::Error;
use crate::error::Result;
use crate::{main_content_action, main_content_mut_action, util};

// ======== Favicon download (feature-gated) ========

#[cfg(feature = "favicon")]
pub async fn download_and_add_custom_icon(db_key: &str, url: &str) -> Result<CustomIconSummary> {
    let png_bytes = crate::favicon::download_favicon(url).await?;
    let parsed = url::Url::parse(url).ok();
    let name = parsed
        .as_ref()
        .and_then(|u| u.host_str())
        .unwrap_or("")
        .to_string();
    let uuid_str = add_custom_icon(db_key, name, png_bytes)?;
    let summaries = list_custom_icons(db_key)?;
    summaries
        .into_iter()
        .find(|s| s.uuid == uuid_str)
        .ok_or_else(|| Error::NotFound("Newly added custom icon not found".into()))
}

#[cfg(feature = "favicon")]
pub fn normalize_image_to_png(input: &[u8]) -> Result<Vec<u8>> {
    crate::favicon::normalize_image_to_png(input, 64)
}

// ======== Custom icon CRUD public API ========

pub fn list_custom_icons(db_key: &str) -> Result<Vec<CustomIconSummary>> {
    main_content_action!(db_key, |k: &KeepassFile| {
        crate::custom_icons::list_custom_icons(k)
    })
}

pub fn get_custom_icon(db_key: &str, uuid: &str) -> Result<CustomIconData> {
    let uuid = uuid.to_string();
    main_content_action!(db_key, move |k: &KeepassFile| {
        crate::custom_icons::get_custom_icon(k, &uuid)
    })
}

pub fn add_custom_icon(db_key: &str, name: String, png_bytes: Vec<u8>) -> Result<String> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        crate::custom_icons::add_custom_icon(k, name.clone(), png_bytes.clone())
    })
}

pub fn remove_custom_icon(db_key: &str, uuid: &str) -> Result<()> {
    let uuid = uuid.to_string();
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        crate::custom_icons::remove_custom_icon(k, &uuid)
    })
}

pub fn set_entry_custom_icon(
    db_key: &str,
    entry_uuid: &str,
    custom_icon_uuid: Option<String>,
) -> Result<()> {
    let entry_uuid = entry_uuid.to_string();
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        crate::custom_icons::set_entry_custom_icon(k, &entry_uuid, custom_icon_uuid.clone())
    })
}

pub fn set_group_custom_icon(
    db_key: &str,
    group_uuid: &str,
    custom_icon_uuid: Option<String>,
) -> Result<()> {
    let group_uuid = group_uuid.to_string();
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        crate::custom_icons::set_group_custom_icon(k, &group_uuid, custom_icon_uuid.clone())
    })
}
