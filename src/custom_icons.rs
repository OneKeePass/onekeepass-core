use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto;
use crate::db_content::{Icon, KeepassFile};
use crate::error::{Error, Result};
use crate::util;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CustomIconSummary {
    pub uuid: String,
    pub name: String,
    pub last_modification_time: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CustomIconData {
    pub uuid: String,
    pub name: String,
    pub data: Vec<u8>,
}

pub(crate) fn list_custom_icons(k: &KeepassFile) -> Result<Vec<CustomIconSummary>> {
    let summaries = k
        .meta
        .custom_icons
        .icons
        .iter()
        .map(|icon| CustomIconSummary {
            uuid: icon.uuid.to_string(),
            name: icon.name.clone().unwrap_or_default(),
            last_modification_time: icon
                .last_modification_time
                .format("%Y-%m-%dT%H:%M:%S")
                .to_string(),
        })
        .collect();
    Ok(summaries)
}

pub(crate) fn get_custom_icon(k: &KeepassFile, uuid: &str) -> Result<CustomIconData> {
    let icon_uuid = Uuid::parse_str(uuid)?;
    k.meta
        .custom_icons
        .icons
        .iter()
        .find(|i| i.uuid == icon_uuid)
        .map(|icon| CustomIconData {
            uuid: icon.uuid.to_string(),
            name: icon.name.clone().unwrap_or_default(),
            data: icon.data.clone(),
        })
        .ok_or_else(|| Error::NotFound(format!("Custom icon {} not found", uuid)))
}

pub(crate) fn add_custom_icon(
    k: &mut KeepassFile,
    name: String,
    png_bytes: Vec<u8>,
) -> Result<String> {
    // Content-addressable dedup: if an existing icon's bytes match what we're
    // adding, return its uuid instead of inserting a byte-identical duplicate.
    // The length pre-check skips hashing for the (overwhelmingly common) case
    // where lengths differ — PNG-encoded sizes vary with content.
    let new_len = png_bytes.len();
    let new_hash = crypto::sha256_hash_from_slice(&png_bytes)?;
    for existing in &k.meta.custom_icons.icons {
        if existing.data.len() != new_len {
            continue;
        }
        if crypto::sha256_hash_from_slice(&existing.data)? == new_hash {
            return Ok(existing.uuid.to_string());
        }
    }

    let icon = Icon {
        uuid: Uuid::new_v4(),
        data: png_bytes,
        name: if name.is_empty() { None } else { Some(name) },
        last_modification_time: util::now_utc(),
    };
    let uuid_str = icon.uuid.to_string();
    k.meta.custom_icons.icons.push(icon);
    Ok(uuid_str)
}

pub(crate) fn remove_custom_icon(k: &mut KeepassFile, uuid: &str) -> Result<()> {
    let icon_uuid = Uuid::parse_str(uuid)?;
    let before = k.meta.custom_icons.icons.len();
    k.meta.custom_icons.icons.retain(|i| i.uuid != icon_uuid);
    if k.meta.custom_icons.icons.len() == before {
        return Err(Error::NotFound(format!("Custom icon {} not found", uuid)));
    }
    k.root.clear_custom_icon_uuid(&icon_uuid);
    Ok(())
}

pub(crate) fn set_entry_custom_icon(
    k: &mut KeepassFile,
    entry_uuid: &str,
    custom_icon_uuid: Option<String>,
) -> Result<()> {
    let entry_uuid = Uuid::parse_str(entry_uuid)?;
    let icon_uuid = custom_icon_uuid
        .as_deref()
        .map(Uuid::parse_str)
        .transpose()?;
    match k.root.entry_by_id_mut(&entry_uuid) {
        Some(entry) => {
            entry.custom_icon_uuid = icon_uuid;
            Ok(())
        }
        None => Err(Error::NotFound(format!("Entry {} not found", entry_uuid))),
    }
}

pub(crate) fn set_group_custom_icon(
    k: &mut KeepassFile,
    group_uuid: &str,
    custom_icon_uuid: Option<String>,
) -> Result<()> {
    let group_uuid = Uuid::parse_str(group_uuid)?;
    let icon_uuid = custom_icon_uuid
        .as_deref()
        .map(Uuid::parse_str)
        .transpose()?;
    match k.root.group_by_id_mut(&group_uuid) {
        Some(group) => {
            group.custom_icon_uuid = icon_uuid;
            Ok(())
        }
        None => Err(Error::NotFound(format!("Group {} not found", group_uuid))),
    }
}
