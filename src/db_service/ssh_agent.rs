use uuid::Uuid;

use crate::constants::{entry_keyvalue_key, entry_type_uuid};
use crate::db_content::{AttachmentHashValue, KeepassFile};
use crate::db_service::{all_kdbx_cache_keys, call_kdbx_context_action, call_main_content_action};
use crate::error::Result;

// A decrypted SSH key drawn from an SSH_KEY entry that has "Add to SSH Agent"
// turned on. This is the only data the desktop SSH agent service needs in order
// to advertise an identity and sign with it.
//
// SECURITY: this struct carries cleartext private-key material (`private_key_pem`
// and `passphrase`) which is decrypted in-memory by the kdbx reader. It is
// intentionally NOT `Serialize`/`Debug` so it can never be sent to the UI layer
// or written to a log. The consuming agent module is responsible for decoding it
// into a signer and zeroizing the material when a database is locked or closed.
#[derive(Clone)]
pub struct SshAgentKeySource {
    pub db_key: String,
    pub entry_uuid: Uuid,
    // Entry title, used as the agent identity "comment".
    pub title: String,
    // Stored "Public Key" field. Used only to validate the key the agent derives
    // from the private key; the advertised public key is always derived.
    pub public_key: Option<String>,
    // OpenSSH-format private key text (the "Private Key" protected field).
    pub private_key_pem: String,
    // Optional passphrase for an encrypted private key.
    pub passphrase: Option<String>,
    // When true, each sign request for this key must be user-confirmed.
    pub require_confirmation: bool,
    // "Agent Lifetime": a whole number of seconds chosen from the entry form's
    // duration picker. After this many seconds the desktop agent stops serving
    // the key (parsed + enforced in the agent's store, from key-load time).
    // Empty/absent means the key never expires.
    pub agent_lifetime: Option<String>,
}

struct SshAgentKeyCandidate {
    db_key: String,
    entry_uuid: Uuid,
    title: String,
    public_key: Option<String>,
    private_key_pem: Option<String>,
    private_key_attachment: Option<(String, AttachmentHashValue)>,
    passphrase: Option<String>,
    require_confirmation: bool,
    agent_lifetime: Option<String>,
}

fn ssh_key_type_uuid() -> Uuid {
    crate::build_uuid!(entry_type_uuid::SSH_KEY)
}

// KeePass Bool fields are stored as a string ("true"/"True"). Treat anything that
// is not an affirmative value as disabled.
fn is_truthy(value: &str) -> bool {
    matches!(value.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes")
}

// Returns the trimmed value of a field, or None when absent or empty.
fn non_empty_field(
    entry: &crate::db_content::Entry,
    name: &str,
) -> Option<String> {
    entry
        .entry_field
        .find_key_value(name)
        .map(|kv| kv.value.clone())
        .filter(|v| !v.trim().is_empty())
}

fn collect_from_db(db_key: &str, k: &KeepassFile, out: &mut Vec<SshAgentKeyCandidate>) {
    let target_type = ssh_key_type_uuid();
    // Active entries only — a key moved to the recycle bin must not be served.
    for entry in k.collect_all_active_entries() {
        if entry.entry_field.entry_type.uuid != target_type {
            continue;
        }

        // Only serve entries explicitly opted into the agent.
        let enabled = entry
            .entry_field
            .find_key_value(entry_keyvalue_key::ADD_TO_SSH_AGENT)
            .map(|kv| is_truthy(&kv.value))
            .unwrap_or(false);
        if !enabled {
            continue;
        }

        let require_confirmation = entry
            .entry_field
            .find_key_value(entry_keyvalue_key::REQUIRE_CONFIRMATION)
            .map(|kv| is_truthy(&kv.value))
            .unwrap_or(false);

        out.push(SshAgentKeyCandidate {
            db_key: db_key.to_string(),
            entry_uuid: entry.get_uuid(),
            title: non_empty_field(entry, entry_keyvalue_key::TITLE).unwrap_or_default(),
            public_key: non_empty_field(entry, entry_keyvalue_key::PUBLIC_KEY),
            private_key_pem: non_empty_field(entry, entry_keyvalue_key::PRIVATE_KEY),
            private_key_attachment: entry
                .binary_key_values
                .first()
                .map(|bkv| (bkv.key.clone(), bkv.data_hash)),
            passphrase: non_empty_field(entry, entry_keyvalue_key::PASSWORD),
            require_confirmation,
            agent_lifetime: non_empty_field(entry, entry_keyvalue_key::AGENT_LIFETIME),
        });
    }
}

fn attachment_private_key_pem(
    db_key: &str,
    entry_title: &str,
    attachment_name: &str,
    data_hash: &AttachmentHashValue,
) -> Option<String> {
    let bytes = call_kdbx_context_action(db_key, |ctx| {
        Ok(ctx.kdbx_file.get_bytes_content(data_hash))
    });

    match bytes {
        Ok(Some(bytes)) => match String::from_utf8(bytes) {
            Ok(s) if !s.trim().is_empty() => {
                log::debug!(
                    "SSH agent: using private key attachment '{}' for SSH Key entry '{}'",
                    attachment_name,
                    entry_title
                );
                Some(s)
            }
            Ok(_) => {
                log::warn!(
                    "SSH agent: private key attachment '{}' for SSH Key entry '{}' is empty",
                    attachment_name,
                    entry_title
                );
                None
            }
            Err(_) => {
                log::warn!(
                    "SSH agent: private key attachment '{}' for SSH Key entry '{}' is not valid UTF-8; skipping",
                    attachment_name,
                    entry_title
                );
                None
            }
        },
        Ok(None) => {
            log::warn!(
                "SSH agent: private key attachment '{}' for SSH Key entry '{}' was not found",
                attachment_name,
                entry_title
            );
            None
        }
        Err(e) => {
            log::warn!(
                "SSH agent: failed to read private key attachment '{}' for SSH Key entry '{}': {}",
                attachment_name,
                entry_title,
                e
            );
            None
        }
    }
}

fn resolve_candidate(candidate: SshAgentKeyCandidate) -> Option<SshAgentKeySource> {
    let private_key_pem = if let Some(private_key_pem) = candidate.private_key_pem {
        private_key_pem
    } else if let Some((name, data_hash)) = candidate.private_key_attachment.as_ref() {
        attachment_private_key_pem(&candidate.db_key, &candidate.title, name, data_hash)?
    } else {
        log::debug!(
            "SSH agent: skipping SSH Key entry '{}' because it has neither a Private Key field nor an attachment",
            candidate.title
        );
        return None;
    };

    Some(SshAgentKeySource {
        db_key: candidate.db_key,
        entry_uuid: candidate.entry_uuid,
        title: candidate.title,
        public_key: candidate.public_key,
        private_key_pem,
        passphrase: candidate.passphrase,
        require_confirmation: candidate.require_confirmation,
        agent_lifetime: candidate.agent_lifetime,
    })
}

fn collect_sources_for_db(db_key: &str) -> Vec<SshAgentKeySource> {
    let key = db_key.to_string();
    let collected: Result<Vec<SshAgentKeyCandidate>> =
        call_main_content_action(db_key, move |k: &KeepassFile| {
            let mut local = Vec::new();
            collect_from_db(&key, k, &mut local);
            Ok(local)
        });

    collected
        .unwrap_or_default()
        .into_iter()
        .filter_map(resolve_candidate)
        .collect()
}

// Enumerates every agent-enabled SSH_KEY entry across all currently open kdbx
// databases. The desktop agent service calls this to (re)build its key store.
pub fn list_ssh_agent_key_sources() -> Vec<SshAgentKeySource> {
    let mut out: Vec<SshAgentKeySource> = Vec::new();
    for db_key in all_kdbx_cache_keys().unwrap_or_default() {
        out.extend(collect_sources_for_db(&db_key));
    }
    out
}

// Same as `list_ssh_agent_key_sources` but limited to a single database. Used by
// the lock/unlock/open hooks to refresh just that db's slice of the key store.
pub fn ssh_agent_key_sources_for_db(db_key: &str) -> Vec<SshAgentKeySource> {
    collect_sources_for_db(db_key)
}
