// Pure cryptographic operations for WebAuthn passkey registration and authentication.
//
// Compiled on all platforms (desktop, iOS, Android) — no `#[cfg]` gate.
// All private-key material stays inside this module (and the KDBX database).
//
// Supported COSE algorithms:
//   -7   ES256  — ECDSA P-256 with SHA-256   (existing)
//   -8   EdDSA  — Ed25519                    (added)
//   -257 RS256  — RSASSA-PKCS1-v1.5 / RSA-2048 with SHA-256 (added)
//
// Botan is the default backend for key generation, PEM handling, signing and randomness.
// The 'rustcrypto-passkey' feature switches back to the RustCrypto crates (p256,
// ed25519-dalek, rsa, rand_core). Both backends read and write the same PKCS#8 PEM, so
// passkeys stored by either one keep working with the other; see the comparison tests

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

#[cfg(not(feature = "rustcrypto-passkey"))]
use botan_backend as backend;
#[cfg(feature = "rustcrypto-passkey")]
use rustcrypto_backend as backend;

// ── Option structs (parsed subsets of the W3C JSON shapes) ──────────────────

#[derive(Debug, Deserialize)]
struct RpInfo {
    id: String,
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserInfo {
    id: String, // base64url-encoded bytes
    name: String,
    #[allow(dead_code)] // Retained for reference.
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PubKeyCredParam {
    alg: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreationOptions {
    rp: RpInfo,
    user: UserInfo,
    challenge: String, // base64url
    #[serde(default)]
    pub_key_cred_params: Vec<PubKeyCredParam>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AllowCredential {
    #[allow(dead_code)] // Retained for reference.
    id: String, // base64url
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestOptions {
    rp_id: Option<String>,
    challenge: String, // base64url
    #[serde(default)]
    #[allow(dead_code)] // Retained for reference.
    allow_credentials: Vec<AllowCredential>,
}

// ── Result structs ────────────────────────────────────────────────────────────

// Everything the caller needs to (a) return a credential to the website and
// (b) persist the key material in KDBX.
#[derive(Debug)]
pub struct PasskeyCreationResult {
    // JSON to return to the browser/site via `completeCreateRequest`.
    pub credential_json: String,

    // ── fields to store in KDBX ──────────────────────────────────────────
    pub credential_id_b64url: String,
    // PKCS#8 PEM private key — must be stored as a KDBX *protected* string.
    pub private_key_pem: String,
    pub rp_id: String,
    pub rp_name: String,
    pub username: String,
    pub user_handle_b64url: String,
    pub origin: String,
}

// The signed WebAuthn assertion JSON, ready to resolve the site's Promise.
// Used by the desktop browser extension flow.
#[derive(Debug)]
pub struct PasskeyAssertionResult {
    pub credential_json: String,
}

// Assertion result for callers that already hold the pre-computed
// `clientDataHash` (e.g. iOS autofill — the OS provides it directly).
#[derive(Debug, Serialize)]
pub struct PasskeyAssertionWithHashResult {
    // DER-encoded ECDSA signature, base64url.
    pub signature_b64url: String,
    // WebAuthn authenticatorData, base64url.
    pub authenticator_data_b64url: String,
    pub credential_id_b64url: String,
    pub user_handle_b64url: String,
    pub rp_id: String,
}

// Registration result for callers that already hold the pre-computed
// `clientDataHash` (e.g. iOS autofill — the OS provides it directly).
#[derive(Debug, Serialize)]
pub struct PasskeyCreationWithHashResult {
    // CBOR-encoded attestation object, base64url.
    pub attestation_object_b64url: String,
    // Raw authenticator data, base64url — for response.authenticatorData in RegistrationResponseJSON.
    pub auth_data_b64url: String,
    pub credential_id_b64url: String,
    // PKCS#8 PEM private key — must be stored as a protected string.
    pub private_key_pem: String,
    // SPKI DER-encoded public key, base64url — for response.publicKey in RegistrationResponseJSON.
    pub public_key_b64url: String,
    pub rp_id: String,
    pub rp_name: String,
    pub username: String,
    pub user_handle_b64url: String,
    // COSE algorithm identifier: -7 (ES256), -8 (EdDSA), -257 (RS256).
    pub algorithm: i64,
}

// Key material produced by a backend for a newly generated passkey.
struct GeneratedKey {
    // COSE_Key CBOR bytes embedded in authData.
    cose_key: Vec<u8>,
    // SPKI DER public key, base64url (no padding).
    public_key_spki_b64url: String,
    // PKCS#8 PEM private key (LF line endings).
    private_key_pem: String,
}

// ── authData builders ─────────────────────────────────────────────────────────

// Builds the authenticator data blob for a *registration* ceremony.
//
// Layout (per WebAuthn §6.1):
// ```text
// rpIdHash      (32 bytes)
// flags         (1 byte)   UP=1, UV=1, AT=1 → 0x45
// signCount     (4 bytes)  big-endian, 0 for software authenticators
// aaguid        (16 bytes) all zeros (no attestation GUID)
// credIdLen     (2 bytes)  big-endian
// credId        (N bytes)
// credPublicKey (CBOR)     COSE EC2 P-256 key
// ```
fn build_auth_data_create(rp_id: &str, credential_id: &[u8], cose_public_key: &[u8]) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(32 + 1 + 4 + 16 + 2 + credential_id.len() + cose_public_key.len());

    buf.extend_from_slice(&Sha256::digest(rp_id.as_bytes())); // rpIdHash
    buf.push(0x5D); // flags: UP|UV|BE|BS|AT
    buf.extend_from_slice(&0u32.to_be_bytes()); // signCount = 0
    buf.extend_from_slice(&[0u8; 16]); // aaguid = zeros
    buf.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    buf.extend_from_slice(credential_id);
    buf.extend_from_slice(cose_public_key);
    buf
}

// Builds the authenticator data blob for an *authentication* (assertion) ceremony.
//
// Layout:
// ```text
// rpIdHash  (32 bytes)
// flags     (1 byte)   UP=1, UV=1, BE=1, BS=1 → 0x1D
// signCount (4 bytes)  big-endian
// ```
fn build_auth_data_get(rp_id: &str, sign_count: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(37);
    buf.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    buf.push(0x1D); // UP|UV|BE|BS
    buf.extend_from_slice(&sign_count.to_be_bytes());
    buf
}

// ── CBOR helpers ──────────────────────────────────────────────────────────────

// Encodes a P-256 public key as a COSE_Key map (RFC 8152 §13.1.1).
// `uncompressed_point` is the SEC1 uncompressed point: 0x04 || x (32 bytes) || y (32 bytes).
fn encode_cose_key_p256(uncompressed_point: &[u8]) -> Result<Vec<u8>> {
    use ciborium::value::Value;

    if uncompressed_point.len() != 65 || uncompressed_point[0] != 0x04 {
        return Err(Error::UnexpectedError(
            "P-256 public key is not a 65-byte uncompressed point".into(),
        ));
    }
    let x = uncompressed_point[1..33].to_vec();
    let y = uncompressed_point[33..65].to_vec();

    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())), // kty: EC2
        (Value::Integer(3i64.into()), Value::Integer((-7i64).into())), // alg: ES256
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())), // crv: P-256
        (Value::Integer((-2i64).into()), Value::Bytes(x)),          // x
        (Value::Integer((-3i64).into()), Value::Bytes(y)),          // y
    ]);

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&cose_key, &mut buf)
        .map_err(|e| Error::UnexpectedError(format!("COSE key CBOR encoding failed: {}", e)))?;
    Ok(buf)
}

// Encodes an Ed25519 verifying key as a COSE_Key OKP map (RFC 8152 §13.2).
// kty=1 (OKP), alg=-8 (EdDSA), crv=-1 (Ed25519), x=raw 32-byte public key.
fn encode_cose_key_ed25519(public_key: &[u8]) -> Result<Vec<u8>> {
    use ciborium::value::Value;
    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(1i64.into())), // kty: OKP
        (Value::Integer(3i64.into()), Value::Integer((-8i64).into())), // alg: EdDSA
        (Value::Integer((-1i64).into()), Value::Integer(6i64.into())), // crv: Ed25519
        (
            Value::Integer((-2i64).into()),
            Value::Bytes(public_key.to_vec()),
        ), // x
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&cose_key, &mut buf).map_err(|e| {
        Error::UnexpectedError(format!("Ed25519 COSE key CBOR encoding failed: {}", e))
    })?;
    Ok(buf)
}

// Encodes an RSA public key as a COSE_Key map (RFC 8230).
// kty=3 (RSA), alg=-257 (RS256), n=modulus bytes, e=exponent bytes (both big-endian,
// no leading zero bytes).
fn encode_cose_key_rsa(n_bytes: Vec<u8>, e_bytes: Vec<u8>) -> Result<Vec<u8>> {
    use ciborium::value::Value;
    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(3i64.into())), // kty: RSA
        (
            Value::Integer(3i64.into()),
            Value::Integer((-257i64).into()),
        ), // alg: RS256
        (Value::Integer((-1i64).into()), Value::Bytes(n_bytes)),    // n: modulus
        (Value::Integer((-2i64).into()), Value::Bytes(e_bytes)),    // e: exponent
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&cose_key, &mut buf)
        .map_err(|e| Error::UnexpectedError(format!("RSA COSE key CBOR encoding failed: {}", e)))?;
    Ok(buf)
}

// Detects the COSE algorithm from a PKCS#8 PEM private key (mirrors KeepassXC's algo_name()).
// Returns -7 (ES256/P-256), -257 (RS256/RSA), or -8 (EdDSA/Ed25519).
// Anything that is not recognised as P-256 or RSA is reported as -8; signing then
// fails with a decode error if the key is not actually Ed25519.
pub fn detect_algorithm_from_pem(private_key_pem: &str) -> i64 {
    backend::detect_algorithm(private_key_pem)
}

// Encodes the attestation object (CBOR map with `fmt`, `attStmt`, `authData`).
fn encode_attestation_object(auth_data: Vec<u8>) -> Result<Vec<u8>> {
    use ciborium::value::Value;

    let att_obj = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
        (Value::Text("authData".into()), Value::Bytes(auth_data)),
    ]);

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&att_obj, &mut buf).map_err(|e| {
        Error::UnexpectedError(format!("attestationObject CBOR encoding failed: {}", e))
    })?;
    Ok(buf)
}

// ── Public API ────────────────────────────────────────────────────────────────

// Performs a WebAuthn registration ceremony for the given creation options.
//
// Selects the algorithm from pubKeyCredParams (first supported: -7, -8, -257; default -7),
// generates a key pair, builds all required WebAuthn structures, and returns both the
// credential JSON (for the site) and the key material (for KDBX storage).
pub fn create_passkey(options_json: &str, origin: &str) -> Result<PasskeyCreationResult> {
    let opts: CreationOptions = serde_json::from_str(options_json)
        .map_err(|e| Error::UnexpectedError(format!("Invalid creation options JSON: {}", e)))?;

    let rp_id = opts.rp.id.clone();
    let rp_name = opts.rp.name.unwrap_or_else(|| rp_id.clone());
    let username = opts.user.name.clone();
    let user_handle_b64url = opts.user.id.clone();
    let challenge_bytes = BASE64URL_NOPAD
        .decode(opts.challenge.as_bytes())
        .map_err(|e| Error::UnexpectedError(format!("Invalid challenge encoding: {}", e)))?;

    // Select algorithm: first supported alg in RP's preferred order.
    const SUPPORTED: &[i64] = &[-7, -8, -257];
    let algorithm = opts
        .pub_key_cred_params
        .iter()
        .find(|p| SUPPORTED.contains(&p.alg))
        .map(|p| p.alg)
        .unwrap_or(-7);

    let mut cred_id_bytes = [0u8; 16];
    backend::fill_random(&mut cred_id_bytes)?;
    let credential_id_b64url = BASE64URL_NOPAD.encode(&cred_id_bytes);

    let client_data = serde_json::json!({
        "type": "webauthn.create",
        "challenge": BASE64URL_NOPAD.encode(&challenge_bytes),
        "origin": origin,
        "crossOrigin": false,
    });
    let client_data_json = serde_json::to_string(&client_data).map_err(|e| {
        Error::UnexpectedError(format!("clientDataJSON serialization failed: {}", e))
    })?;

    let GeneratedKey {
        cose_key: cose_key_bytes,
        public_key_spki_b64url: public_key_b64url,
        private_key_pem,
    } = backend::generate_key(algorithm)?;

    let auth_data = build_auth_data_create(&rp_id, &cred_id_bytes, &cose_key_bytes);
    let auth_data_b64url = BASE64URL_NOPAD.encode(&auth_data);
    let attestation_object = encode_attestation_object(auth_data)?;

    let credential_json = serde_json::to_string(&serde_json::json!({
        "id":   credential_id_b64url,
        "rawId": credential_id_b64url,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {},
        "response": {
            "attestationObject":  BASE64URL_NOPAD.encode(&attestation_object),
            "authenticatorData":  auth_data_b64url,
            "clientDataJSON":     BASE64URL_NOPAD.encode(client_data_json.as_bytes()),
            "publicKey":          public_key_b64url,
            "publicKeyAlgorithm": algorithm,
            "transports":         ["internal"],
        },
    }))
    .map_err(|e| Error::UnexpectedError(format!("Credential JSON serialization failed: {}", e)))?;

    Ok(PasskeyCreationResult {
        credential_json,
        credential_id_b64url,
        private_key_pem,
        rp_id,
        rp_name,
        username,
        user_handle_b64url,
        origin: origin.to_string(),
    })
}

// Performs a WebAuthn registration ceremony for callers that already hold
// the pre-computed `clientDataHash` (e.g. iOS autofill / Android Credential Manager).
//
// `algorithm` selects the key type: -7 (ES256/P-256), -8 (EdDSA/Ed25519), -257 (RS256/RSA-2048).
// Generates a key pair, builds the attestation object (fmt="none"), and returns the individual
// fields needed by the platform credential API plus the private key PEM for storage.
pub fn create_passkey_with_hash(
    rp_id: &str,
    rp_name: &str,
    user_name: &str,
    user_handle_b64url: &str,
    _client_data_hash: &[u8],
    algorithm: i64,
) -> Result<PasskeyCreationWithHashResult> {
    let mut cred_id_bytes = [0u8; 16];
    backend::fill_random(&mut cred_id_bytes)?;
    let credential_id_b64url = BASE64URL_NOPAD.encode(&cred_id_bytes);

    let GeneratedKey {
        cose_key: cose_key_bytes,
        public_key_spki_b64url: public_key_b64url,
        private_key_pem,
    } = backend::generate_key(algorithm)?;

    let auth_data = build_auth_data_create(rp_id, &cred_id_bytes, &cose_key_bytes);
    let auth_data_b64url = BASE64URL_NOPAD.encode(&auth_data);
    let attestation_object = encode_attestation_object(auth_data)?;
    let attestation_object_b64url = BASE64URL_NOPAD.encode(&attestation_object);

    Ok(PasskeyCreationWithHashResult {
        attestation_object_b64url,
        auth_data_b64url,
        credential_id_b64url,
        private_key_pem,
        public_key_b64url,
        rp_id: rp_id.to_string(),
        rp_name: rp_name.to_string(),
        username: user_name.to_string(),
        user_handle_b64url: user_handle_b64url.to_string(),
        algorithm,
    })
}

// Performs a WebAuthn authentication (assertion) ceremony.
//
// Loads the private key from `private_key_pem`, builds `clientDataJSON` from
// `options_json`, signs the assertion, and returns the `PublicKeyCredential`
// JSON the extension passes back to the site.
//
// Used by the desktop browser extension where `options_json` is provided by
// the browser.  For the mobile autofill path use [`sign_assertion_with_hash`].
pub fn sign_assertion(
    credential_id_b64url: &str,
    rp_id: &str,
    user_handle_b64url: &str,
    private_key_pem: &str,
    options_json: &str,
    origin: &str,
) -> Result<PasskeyAssertionResult> {
    let opts: RequestOptions = serde_json::from_str(options_json)
        .map_err(|e| Error::UnexpectedError(format!("Invalid request options JSON: {}", e)))?;

    let effective_rp_id = opts.rp_id.as_deref().unwrap_or(rp_id);
    let challenge_bytes = BASE64URL_NOPAD
        .decode(opts.challenge.as_bytes())
        .map_err(|e| Error::UnexpectedError(format!("Invalid challenge encoding: {}", e)))?;

    let client_data = serde_json::json!({
        "type": "webauthn.get",
        "challenge": BASE64URL_NOPAD.encode(&challenge_bytes),
        "origin": origin,
        "crossOrigin": false,
    });
    let client_data_json = serde_json::to_string(&client_data).map_err(|e| {
        Error::UnexpectedError(format!("clientDataJSON serialization failed: {}", e))
    })?;

    let auth_data = build_auth_data_get(effective_rp_id, 0u32);

    let client_data_hash = Sha256::digest(client_data_json.as_bytes());
    let mut sig_input = Vec::with_capacity(auth_data.len() + 32);
    sig_input.extend_from_slice(&auth_data);
    sig_input.extend_from_slice(&client_data_hash);

    let sig_b64url = sign_with_pem(private_key_pem, &sig_input)?;

    let credential_json = serde_json::to_string(&serde_json::json!({
        "id":   credential_id_b64url,
        "rawId": credential_id_b64url,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {},
        "response": {
            "authenticatorData": BASE64URL_NOPAD.encode(&auth_data),
            "clientDataJSON":    BASE64URL_NOPAD.encode(client_data_json.as_bytes()),
            "signature":         sig_b64url,
            "userHandle":        user_handle_b64url,
        },
    }))
    .map_err(|e| Error::UnexpectedError(format!("Credential JSON serialization failed: {}", e)))?;

    Ok(PasskeyAssertionResult { credential_json })
}

// Signs a WebAuthn assertion when the caller already has the pre-computed
// `clientDataHash`.
//
// iOS autofill provides `clientDataHash` directly (the OS computes it before
// invoking the extension), so there is no `options_json` or `origin` to pass.
// The result contains all fields needed to construct `ASPasskeyAssertionCredential`.
// The algorithm is auto-detected from the PKCS#8 PEM (see `detect_algorithm_from_pem`).
pub fn sign_assertion_with_hash(
    credential_id_b64url: &str,
    rp_id: &str,
    user_handle_b64url: &str,
    private_key_pem: &str,
    client_data_hash: &[u8],
) -> Result<PasskeyAssertionWithHashResult> {
    let auth_data = build_auth_data_get(rp_id, 0u32);

    // Sign: authenticatorData || clientDataHash
    let mut sig_input = Vec::with_capacity(auth_data.len() + client_data_hash.len());
    sig_input.extend_from_slice(&auth_data);
    sig_input.extend_from_slice(client_data_hash);

    let sig_b64url = sign_with_pem(private_key_pem, &sig_input)?;

    Ok(PasskeyAssertionWithHashResult {
        signature_b64url: sig_b64url,
        authenticator_data_b64url: BASE64URL_NOPAD.encode(&auth_data),
        credential_id_b64url: credential_id_b64url.to_string(),
        user_handle_b64url: user_handle_b64url.to_string(),
        rp_id: rp_id.to_string(),
    })
}

// Signs `message` with the private key in `private_key_pem`, auto-detecting the algorithm.
// Returns the base64url-encoded signature bytes.
// Signature formats:
//   -7  (ES256): DER-encoded ECDSA signature
//   -8  (EdDSA): raw 64-byte Ed25519 signature
//   -257 (RS256): raw RSA-PKCS1v1.5 signature bytes
fn sign_with_pem(private_key_pem: &str, message: &[u8]) -> Result<String> {
    let signature = backend::sign(private_key_pem, message)?;
    Ok(BASE64URL_NOPAD.encode(&signature))
}

// ── Botan backend (default) ───────────────────────────────────────────────────

// Only the comparison tests call this when RustCrypto is the selected backend
#[cfg_attr(feature = "rustcrypto-passkey", allow(dead_code))]
mod botan_backend {
    use botan::{Privkey, RandomNumberGenerator, Signer};
    use data_encoding::BASE64URL_NOPAD;

    use super::{encode_cose_key_ed25519, encode_cose_key_p256, encode_cose_key_rsa, GeneratedKey};
    use crate::error::{Error, Result};

    pub(super) fn fill_random(out: &mut [u8]) -> Result<()> {
        let mut rng = RandomNumberGenerator::new_system()?;
        rng.fill(out)?;
        Ok(())
    }

    pub(super) fn generate_key(algorithm: i64) -> Result<GeneratedKey> {
        
        log::info!("Botan backend for passkey generate key call");

        let mut rng = RandomNumberGenerator::new_system()?;
        let private_key = match algorithm {
            -8 => Privkey::create("Ed25519", "", &mut rng)?,
            -257 => Privkey::create("RSA", "2048", &mut rng)?,
            // -7: ES256 / P-256 (default)
            _ => Privkey::create("ECDSA", "secp256r1", &mut rng)?,
        };
        let public_key = private_key.pubkey()?;

        let cose_key = match algorithm {
            -8 => encode_cose_key_ed25519(&public_key.get_ed25519_key()?)?,
            -257 => encode_cose_key_rsa(
                public_key.get_field("n")?.to_bin()?,
                public_key.get_field("e")?.to_bin()?,
            )?,
            _ => encode_cose_key_p256(&public_key.ec_public_point()?)?,
        };

        Ok(GeneratedKey {
            cose_key,
            public_key_spki_b64url: BASE64URL_NOPAD.encode(&public_key.der_encode()?),
            private_key_pem: private_key.pem_encode()?,
        })
    }

    pub(super) fn detect_algorithm(private_key_pem: &str) -> i64 {
        load_private_key(private_key_pem)
            .map(|(_, algorithm)| algorithm)
            .unwrap_or(-8)
    }

    pub(super) fn sign(private_key_pem: &str, message: &[u8]) -> Result<Vec<u8>> {
        
        log::info!("Botan backend for passkey sign call");

        let (private_key, algorithm) = load_private_key(private_key_pem)?;

        log::debug!("Sign algorithm used {}",&algorithm);

        let mut signer = match algorithm {
            // WebAuthn ES256 signatures are DER encoded, not Botan's default raw r || s
            -7 => Signer::new_with_der_formatted_signatures(&private_key, "SHA-256")?,
            -257 => Signer::new(&private_key, "PKCS1v15(SHA-256)")?,
            _ => Signer::new(&private_key, "Pure")?,
        };
        signer.update(message)?;
        let mut rng = RandomNumberGenerator::new_system()?;
        Ok(signer.finish(&mut rng)?)
    }

    // Loads a PKCS#8 PEM private key and returns it with its COSE algorithm identifier
    fn load_private_key(private_key_pem: &str) -> Result<(Privkey, i64)> {
        let private_key = Privkey::load_pem(private_key_pem).map_err(|e| {
            Error::UnexpectedError(format!("Failed to decode private key PEM: {}", e))
        })?;
        let algo_name = private_key.algo_name()?;
        
        log::debug!("Key algorithm {}",&algo_name);

        let algorithm = match algo_name.as_str() {
            // Only a P-256 key has a 65-byte uncompressed public point
            "ECDSA" if private_key.pubkey()?.ec_public_point()?.len() == 65 => -7,
            "RSA" => -257,
            "Ed25519" => -8,
            _ => {
                return Err(Error::UnexpectedError(format!(
                    "Unsupported passkey private key: {}",
                    algo_name
                )))
            }
        };
        Ok((private_key, algorithm))
    }
}

// ── RustCrypto backend ('rustcrypto-passkey' feature) ────────────────────────

#[cfg(feature = "rustcrypto-passkey")]
mod rustcrypto_backend {
    use data_encoding::BASE64URL_NOPAD;
    use ed25519_dalek::SigningKey as Ed25519SigningKey;
    use p256::{
        ecdsa::{signature::Signer, Signature, SigningKey},
        pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
    };
    use rand_core::{OsRng, RngCore};
    use rsa::{pkcs1v15::SigningKey as RsaSigningKey, traits::PublicKeyParts, RsaPrivateKey};
    use sha2::Sha256;

    use super::{encode_cose_key_ed25519, encode_cose_key_p256, encode_cose_key_rsa, GeneratedKey};
    use crate::error::{Error, Result};

    // DER prefix for a P-256 SubjectPublicKeyInfo: SEQUENCE { SEQUENCE { OID ecPublicKey, OID prime256v1 }, BIT STRING }
    const P256_SPKI_PREFIX: &[u8] = &[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];

    // DER prefix for an Ed25519 SubjectPublicKeyInfo: SEQUENCE { SEQUENCE { OID id-EdDSA (1.3.101.112) }, BIT STRING }
    const ED25519_SPKI_PREFIX: &[u8] = &[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    pub(super) fn fill_random(out: &mut [u8]) -> Result<()> {
        OsRng.fill_bytes(out);
        Ok(())
    }

    pub(super) fn generate_key(algorithm: i64) -> Result<GeneratedKey> {
        log::info!("Rustcrypto backend for passkey generate key call");
        match algorithm {
            -8 => {
                use ed25519_dalek::pkcs8::{EncodePrivateKey as _, KeypairBytes};
                let sk = Ed25519SigningKey::generate(&mut OsRng);
                let vk = sk.verifying_key();
                let mut spki = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + 32);
                spki.extend_from_slice(ED25519_SPKI_PREFIX);
                spki.extend_from_slice(vk.as_bytes());
                // Use KeypairBytes with public_key=None to produce PKCS#8 V1 (version=0, no embedded
                // public key). ed25519-dalek v2 normally embeds the public key (V2/OneAsymmetricKey)
                // which Botan 2.x (used by KeepassXC) cannot load.
                let keypair_bytes = KeypairBytes {
                    secret_key: sk.to_bytes(),
                    public_key: None,
                };
                let pem = keypair_bytes.to_pkcs8_pem(LineEnding::LF).map_err(|e| {
                    Error::UnexpectedError(format!("Ed25519 PEM encoding failed: {}", e))
                })?;
                Ok(GeneratedKey {
                    cose_key: encode_cose_key_ed25519(vk.as_bytes())?,
                    public_key_spki_b64url: BASE64URL_NOPAD.encode(&spki),
                    private_key_pem: pem.as_str().to_string(),
                })
            }
            -257 => {
                use rsa::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};
                let sk = RsaPrivateKey::new(&mut OsRng, 2048).map_err(|e| {
                    Error::UnexpectedError(format!("RSA key generation failed: {}", e))
                })?;
                let public_key = sk.to_public_key();
                let spki_der = public_key.to_public_key_der().map_err(|e| {
                    Error::UnexpectedError(format!("RSA SPKI encoding failed: {}", e))
                })?;
                let pem = sk.to_pkcs8_pem(LineEnding::LF).map_err(|e| {
                    Error::UnexpectedError(format!("RSA PEM encoding failed: {}", e))
                })?;
                Ok(GeneratedKey {
                    cose_key: encode_cose_key_rsa(
                        public_key.n().to_bytes_be(),
                        public_key.e().to_bytes_be(),
                    )?,
                    public_key_spki_b64url: BASE64URL_NOPAD.encode(spki_der.as_bytes()),
                    private_key_pem: pem.as_str().to_string(),
                })
            }
            _ => {
                // -7: ES256 / P-256 (default)
                let sk = SigningKey::random(&mut OsRng);
                let point = sk
                    .verifying_key()
                    .to_encoded_point(false /* uncompressed */);
                let mut spki = Vec::with_capacity(91);
                spki.extend_from_slice(P256_SPKI_PREFIX);
                spki.extend_from_slice(point.as_bytes());
                let pem = sk
                    .to_pkcs8_pem(LineEnding::LF)
                    .map_err(|e| Error::UnexpectedError(format!("PEM encoding failed: {}", e)))?;
                Ok(GeneratedKey {
                    cose_key: encode_cose_key_p256(point.as_bytes())?,
                    public_key_spki_b64url: BASE64URL_NOPAD.encode(&spki),
                    private_key_pem: pem.as_str().to_string(),
                })
            }
        }
    }

    // Tries P-256 first since most existing entries are P-256.
    pub(super) fn detect_algorithm(private_key_pem: &str) -> i64 {
        if SigningKey::from_pkcs8_pem(private_key_pem).is_ok() {
            log::debug!("Sign algorithm used -7 ES256");
            return -7;
        }
        {
            use rsa::pkcs8::DecodePrivateKey as _;
            if RsaPrivateKey::from_pkcs8_pem(private_key_pem).is_ok() {
                log::debug!("Sign algorithm used -257 RSA");
                return -257;
            }
        }
        log::debug!("Sign algorithm used -8 Ed25519");
        -8 // Ed25519
    }

    pub(super) fn sign(private_key_pem: &str, message: &[u8]) -> Result<Vec<u8>> {
        log::info!("Rustcrypto backend for passkey sign call");

        match detect_algorithm(private_key_pem) {
            -257 => {
                use rsa::pkcs8::DecodePrivateKey as _;
                use rsa::signature::SignatureEncoding;
                let rsa_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
                    .map_err(|e| Error::UnexpectedError(format!("RSA PEM decode failed: {}", e)))?;
                let signing_key = RsaSigningKey::<Sha256>::new(rsa_key);
                Ok(signing_key.sign(message).to_vec())
            }
            -8 => {
                use ed25519_dalek::{pkcs8::DecodePrivateKey as _, Signer as _};
                let ed_key = Ed25519SigningKey::from_pkcs8_pem(private_key_pem).map_err(|e| {
                    Error::UnexpectedError(format!("Ed25519 PEM decode failed: {}", e))
                })?;
                Ok(ed_key.sign(message).to_bytes().to_vec())
            }
            _ => {
                // -7: ES256 / P-256
                let signing_key = SigningKey::from_pkcs8_pem(private_key_pem).map_err(|e| {
                    Error::UnexpectedError(format!("Failed to decode private key PEM: {}", e))
                })?;
                let signature: Signature = signing_key.sign(message);
                Ok(signature.to_der().as_bytes().to_vec())
            }
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_creation_options(rp_id: &str) -> String {
        let challenge = BASE64URL_NOPAD.encode(b"test-challenge-1234");
        let user_id = BASE64URL_NOPAD.encode(b"user-id-bytes");
        serde_json::json!({
            "rp": { "id": rp_id, "name": "Test Site" },
            "user": {
                "id": user_id,
                "name": "alice@example.com",
                "displayName": "Alice"
            },
            "challenge": challenge,
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
        })
        .to_string()
    }

    fn sample_request_options(rp_id: &str, cred_id: &str) -> String {
        let challenge = BASE64URL_NOPAD.encode(b"auth-challenge-5678");
        serde_json::json!({
            "rpId": rp_id,
            "challenge": challenge,
            "allowCredentials": [{ "type": "public-key", "id": cred_id }],
            "userVerification": "preferred",
        })
        .to_string()
    }

    #[test]
    fn create_and_sign_roundtrip() {
        let rp_id = "example.com";
        let origin = "https://example.com";

        let creation_opts = sample_creation_options(rp_id);
        let result =
            create_passkey(&creation_opts, origin).expect("passkey creation should succeed");

        assert!(!result.credential_json.is_empty());
        assert!(!result.private_key_pem.is_empty());
        assert_eq!(result.rp_id, rp_id);
        assert_eq!(result.username, "alice@example.com");

        let cred: serde_json::Value = serde_json::from_str(&result.credential_json)
            .expect("credential_json must be valid JSON");
        assert_eq!(cred["type"], "public-key");
        assert!(cred["response"]["attestationObject"].is_string());
        assert!(cred["response"]["clientDataJSON"].is_string());

        let request_opts = sample_request_options(rp_id, &result.credential_id_b64url);
        let assertion = sign_assertion(
            &result.credential_id_b64url,
            rp_id,
            &result.user_handle_b64url,
            &result.private_key_pem,
            &request_opts,
            origin,
        )
        .expect("assertion signing should succeed");

        let asr: serde_json::Value = serde_json::from_str(&assertion.credential_json)
            .expect("assertion credential_json must be valid JSON");
        assert_eq!(asr["type"], "public-key");
        assert!(asr["response"]["signature"].is_string());
        assert!(asr["response"]["authenticatorData"].is_string());
    }

    #[test]
    fn sign_assertion_with_hash_roundtrip() {
        let rp_id = "mobile.example.com";
        let origin = "https://mobile.example.com";

        let creation_opts = sample_creation_options(rp_id);
        let created = create_passkey(&creation_opts, origin).unwrap();

        // Simulate iOS providing a pre-computed clientDataHash
        let client_data_hash = Sha256::digest(b"simulated-client-data-json");

        let result = sign_assertion_with_hash(
            &created.credential_id_b64url,
            rp_id,
            &created.user_handle_b64url,
            &created.private_key_pem,
            &client_data_hash,
        )
        .expect("sign_assertion_with_hash should succeed");

        assert!(!result.signature_b64url.is_empty());
        assert!(!result.authenticator_data_b64url.is_empty());
        assert_eq!(result.credential_id_b64url, created.credential_id_b64url);
        assert_eq!(result.rp_id, rp_id);

        // Verify the authenticator data starts with SHA-256(rpId)
        let auth_data_bytes = BASE64URL_NOPAD
            .decode(result.authenticator_data_b64url.as_bytes())
            .unwrap();
        let expected_rp_hash = Sha256::digest(rp_id.as_bytes());
        assert_eq!(&auth_data_bytes[..32], &expected_rp_hash[..]);
    }

    #[test]
    fn create_passkey_produces_unique_credential_ids() {
        let opts = sample_creation_options("test.com");
        let r1 = create_passkey(&opts, "https://test.com").unwrap();
        let r2 = create_passkey(&opts, "https://test.com").unwrap();
        assert_ne!(r1.credential_id_b64url, r2.credential_id_b64url);
        assert_ne!(r1.private_key_pem, r2.private_key_pem);
    }

    #[test]
    fn invalid_options_json_returns_error() {
        let result = create_passkey("not valid json", "https://example.com");
        assert!(result.is_err());
    }

    #[test]
    fn sign_assertion_with_wrong_pem_returns_error() {
        let request_opts = sample_request_options("example.com", "some-cred-id");
        let result = sign_assertion(
            "some-cred-id",
            "example.com",
            "dXNlcg",
            "NOT A VALID PEM",
            &request_opts,
            "https://example.com",
        );
        assert!(result.is_err(), "invalid PEM should return an error");
    }

    #[test]
    fn sign_assertion_without_rp_id_in_options_falls_back_to_arg() {
        let creation_opts = sample_creation_options("fallback.com");
        let creation = create_passkey(&creation_opts, "https://fallback.com").unwrap();

        let opts_without_rp_id = {
            let challenge = BASE64URL_NOPAD.encode(b"challenge-no-rpid");
            serde_json::json!({
                "challenge": challenge,
                "allowCredentials": [],
            })
            .to_string()
        };

        let assertion = sign_assertion(
            &creation.credential_id_b64url,
            "fallback.com",
            &creation.user_handle_b64url,
            &creation.private_key_pem,
            &opts_without_rp_id,
            "https://fallback.com",
        );
        assert!(
            assertion.is_ok(),
            "should succeed using fallback rp_id: {:?}",
            assertion
        );
    }

    #[test]
    fn auth_data_create_has_correct_length_and_flags() {
        let rp_id = "len-test.com";
        let cred_id = b"test-credential-id-16b";
        let cose_key = b"COSE_KEY_PLACEHOLDER";

        let auth_data = build_auth_data_create(rp_id, cred_id, cose_key);

        let expected_len = 32 + 1 + 4 + 16 + 2 + cred_id.len() + cose_key.len();
        assert_eq!(auth_data.len(), expected_len);

        let expected_hash: Vec<u8> = Sha256::digest(rp_id.as_bytes()).to_vec();
        assert_eq!(&auth_data[..32], expected_hash.as_slice());
        assert_eq!(auth_data[32], 0x5D);
        assert_eq!(&auth_data[33..37], &[0u8; 4]);
    }

    #[test]
    fn auth_data_get_has_correct_length_and_flags() {
        let rp_id = "get-test.com";
        let sign_count = 42u32;
        let auth_data = build_auth_data_get(rp_id, sign_count);

        assert_eq!(auth_data.len(), 37);

        let expected_hash: Vec<u8> = Sha256::digest(rp_id.as_bytes()).to_vec();
        assert_eq!(&auth_data[..32], expected_hash.as_slice());
        assert_eq!(auth_data[32], 0x1D);

        let count_bytes = sign_count.to_be_bytes();
        assert_eq!(&auth_data[33..37], &count_bytes);
    }

    fn creation_options_with_alg(rp_id: &str, alg: i64) -> String {
        let challenge = BASE64URL_NOPAD.encode(b"test-challenge-alg");
        let user_id = BASE64URL_NOPAD.encode(b"user-id-bytes");
        serde_json::json!({
            "rp": { "id": rp_id, "name": "Test Site" },
            "user": { "id": user_id, "name": "alice@example.com", "displayName": "Alice" },
            "challenge": challenge,
            "pubKeyCredParams": [{ "type": "public-key", "alg": alg }],
        })
        .to_string()
    }

    #[test]
    fn ed25519_create_and_sign_with_hash_roundtrip() {
        let rp_id = "ed25519.example.com";
        let opts = creation_options_with_alg(rp_id, -8);
        let created = create_passkey(&opts, "https://ed25519.example.com")
            .expect("Ed25519 passkey creation should succeed");

        assert_eq!(detect_algorithm_from_pem(&created.private_key_pem), -8);

        let client_data_hash = Sha256::digest(b"ed25519-client-data");
        let result = sign_assertion_with_hash(
            &created.credential_id_b64url,
            rp_id,
            &created.user_handle_b64url,
            &created.private_key_pem,
            &client_data_hash,
        )
        .expect("Ed25519 assertion signing should succeed");

        assert!(!result.signature_b64url.is_empty());
        assert!(!result.authenticator_data_b64url.is_empty());
        assert_eq!(result.credential_id_b64url, created.credential_id_b64url);
        assert_eq!(result.rp_id, rp_id);
    }

    #[test]
    fn rsa_create_and_sign_with_hash_roundtrip() {
        let rp_id = "rsa.example.com";
        let opts = creation_options_with_alg(rp_id, -257);
        let created = create_passkey(&opts, "https://rsa.example.com")
            .expect("RSA passkey creation should succeed");

        assert_eq!(detect_algorithm_from_pem(&created.private_key_pem), -257);

        let client_data_hash = Sha256::digest(b"rsa-client-data");
        let result = sign_assertion_with_hash(
            &created.credential_id_b64url,
            rp_id,
            &created.user_handle_b64url,
            &created.private_key_pem,
            &client_data_hash,
        )
        .expect("RSA assertion signing should succeed");

        assert!(!result.signature_b64url.is_empty());
        assert!(!result.authenticator_data_b64url.is_empty());
        assert_eq!(result.credential_id_b64url, created.credential_id_b64url);
        assert_eq!(result.rp_id, rp_id);
    }

    #[test]
    fn create_passkey_with_hash_ed25519_roundtrip() {
        let rp_id = "ed25519-hash.example.com";
        let user_handle = BASE64URL_NOPAD.encode(b"user-handle");
        let client_data_hash = Sha256::digest(b"client-data-json");

        let created = create_passkey_with_hash(
            rp_id,
            "Test Site",
            "alice@example.com",
            &user_handle,
            &client_data_hash,
            -8,
        )
        .expect("Ed25519 create_passkey_with_hash should succeed");

        assert_eq!(created.algorithm, -8);
        assert!(!created.private_key_pem.is_empty());
        assert!(!created.attestation_object_b64url.is_empty());

        let sig_result = sign_assertion_with_hash(
            &created.credential_id_b64url,
            rp_id,
            &created.user_handle_b64url,
            &created.private_key_pem,
            &client_data_hash,
        )
        .expect("Ed25519 sign after create_passkey_with_hash should succeed");

        assert!(!sig_result.signature_b64url.is_empty());
    }

    #[test]
    fn create_passkey_with_hash_rsa_roundtrip() {
        let rp_id = "rsa-hash.example.com";
        let user_handle = BASE64URL_NOPAD.encode(b"user-handle");
        let client_data_hash = Sha256::digest(b"client-data-json");

        let created = create_passkey_with_hash(
            rp_id,
            "Test Site",
            "alice@example.com",
            &user_handle,
            &client_data_hash,
            -257,
        )
        .expect("RSA create_passkey_with_hash should succeed");

        assert_eq!(created.algorithm, -257);
        assert!(!created.private_key_pem.is_empty());
        assert!(!created.attestation_object_b64url.is_empty());

        let sig_result = sign_assertion_with_hash(
            &created.credential_id_b64url,
            rp_id,
            &created.user_handle_b64url,
            &created.private_key_pem,
            &client_data_hash,
        )
        .expect("RSA sign after create_passkey_with_hash should succeed");

        assert!(!sig_result.signature_b64url.is_empty());
    }

    #[test]
    fn detect_algorithm_identifies_p256() {
        let opts = creation_options_with_alg("p256.example.com", -7);
        let created = create_passkey(&opts, "https://p256.example.com").unwrap();
        assert_eq!(detect_algorithm_from_pem(&created.private_key_pem), -7);
    }

    #[test]
    fn detect_algorithm_identifies_ed25519() {
        let opts = creation_options_with_alg("ed.example.com", -8);
        let created = create_passkey(&opts, "https://ed.example.com").unwrap();
        assert_eq!(detect_algorithm_from_pem(&created.private_key_pem), -8);
    }

    #[test]
    fn detect_algorithm_identifies_rsa() {
        let opts = creation_options_with_alg("rsa.example.com", -257);
        let created = create_passkey(&opts, "https://rsa.example.com").unwrap();
        assert_eq!(detect_algorithm_from_pem(&created.private_key_pem), -257);
    }

    #[test]
    fn algo_selection_picks_first_supported_from_list() {
        let rp_id = "multi.example.com";
        let challenge = BASE64URL_NOPAD.encode(b"multi-alg-challenge");
        let user_id = BASE64URL_NOPAD.encode(b"user-id");
        // RP prefers -8 first, then -7
        let opts = serde_json::json!({
            "rp": { "id": rp_id, "name": "Multi Alg Site" },
            "user": { "id": user_id, "name": "bob@example.com" },
            "challenge": challenge,
            "pubKeyCredParams": [
                { "type": "public-key", "alg": -8 },
                { "type": "public-key", "alg": -7 },
            ],
        })
        .to_string();
        let created = create_passkey(&opts, "https://multi.example.com").unwrap();
        // Should pick -8 (first in list that is supported)
        assert_eq!(detect_algorithm_from_pem(&created.private_key_pem), -8);
    }

    #[test]
    fn algo_selection_defaults_to_p256_when_none_match() {
        let rp_id = "unknown.example.com";
        let challenge = BASE64URL_NOPAD.encode(b"unknown-alg-challenge");
        let user_id = BASE64URL_NOPAD.encode(b"user-id");
        // RP only advertises an unknown algorithm
        let opts = serde_json::json!({
            "rp": { "id": rp_id, "name": "Unknown Alg Site" },
            "user": { "id": user_id, "name": "charlie@example.com" },
            "challenge": challenge,
            "pubKeyCredParams": [{ "type": "public-key", "alg": -999 }],
        })
        .to_string();
        let created = create_passkey(&opts, "https://unknown.example.com").unwrap();
        // Should fall back to -7 (P-256)
        assert_eq!(detect_algorithm_from_pem(&created.private_key_pem), -7);
    }

    // ── Compatibility with keys created by the RustCrypto backend ──────────────
    //
    // Passkeys already stored in KDBX files were generated by the RustCrypto crates.
    // These test-only keys were produced by that code and must keep working with
    // whichever backend is selected.

    const RUSTCRYPTO_P256_PEM: &str = "\
-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8kNvCFi5I6PY1Vij\n\
b1U/mtKnsg58PcIYvTWR8eJtTSWhRANCAASNy5mjD9+ZVlWJ/pHx0eMchSOcWDw3\n\
oJb5r3X55/27C9pg0bRHCm+gp6bsbe1UXgMv6Fhv1J9YxcUrYwQDePA3\n\
-----END PRIVATE KEY-----\n\
";
    const RUSTCRYPTO_P256_SPKI: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjcuZow_fmVZVif6R8dHjHIUjnFg8N6CW-a91-ef9uwvaYNG0RwpvoKem7G3tVF4DL-hYb9SfWMXFK2MEA3jwNw";

    const RUSTCRYPTO_ED25519_PEM: &str = "\
-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEIC9Mfu2LQSbKX9IL3r3Q2ZXhDUt+pBI1x87MbgmJZsC0\n\
-----END PRIVATE KEY-----\n\
";
    const RUSTCRYPTO_ED25519_SPKI: &str =
        "MCowBQYDK2VwAyEAIzwDCfaTYtf8Tk57vhmal5P8f_IQz-Df4NCrwtwbJ_0";

    const RUSTCRYPTO_RSA_PEM: &str = "\
-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDaG2pmQaWwIwjt\n\
09vMhNne3J5QLxV8Yla8eCCKiLlQgoM76/RqMIA3a3W8LrawX9pjNMDfoMUmx6CR\n\
NvoRq4IEKRNZMmabNp1AvjDG8mtit5FkF10XnpaJ3EaYNwJjuVJXLts+abMQK9h6\n\
CdYxbxpcM0I8/+E3WK/Vi9Znt2bo7ZIjwosOrvHljUqRRsDSb369dxcsi+0O1fKF\n\
INQ1u6NKXWdcSB7G0Y+EmIqEjLHGief5d46hDPZ907zeOWGDBIZsEzXYHX01KMC4\n\
fVN4XYFm/BEBTkQJRAzchZxN5BW3WKUh04FLqfs0Y2Of0O3oblVo5pDvnD6dqcSB\n\
IGlC0kd9AgMBAAECggEBAJjg2J6eazXgCNUzSAC+KjzVZT6NEkFiaKuohB62oTZ2\n\
lOg+hs6b+nNeJmNmVvWf6mLZSkw105tQGBNRds1F61dhN0exVUx8ZpNH/Mami3Dh\n\
fM6stbrllV1CglUVUd52uumTVWgVDMdMBGveUz3JQ6/W2hoJvWJfDrjfUMTYQBEJ\n\
kPH+nrkQAa4GyiTdoWbEriC2gWHV4cwnXduVH4D8ZIg4z9IxZjDEfolzXnXi8wNP\n\
PswXTbD0+uy8Z+jxrhYK43UsN3HyMO/+gYc8OS79KWWhQ5HP1ZH4/eBlz2mYZklD\n\
4wpQphYjYHeAqjSy/ESmPmuOM9IHTsffm9bDnxhRr+ECgYEA/WDHnGpueHB8gTgb\n\
+bveodXp4XSRYhq9J9OlvUosHuXHfiEMiE5TSlEpK4+HTtCu5ieByu/I5uLU3ScV\n\
YH9lfg3U8oKCAVfBnwtLn4czYLMC7FJyuxAZHL0um0XsQ+C9JIntg+XnM7GcDj9O\n\
kte9Gr/YHeAomDVmkGEPmNSydDkCgYEA3F0zOaGzdHVQUOjoq8pEfNIgRALZM9U7\n\
xcGKuIyFlV1Igm8/ntFgWoMFfL4ZK7WuxOx7C8DmSB2gfnvjBjzJo9EeQTRlK+eS\n\
ImK/ciz4cCUo4RQQV1v7fGqvwLIlr1VFkqX0cY24n0rSKFipXDtiD5PqR5GMmcoR\n\
xid1UkFv1WUCgYBc0b9OBY9Cf7Kcg7l72t7L2lk7RkCb97+jf10P4sQW7YYPJnw4\n\
0rigWOsEEig3LytjFMXvWbf3HNFt0ot6NjEv5FFGJZkKdONxJ+okHpsrqWhAulNd\n\
Q6Bvbr5ME2lh1Ep1wDFKSEZSIZZRgc9+65lS20SIbT1xxN41tdjI2+IjwQKBgCb+\n\
gwsGtye7fqvimxGTKE1iLX17d435hKs41WBU1WqZ6DPUldB3wnIhzz3EsdWPP87u\n\
/dMVnmpSe80GBSVcal4Hqi/loqWDQ9O7357HoGrP2I0DrOSYjUb15gXWQF7nWvlZ\n\
Tokth+cAKXIkRkvg4jhZd1KUyemI3V5QKy2UEMMVAoGAEG3au9G7wAIQ8KGsYd3b\n\
dLBKQsNE6iYpvG/rEyNFNt994ZcbNq8JjqWLLLYRymCr27rWbZuspneTWAU+u9cw\n\
oeYiDipspH0aGS7Iu6CAuNpkNH7Aj2Z9rSzt9H0q3PUJ3feZKhb6o554GqvumG3K\n\
J2QOX4dW1SYNvuF2ktILiR8=\n\
-----END PRIVATE KEY-----\n\
";
    const RUSTCRYPTO_RSA_SPKI: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2htqZkGlsCMI7dPbzITZ3tyeUC8VfGJWvHggioi5UIKDO-v0ajCAN2t1vC62sF_aYzTA36DFJsegkTb6EauCBCkTWTJmmzadQL4wxvJrYreRZBddF56WidxGmDcCY7lSVy7bPmmzECvYegnWMW8aXDNCPP_hN1iv1YvWZ7dm6O2SI8KLDq7x5Y1KkUbA0m9-vXcXLIvtDtXyhSDUNbujSl1nXEgextGPhJiKhIyxxonn-XeOoQz2fdO83jlhgwSGbBM12B19NSjAuH1TeF2BZvwRAU5ECUQM3IWcTeQVt1ilIdOBS6n7NGNjn9Dt6G5VaOaQ75w-nanEgSBpQtJHfQIDAQAB";

    // DER prefix for a P-256 SubjectPublicKeyInfo using the named curve OID (prime256v1)
    const P256_SPKI_PREFIX: &[u8] = &[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];

    // Verifies a WebAuthn signature against the SPKI public key the site received at
    // registration. Uses Botan directly so it is independent of the selected backend.
    fn verify_with_spki(
        spki_b64url: &str,
        algorithm: i64,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        let spki = BASE64URL_NOPAD.decode(spki_b64url.as_bytes()).unwrap();
        let public_key = botan::Pubkey::load_der(&spki).unwrap();
        let mut verifier = match algorithm {
            -7 => botan::Verifier::new_with_der_formatted_signatures(&public_key, "SHA-256"),
            -257 => botan::Verifier::new(&public_key, "PKCS1v15(SHA-256)"),
            _ => botan::Verifier::new(&public_key, "Pure"),
        }
        .unwrap();
        verifier.update(message).unwrap();
        verifier.finish(signature).unwrap()
    }

    // Signs an assertion with `private_key_pem` and checks the signature verifies
    // against `spki_b64url`.
    fn assert_assertion_verifies(private_key_pem: &str, spki_b64url: &str, algorithm: i64) {
        let rp_id = "verify.example.com";
        let client_data_hash = Sha256::digest(b"verify-client-data");
        let result = sign_assertion_with_hash(
            "Y3JlZA",
            rp_id,
            "dXNlcg",
            private_key_pem,
            &client_data_hash,
        )
        .expect("assertion signing should succeed");

        let mut message = BASE64URL_NOPAD
            .decode(result.authenticator_data_b64url.as_bytes())
            .unwrap();
        message.extend_from_slice(&client_data_hash);
        let signature = BASE64URL_NOPAD
            .decode(result.signature_b64url.as_bytes())
            .unwrap();

        assert!(
            verify_with_spki(spki_b64url, algorithm, &message, &signature),
            "signature for algorithm {} must verify against the registered public key",
            algorithm
        );
    }

    #[test]
    fn rustcrypto_stored_keys_are_detected() {
        assert_eq!(detect_algorithm_from_pem(RUSTCRYPTO_P256_PEM), -7);
        assert_eq!(detect_algorithm_from_pem(RUSTCRYPTO_ED25519_PEM), -8);
        assert_eq!(detect_algorithm_from_pem(RUSTCRYPTO_RSA_PEM), -257);
    }

    #[test]
    fn rustcrypto_stored_keys_sign_verifiable_assertions() {
        assert_assertion_verifies(RUSTCRYPTO_P256_PEM, RUSTCRYPTO_P256_SPKI, -7);
        assert_assertion_verifies(RUSTCRYPTO_ED25519_PEM, RUSTCRYPTO_ED25519_SPKI, -8);
        assert_assertion_verifies(RUSTCRYPTO_RSA_PEM, RUSTCRYPTO_RSA_SPKI, -257);
    }

    #[test]
    fn rustcrypto_stored_keys_yield_the_same_public_key_under_botan() {
        for (pem, spki) in [
            (RUSTCRYPTO_P256_PEM, RUSTCRYPTO_P256_SPKI),
            (RUSTCRYPTO_ED25519_PEM, RUSTCRYPTO_ED25519_SPKI),
            (RUSTCRYPTO_RSA_PEM, RUSTCRYPTO_RSA_SPKI),
        ] {
            let private_key = botan::Privkey::load_pem(pem).unwrap();
            let der = private_key.pubkey().unwrap().der_encode().unwrap();
            assert_eq!(BASE64URL_NOPAD.encode(&der), spki);
        }
    }

    #[test]
    fn created_passkeys_sign_assertions_that_verify_against_registered_public_key() {
        for algorithm in [-7i64, -8, -257] {
            let created = create_passkey_with_hash(
                "created.example.com",
                "Test Site",
                "alice@example.com",
                "dXNlcg",
                &[0u8; 32],
                algorithm,
            )
            .unwrap();
            assert_assertion_verifies(
                &created.private_key_pem,
                &created.public_key_b64url,
                algorithm,
            );
        }
    }

    #[test]
    fn p256_spki_uses_named_curve_and_matches_cose_key() {
        let created =
            create_passkey_with_hash("cose.example.com", "T", "u", "dXNlcg", &[0u8; 32], -7)
                .unwrap();
        let spki = BASE64URL_NOPAD
            .decode(created.public_key_b64url.as_bytes())
            .unwrap();
        assert_eq!(spki.len(), P256_SPKI_PREFIX.len() + 65);
        assert_eq!(&spki[..P256_SPKI_PREFIX.len()], P256_SPKI_PREFIX);

        // The COSE key at the end of authData must hold the same x and y as the SPKI point
        let auth_data = BASE64URL_NOPAD
            .decode(created.auth_data_b64url.as_bytes())
            .unwrap();
        let cose_start = 32 + 1 + 4 + 16 + 2 + 16;
        let cose: ciborium::value::Value =
            ciborium::de::from_reader(&auth_data[cose_start..]).unwrap();
        let entries = cose.as_map().unwrap();
        let field = |label: i64| {
            entries
                .iter()
                .find(|(k, _)| k.as_integer() == Some(label.into()))
                .and_then(|(_, v)| v.as_bytes().cloned())
                .unwrap()
        };
        let point = &spki[P256_SPKI_PREFIX.len()..];
        assert_eq!(point[0], 0x04);
        assert_eq!(field(-2), point[1..33].to_vec());
        assert_eq!(field(-3), point[33..65].to_vec());
    }

    #[test]
    fn ed25519_pem_is_pkcs8_v1_without_embedded_public_key() {
        // KeePassXC (Botan 2.x) cannot load the PKCS#8 v2 form that embeds the public key
        let created =
            create_passkey_with_hash("v1.example.com", "T", "u", "dXNlcg", &[0u8; 32], -8).unwrap();
        let body: String = created
            .private_key_pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let der = data_encoding::BASE64.decode(body.as_bytes()).unwrap();
        // SEQUENCE (46 bytes) { INTEGER 0 (version v1), ... }
        assert_eq!(&der[..5], &[0x30, 0x2e, 0x02, 0x01, 0x00]);
        assert_eq!(der.len(), 48);
    }

    #[test]
    fn unsupported_key_type_fails_to_sign() {
        let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
        let p384 = botan::Privkey::create("ECDSA", "secp384r1", &mut rng)
            .unwrap()
            .pem_encode()
            .unwrap();
        assert!(sign_assertion_with_hash("Y3JlZA", "x.com", "dXNlcg", &p384, &[0u8; 32]).is_err());
    }
}

// Botan vs RustCrypto cross-compatibility: a key created by either backend must load
// and sign with the other, and both must agree on the detected algorithm.
// Run with: cargo test --lib --features rustcrypto-passkey passkey_crypto
#[cfg(all(test, feature = "rustcrypto-passkey"))]
mod backend_comparison_tests {
    use data_encoding::BASE64URL_NOPAD;

    use super::{botan_backend, rustcrypto_backend};

    fn verify(spki_b64url: &str, algorithm: i64, message: &[u8], signature: &[u8]) -> bool {
        let spki = BASE64URL_NOPAD.decode(spki_b64url.as_bytes()).unwrap();
        let public_key = botan::Pubkey::load_der(&spki).unwrap();
        let mut verifier = match algorithm {
            -7 => botan::Verifier::new_with_der_formatted_signatures(&public_key, "SHA-256"),
            -257 => botan::Verifier::new(&public_key, "PKCS1v15(SHA-256)"),
            _ => botan::Verifier::new(&public_key, "Pure"),
        }
        .unwrap();
        verifier.update(message).unwrap();
        verifier.finish(signature).unwrap()
    }

    #[test]
    fn botan_keys_work_with_rustcrypto() {
        let message = b"botan-to-rustcrypto";
        for algorithm in [-7i64, -8, -257] {
            let key = botan_backend::generate_key(algorithm).unwrap();
            assert_eq!(
                rustcrypto_backend::detect_algorithm(&key.private_key_pem),
                algorithm
            );
            let signature = rustcrypto_backend::sign(&key.private_key_pem, message).unwrap();
            assert!(verify(
                &key.public_key_spki_b64url,
                algorithm,
                message,
                &signature
            ));
        }
    }

    #[test]
    fn rustcrypto_keys_work_with_botan() {
        let message = b"rustcrypto-to-botan";
        for algorithm in [-7i64, -8, -257] {
            let key = rustcrypto_backend::generate_key(algorithm).unwrap();
            assert_eq!(
                botan_backend::detect_algorithm(&key.private_key_pem),
                algorithm
            );
            let signature = botan_backend::sign(&key.private_key_pem, message).unwrap();
            assert!(verify(
                &key.public_key_spki_b64url,
                algorithm,
                message,
                &signature
            ));
        }
    }
}
