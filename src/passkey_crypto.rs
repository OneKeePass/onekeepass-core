// Pure cryptographic operations for WebAuthn passkey registration and authentication.
//
// Compiled on all platforms (desktop, iOS, Android) — no `#[cfg]` gate.
// All private-key material stays inside this module (and the KDBX database).

use data_encoding::BASE64URL_NOPAD;
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
    EncodedPoint,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

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
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreationOptions {
    rp: RpInfo,
    user: UserInfo,
    challenge: String, // base64url
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AllowCredential {
    id: String, // base64url
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestOptions {
    rp_id: Option<String>,
    challenge: String, // base64url
    #[serde(default)]
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
    pub credential_id_b64url: String,
    // PKCS#8 PEM private key — must be stored as a protected string.
    pub private_key_pem: String,
    pub rp_id: String,
    pub rp_name: String,
    pub username: String,
    pub user_handle_b64url: String,
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
fn build_auth_data_create(
    rp_id: &str,
    credential_id: &[u8],
    cose_public_key: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + 1 + 4 + 16 + 2 + credential_id.len() + cose_public_key.len());

    buf.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));   // rpIdHash
    buf.push(0x5D);                                              // flags: UP|UV|BE|BS|AT
    buf.extend_from_slice(&0u32.to_be_bytes());                  // signCount = 0
    buf.extend_from_slice(&[0u8; 16]);                           // aaguid = zeros
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
fn encode_cose_key(verifying_key: &p256::ecdsa::VerifyingKey) -> Result<Vec<u8>> {
    use ciborium::value::Value;

    let point: EncodedPoint = verifying_key.to_encoded_point(false /* uncompressed */);
    let x = point
        .x()
        .ok_or_else(|| Error::UnexpectedError("P-256 x coordinate missing".into()))?
        .to_vec();
    let y = point
        .y()
        .ok_or_else(|| Error::UnexpectedError("P-256 y coordinate missing".into()))?
        .to_vec();

    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())),    // kty: EC2
        (Value::Integer(3i64.into()), Value::Integer((-7i64).into())), // alg: ES256
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())), // crv: P-256
        (Value::Integer((-2i64).into()), Value::Bytes(x)),              // x
        (Value::Integer((-3i64).into()), Value::Bytes(y)),              // y
    ]);

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&cose_key, &mut buf)
        .map_err(|e| Error::UnexpectedError(format!("COSE key CBOR encoding failed: {}", e)))?;
    Ok(buf)
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
// Generates a P-256 key pair, builds all required WebAuthn structures, and
// returns both the credential JSON (for the site) and the key material (for
// KDBX storage).
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

    let signing_key = SigningKey::random(&mut OsRng);

    let mut cred_id_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut cred_id_bytes);
    let credential_id_b64url = BASE64URL_NOPAD.encode(&cred_id_bytes);

    let cose_key_bytes = encode_cose_key(signing_key.verifying_key())?;
    let auth_data = build_auth_data_create(&rp_id, &cred_id_bytes, &cose_key_bytes);

    let auth_data_b64url = BASE64URL_NOPAD.encode(&auth_data);
    let attestation_object = encode_attestation_object(auth_data)?;

    let client_data = serde_json::json!({
        "type": "webauthn.create",
        "challenge": BASE64URL_NOPAD.encode(&challenge_bytes),
        "origin": origin,
        "crossOrigin": false,
    });
    let client_data_json = serde_json::to_string(&client_data)
        .map_err(|e| Error::UnexpectedError(format!("clientDataJSON serialization failed: {}", e)))?;

    let pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| Error::UnexpectedError(format!("PEM encoding failed: {}", e)))?;
    let private_key_pem = pem.as_str().to_string();

    let encoded_point = signing_key.verifying_key().to_encoded_point(false);
    const P256_SPKI_PREFIX: &[u8] = &[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    let mut public_key_spki = Vec::with_capacity(91);
    public_key_spki.extend_from_slice(P256_SPKI_PREFIX);
    public_key_spki.extend_from_slice(encoded_point.as_bytes());
    let public_key_b64url = BASE64URL_NOPAD.encode(&public_key_spki);

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
            "publicKeyAlgorithm": -7_i64,
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
// the pre-computed `clientDataHash` (e.g. iOS autofill extension).
//
// Generates a new P-256 key pair, builds the attestation object (fmt="none"),
// and returns the individual fields needed by `ASPasskeyRegistrationCredential`
// plus the private key PEM for storage.
pub fn create_passkey_with_hash(
    rp_id: &str,
    rp_name: &str,
    user_name: &str,
    user_handle_b64url: &str,
    _client_data_hash: &[u8],
) -> Result<PasskeyCreationWithHashResult> {
    let signing_key = SigningKey::random(&mut OsRng);

    let mut cred_id_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut cred_id_bytes);
    let credential_id_b64url = BASE64URL_NOPAD.encode(&cred_id_bytes);

    let cose_key_bytes = encode_cose_key(signing_key.verifying_key())?;
    let auth_data = build_auth_data_create(rp_id, &cred_id_bytes, &cose_key_bytes);
    let attestation_object = encode_attestation_object(auth_data)?;
    let attestation_object_b64url = BASE64URL_NOPAD.encode(&attestation_object);

    let pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| Error::UnexpectedError(format!("PEM encoding failed: {}", e)))?;
    let private_key_pem = pem.as_str().to_string();

    Ok(PasskeyCreationWithHashResult {
        attestation_object_b64url,
        credential_id_b64url,
        private_key_pem,
        rp_id: rp_id.to_string(),
        rp_name: rp_name.to_string(),
        username: user_name.to_string(),
        user_handle_b64url: user_handle_b64url.to_string(),
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
    let client_data_json = serde_json::to_string(&client_data)
        .map_err(|e| Error::UnexpectedError(format!("clientDataJSON serialization failed: {}", e)))?;

    let auth_data = build_auth_data_get(effective_rp_id, 0u32);

    let signing_key = SigningKey::from_pkcs8_pem(private_key_pem)
        .map_err(|e| Error::UnexpectedError(format!("Failed to decode private key PEM: {}", e)))?;

    let client_data_hash = Sha256::digest(client_data_json.as_bytes());
    let mut sig_input = Vec::with_capacity(auth_data.len() + 32);
    sig_input.extend_from_slice(&auth_data);
    sig_input.extend_from_slice(&client_data_hash);

    let signature: Signature = signing_key.sign(&sig_input);
    let sig_der = signature.to_der();

    let credential_json = serde_json::to_string(&serde_json::json!({
        "id":   credential_id_b64url,
        "rawId": credential_id_b64url,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {},
        "response": {
            "authenticatorData": BASE64URL_NOPAD.encode(&auth_data),
            "clientDataJSON":    BASE64URL_NOPAD.encode(client_data_json.as_bytes()),
            "signature":         BASE64URL_NOPAD.encode(sig_der.as_bytes()),
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
pub fn sign_assertion_with_hash(
    credential_id_b64url: &str,
    rp_id: &str,
    user_handle_b64url: &str,
    private_key_pem: &str,
    client_data_hash: &[u8],
) -> Result<PasskeyAssertionWithHashResult> {
    let auth_data = build_auth_data_get(rp_id, 0u32);

    let signing_key = SigningKey::from_pkcs8_pem(private_key_pem)
        .map_err(|e| Error::UnexpectedError(format!("Failed to decode private key PEM: {}", e)))?;

    // Sign: authenticatorData || clientDataHash
    let mut sig_input = Vec::with_capacity(auth_data.len() + client_data_hash.len());
    sig_input.extend_from_slice(&auth_data);
    sig_input.extend_from_slice(client_data_hash);

    let signature: Signature = signing_key.sign(&sig_input);

    let sig_der = signature.to_der();

    Ok(PasskeyAssertionWithHashResult {
        signature_b64url: BASE64URL_NOPAD.encode(sig_der.as_bytes()),
        authenticator_data_b64url: BASE64URL_NOPAD.encode(&auth_data),
        credential_id_b64url: credential_id_b64url.to_string(),
        user_handle_b64url: user_handle_b64url.to_string(),
        rp_id: rp_id.to_string(),
    })
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
        let result = create_passkey(&creation_opts, origin)
            .expect("passkey creation should succeed");

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
        assert_eq!(&auth_data_bytes[..32], expected_rp_hash.as_slice());
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
}
