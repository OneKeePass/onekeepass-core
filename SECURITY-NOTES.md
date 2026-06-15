# Security Notes — Dependency Advisories

Tracking of known `cargo audit` / RustSec advisories that affect this crate's
dependency tree, and the decision taken for each. Update this file whenever an
advisory is resolved or a new one is accepted.

Run `cargo audit` from this directory. Ignored advisories live in
[.cargo/audit.toml](.cargo/audit.toml). As of the last review the only
non-ignored output is the three allowed *warnings* listed at the bottom — no
open vulnerabilities.

---

## RUSTSEC-2026-0154 — russh unbounded SSH-agent frame allocation — RESOLVED

- **CVE:** CVE-2026-46673 · **Severity:** HIGH (DoS)
- **Advisory:** https://github.com/Eugeny/russh/security/advisories/GHSA-g9f8-wqj9-fjw5
- **Status:** **Fixed.** Upgraded `russh 0.52.1 → 0.61.2` and `russh-sftp 2.1.1 → 2.3.0`
  (patched in russh ≥ 0.60.3). `russh-keys` was dropped — keys now live in `russh::keys`.
- **Note:** The flaw is in the SSH **agent** server/client frame parsing, which
  OneKeePass never uses (SFTP runs as a client with directly-loaded keys), so
  real exposure was low even before the bump.
- **Downstream:** desktop (path dep) and the mobile FFI (local path core 0.23.0)
  lockfiles were re-resolved to the fixed versions. When mobile returns to a
  git-tag core dependency, the new tag must contain this bump.

---

## RUSTSEC-2023-0071 — rsa "Marvin Attack" timing side-channel — ACCEPTED (no fix available)

- **CVE:** CVE-2023-49092 · **Severity:** MEDIUM (attack complexity HIGH)
- **Advisory:** https://github.com/RustCrypto/RSA/issues/626
- **Status:** **Accepted / ignored** in `audit.toml`. There is **no patched
  version** (`patched = []`); the upstream constant-time rewrite is still in progress.
- **Why we can't remove it:** `rsa` enters the tree two ways —
  - directly, for passkey **RS256** signing ([src/passkey_crypto.rs](src/passkey_crypto.rs)), and
  - transitively via **russh** (SSH RSA keys).

  Dropping RS256 passkey support would not clear the advisory because russh/SFTP
  still pulls `rsa` in.
- **Why risk is low here:** the Marvin attack needs an attacker to observe many
  timing samples of chosen-input RSA private-key operations over the network.
  In OneKeePass, RSA private-key operations are **local, on-device** (signing a
  WebAuthn challenge) and are never exposed as a queryable network oracle.
- **Revisit:** when RustCrypto ships a constant-time `rsa` release, remove the
  ignore entry and upgrade.

---

## rustls-webpki / quinn-proto (WebDav HTTP stack) — RESOLVED

Surfaced transitively via `reqwest_dav → reqwest`. Fixed by lockfile bumps
(no `Cargo.toml` change needed):

- **rustls-webpki 0.103.8 → 0.103.13** — clears RUSTSEC-2026-0104 (CRL parse
  panic), -0098 / -0099 (name-constraint bypasses), -0049 (CRL authority logic).
- **quinn-proto 0.11.13 → 0.11.14** — clears RUSTSEC-2026-0037 (endpoint DoS).

Same bumps applied to the desktop (already resolved) and mobile FFI lockfiles.

---

## Crypto backend & TLS notes (not advisories — build/runtime considerations)

**aws-lc-rs via russh 0.61.** russh 0.52 used pure-RustCrypto and pulled no native
crypto backend. russh 0.61 *requires* a vetted backend; its default is `aws-lc-rs`
(needs cmake/C). Verified building for both iOS and Android. A `ring` backend is
available as an alternative if aws-lc-rs ever causes cross-compile trouble:

```toml
russh = { version = "0.61.2", default-features = false, features = ["ring", "flate2", "rsa"] }
```

**reqwest 0.13 / reqwest_dav 0.3.3.** Upgraded reqwest_dav 0.1.15 → 0.3.3 (WebDav
API source-compatible) which moves reqwest 0.12 → 0.13. Consequences:

- reqwest 0.13 renamed the rustls feature `rustls-tls` → `rustls`; the favicon
  `[dependencies.reqwest]` was updated to match.
- The tree now unifies on **aws-lc-rs** (reqwest 0.13's `rustls` uses it too), so
  `ring` is no longer pulled — one native crypto backend instead of two.
- **Android platform-verifier issue — RESOLVED in Rust.** reqwest 0.13's only
  rustls options (`rustls` / `rustls-no-provider`) force `rustls-platform-verifier`;
  the bundled-`webpki-roots` option from 0.12 is gone. On Android that verifier
  needs the JVM `Context` wired in via JNI at startup
  (`rustls_platform_verifier::android::init_*`) or it panics at runtime
  ("Expect rustls-platform-verifier to be initialized") — confirmed on a device.
  Rather than add a JNI/AAR/Proguard init bridge, we hand reqwest a rustls config
  trusting the bundled Mozilla roots via `tls_backend_preconfigured`
  ([src/net_tls.rs](src/net_tls.rs)). Per reqwest's source this routes TLS through
  the `BuiltRustls` backend instead of the default `Rustls` backend — and the
  default backend is the only place the platform verifier is constructed — so it
  is never invoked on any platform. Applied at both reqwest client sites:
  [webdav.rs](src/remote_storage/storage_service/webdav.rs) (keeps the existing
  `danger_accept_invalid_certs` branch for the "allow untrusted cert" option) and
  [favicon.rs](src/favicon.rs). Trust behaviour matches the old reqwest 0.12.
  `rustls-platform-verifier` remains compiled (pulled by reqwest's `rustls`
  feature) but is dead code at runtime. Note the coupling reqwest documents: the
  preconfigured `rustls::ClientConfig` version must match reqwest's rustls (we pin
  `rustls = "0.23"`, which cargo unifies with reqwest's). If a future reqwest bumps
  to a new rustls major, the type downcast fails → reqwest reports "Unknown TLS
  backend" at client build — a loud, safe failure (not silent loss of verification)
  that signals the pin needs updating.
- On desktop, the Tauri crate keeps its own direct `reqwest 0.12`, so desktop
  currently compiles both 0.12 and 0.13 (build bloat only). Bump the desktop
  crate's reqwest to 0.13 to deduplicate when convenient.

---

## Allowed warnings (informational — not vulnerabilities)

These are surfaced by `cargo audit` as warnings and intentionally left as-is:

- **RUSTSEC-2024-0436** — `paste 1.0.15` unmaintained. Build-time proc-macro
  only; no runtime impact and no drop-in replacement.
- **RUSTSEC-2026-0097** — `rand 0.8.5` / `0.9.2` unsound *only* when a custom
  logger calls `rand::rng()` re-entrantly. We don't use that pattern.
