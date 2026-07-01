use std::sync::Arc;

// Builds a rustls ClientConfig that verifies servers against the bundled
// webpki-roots (the Mozilla CA set), matching the behaviour reqwest had on 0.12.
//
// reqwest 0.13's only rustls option uses rustls-platform-verifier, which on
// Android must be initialised with the JVM Context before any TLS handshake or
// it panics at runtime ("Expect rustls-platform-verifier to be initialized").
// We side-step that entirely by handing this config to reqwest via
// `use_preconfigured_tls`, so the platform verifier is never invoked. The
// resulting trust behaviour is identical on every platform.
pub(crate) fn webpki_roots_rustls_config() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("rustls default protocol versions are valid")
    .with_root_certificates(roots)
    .with_no_client_auth()
}
