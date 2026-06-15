use image::imageops::FilterType;
use image::ImageFormat;
use regex::Regex;
use std::io::Cursor;

use crate::error::{Error, Result};

const TARGET_SIZE: u32 = 64;
const TIMEOUT_SECS: u64 = 8;
const MAX_BODY_BYTES: u64 = 2 * 1024 * 1024;

// Many CDNs (Squarespace, Cloudflare, Wix, ...) return 403 / serve HTML error
// pages to clients that don't look like a real browser. A common Chrome UA
// avoids that without raising any other red flags.
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) \
     Chrome/124.0.0.0 Safari/537.36";

pub async fn download_favicon(url: &str) -> Result<Vec<u8>> {
    log::debug!("Going to download favicon for url {}", url);

    let parsed = url::Url::parse(url).map_err(|e| Error::UnexpectedError(e.to_string()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| Error::UnexpectedError("URL has no host".into()))?;
    let scheme = parsed.scheme();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(TIMEOUT_SECS))
        .user_agent(USER_AGENT)
        // Use bundled webpki-roots rather than reqwest 0.13's default
        // rustls-platform-verifier (which needs JVM init on Android). See net_tls.
        .tls_backend_preconfigured(crate::net_tls::webpki_roots_rustls_config())
        .build()
        .map_err(|e| Error::UnexpectedError(e.to_string()))?;

    // Step 1: try /favicon.ico directly. reqwest's default redirect policy
    // follows up to 10 hops, so an .ico that 302s to a CDN-hosted PNG works.
    let favicon_ico_url = format!("{}://{}/favicon.ico", scheme, host);
    log::debug!("Trying direct favicon at {}", &favicon_ico_url);
    match fetch_bytes(&client, &favicon_ico_url).await {
        Ok(bytes) => match normalize_image_to_png(&bytes, TARGET_SIZE) {
            Ok(png) => {
                log::debug!("Got favicon via /favicon.ico");
                return Ok(png);
            }
            Err(e) => log::debug!("/favicon.ico bytes were not a usable image: {}", e),
        },
        Err(e) => log::debug!("/favicon.ico fetch failed: {}", e),
    }

    // Step 2: parse the homepage and look for <link rel="icon"> /
    // <link rel="shortcut icon"> / <link rel="apple-touch-icon">.
    // We use the *homepage* (scheme://host/) rather than the user-supplied URL
    // — that URL might be the .ico itself (which we just tried) or a deep link
    // (which often won't carry the icon link tag).
    let homepage = format!("{}://{}/", scheme, host);
    log::debug!("Fetching homepage {} for icon-link discovery", &homepage);
    match fetch_bytes(&client, &homepage).await {
        Ok(html_bytes) => {
            let html = String::from_utf8_lossy(&html_bytes);
            if let Some(icon_url) = extract_icon_url_from_html(&html, &homepage) {
                log::debug!("Discovered icon link {}", &icon_url);
                match fetch_bytes(&client, &icon_url).await {
                    Ok(bytes) => match normalize_image_to_png(&bytes, TARGET_SIZE) {
                        Ok(png) => {
                            log::debug!("Got favicon via <link> tag");
                            return Ok(png);
                        }
                        Err(e) => log::debug!("Linked icon bytes were not usable: {}", e),
                    },
                    Err(e) => log::debug!("Linked icon fetch failed: {}", e),
                }
            } else {
                log::debug!("No icon <link> tag found in homepage");
            }
        }
        Err(e) => log::debug!("Homepage fetch failed: {}", e),
    }

    Err(Error::UnexpectedError(format!(
        "Could not download a usable favicon from {}",
        url
    )))
}

async fn fetch_bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let resp = client
        .get(url)
        // Hint that we want an image or HTML page, not e.g. a JSON API response.
        .header(
            reqwest::header::ACCEPT,
            "image/png,image/x-icon,image/svg+xml,image/*;q=0.9,text/html;q=0.8,*/*;q=0.5",
        )
        .send()
        .await
        .map_err(|e| Error::UnexpectedError(e.to_string()))?;

    if !resp.status().is_success() {
        return Err(Error::UnexpectedError(format!(
            "HTTP {} for {}",
            resp.status(),
            url
        )));
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| Error::UnexpectedError(e.to_string()))?;

    if bytes.len() as u64 > MAX_BODY_BYTES {
        return Err(Error::UnexpectedError(format!(
            "Response from {} exceeds size limit ({} bytes)",
            url,
            bytes.len()
        )));
    }

    Ok(bytes.to_vec())
}

// Extracts the href from the first matching <link rel="..."> tag for icon-like
// rel values: "icon", "shortcut icon", "apple-touch-icon",
// "apple-touch-icon-precomposed".
fn extract_icon_url_from_html(html: &str, base_url: &str) -> Option<String> {
    let re = Regex::new(
        r#"(?is)<link\b[^>]*\brel\s*=\s*["']?(?:shortcut\s+icon|icon|apple-touch-icon(?:-precomposed)?)["']?[^>]*\bhref\s*=\s*["']([^"']+)["']"#,
    )
    .ok()?;

    // Try rel-then-href ordering first; if not found, try href-then-rel.
    let href = if let Some(c) = re.captures(html) {
        c.get(1)?.as_str().to_string()
    } else {
        let re2 = Regex::new(
            r#"(?is)<link\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*\brel\s*=\s*["']?(?:shortcut\s+icon|icon|apple-touch-icon(?:-precomposed)?)["']?"#,
        )
        .ok()?;
        re2.captures(html)?.get(1)?.as_str().to_string()
    };

    // Resolve href relative to the page URL.
    let base = url::Url::parse(base_url).ok()?;
    let resolved = base.join(&href).ok()?;
    Some(resolved.to_string())
}

pub fn normalize_image_to_png(input: &[u8], target: u32) -> Result<Vec<u8>> {
    log::debug!("In normalize_image_to_png...");
    // Try ICO first (multi-image container)
    if let Ok(icon_dir) = ico::IconDir::read(Cursor::new(input)) {
        // Pick the largest entry
        let entry = icon_dir
            .entries()
            .iter()
            .max_by_key(|e| e.width() as u32 * e.height() as u32)
            .ok_or_else(|| Error::UnexpectedError("ICO file has no entries".into()))?;
        let rgba = entry
            .decode()
            .map_err(|e| Error::UnexpectedError(e.to_string()))?;
        let img = image::DynamicImage::ImageRgba8(
            image::RgbaImage::from_raw(rgba.width(), rgba.height(), rgba.rgba_data().to_vec())
                .ok_or_else(|| {
                    Error::UnexpectedError("Failed to build image from ICO data".into())
                })?,
        );
        log::debug!("Encoded image png resized");
        return encode_png_resized(img, target);
    }

    log::debug!("Trying generic image (PNG, JPEG, etc.)");
    // Try generic image (PNG, JPEG, etc.)
    let img = image::load_from_memory(input)
        .map_err(|e| Error::UnexpectedError(format!("Unsupported image format: {}", e)))?;
    encode_png_resized(img, target)
}

fn encode_png_resized(img: image::DynamicImage, target: u32) -> Result<Vec<u8>> {
    let resized = img.resize_exact(target, target, FilterType::Lanczos3);
    let mut out = Cursor::new(Vec::new());
    resized
        .write_to(&mut out, ImageFormat::Png)
        .map_err(|e| Error::UnexpectedError(e.to_string()))?;
    Ok(out.into_inner())
}
