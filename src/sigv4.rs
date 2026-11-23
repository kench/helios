//! AWS Signature Version 4 for requests Helios makes with its credentials-provider credentials
//! (LLD 3, section 3.2): the egress echo first, any IAM-signed call later.
//!
//! Signs in the request headers (`Authorization`, `X-Amz-Date`, and `X-Amz-Security-Token`
//! for temporary credentials), as AWS describes in "Create a signed AWS API request". Tested
//! against AWS's SigV4 test suite (`tests/data/sigv4`). Paths must already be in their
//! canonical form (absolute, normalized, only unreserved characters and `/`): the callers sign
//! fixed paths, so the signer refuses others rather than guessing their encoding.

use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_credential_types::Credentials;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

/// The request to sign.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    /// `GET`, `POST`...
    pub method: &'a str,
    /// The `Host` header's value (signed; the caller sends the same).
    pub host: &'a str,
    /// The absolute path, in canonical form.
    pub path: &'a str,
    /// Query parameters, not yet encoded.
    pub query: &'a [(&'a str, &'a str)],
    /// Other headers to sign and send, as the caller sends them.
    pub headers: &'a [(&'a str, &'a str)],
    /// The body.
    pub body: &'a [u8],
}

/// Where the request goes, and how it's signed.
#[derive(Debug, Clone, Copy)]
pub struct Scope<'a> {
    /// The AWS region, for example `us-west-2`.
    pub region: &'a str,
    /// The service's signing name, for example `execute-api`.
    pub service: &'a str,
    /// Also sign the body's hash in `X-Amz-Content-Sha256` (S3 needs it; API Gateway doesn't).
    pub sign_body: bool,
}

/// The request can't be signed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    /// The path isn't in canonical form.
    #[error("the path {0:?} isn't a canonical absolute path")]
    Path(String),
    /// A header name isn't a valid token, or a value holds a line break.
    #[error("the header {0:?} can't be signed")]
    Header(String),
    /// The clock is before 1970.
    #[error("the clock is before 1970")]
    Clock,
}

/// Signs `request` with `credentials` at `now`: the headers to add to it, in order.
///
/// # Errors
///
/// [`SignError`] for a path or header that can't be signed, or a clock before 1970.
pub fn sign(
    request: &Request<'_>,
    credentials: &Credentials,
    scope: Scope<'_>,
    now: SystemTime,
) -> Result<Vec<(&'static str, String)>, SignError> {
    Ok(signing(request, credentials, scope, now)?.headers)
}

/// Each stage of signing a request, for [`sign`] and the tests.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the canonical request and string to sign are checked by the tests"
    )
)]
struct Signing {
    canonical_request: String,
    string_to_sign: String,
    headers: Vec<(&'static str, String)>,
}

fn signing(
    request: &Request<'_>,
    credentials: &Credentials,
    scope: Scope<'_>,
    now: SystemTime,
) -> Result<Signing, SignError> {
    let (date, timestamp) = amz_date(now)?;
    let mut headers: Vec<(&'static str, String)> = Vec::new();
    if let Some(token) = credentials.session_token() {
        headers.push(("X-Amz-Security-Token", token.to_owned()));
    }
    let body_hash = hex(&Sha256::digest(request.body));
    if scope.sign_body {
        headers.push(("X-Amz-Content-Sha256", body_hash.clone()));
    }
    headers.push(("X-Amz-Date", timestamp.clone()));
    let (canonical_request, signed_headers) = canonical_request(request, &headers, &body_hash)?;
    let credential_scope = format!("{date}/{}/{}/aws4_request", scope.region, scope.service);
    let string_to_sign = string_to_sign(&timestamp, &credential_scope, &canonical_request);
    let key = signing_key(
        credentials.secret_access_key(),
        &date,
        scope.region,
        scope.service,
    );
    let signature = hex(&hmac(&key, string_to_sign.as_bytes()));
    headers.push((
        "Authorization",
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, \
             Signature={signature}",
            credentials.access_key_id()
        ),
    ));
    Ok(Signing {
        canonical_request,
        string_to_sign,
        headers,
    })
}

/// The canonical request and its signed-header list.
fn canonical_request(
    request: &Request<'_>,
    added: &[(&str, String)],
    body_hash: &str,
) -> Result<(String, String), SignError> {
    if !canonical_path(request.path) {
        return Err(SignError::Path(request.path.to_owned()));
    }
    let mut query: Vec<(String, String)> = request
        .query
        .iter()
        .map(|(key, value)| (encode(key), encode(value)))
        .collect();
    query.sort();
    let query = query
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&");

    // Lower-case names, values trimmed with inner runs of spaces collapsed, and repeated
    // headers joined with commas in the order they're sent.
    let mut headers: Vec<(String, String)> = Vec::new();
    let all = std::iter::once(("host", request.host))
        .chain(request.headers.iter().copied())
        .chain(added.iter().map(|(name, value)| (*name, value.as_str())));
    for (name, value) in all {
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_graphic() && b != b':')
            || value.contains(['\r', '\n'])
        {
            return Err(SignError::Header(name.to_owned()));
        }
        let name = name.to_ascii_lowercase();
        let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
        match headers.iter_mut().find(|(existing, _)| *existing == name) {
            Some((_, existing)) => {
                existing.push(',');
                existing.push_str(&value);
            }
            None => headers.push((name, value)),
        }
    }
    headers.sort_by(|(a, _), (b, _)| a.cmp(b));
    let signed = headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let mut canonical = format!("{}\n{}\n{query}\n", request.method, request.path);
    for (name, value) in &headers {
        let _ = writeln!(canonical, "{name}:{value}");
    }
    let _ = write!(canonical, "\n{signed}\n{body_hash}");
    Ok((canonical, signed))
}

fn string_to_sign(timestamp: &str, credential_scope: &str, canonical: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256\n{timestamp}\n{credential_scope}\n{}",
        hex(&Sha256::digest(canonical.as_bytes()))
    )
}

fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let key = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let key = hmac(&key, region.as_bytes());
    let key = hmac(&key, service.as_bytes());
    hmac(&key, b"aws4_request")
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    // HMAC takes a key of any length, so this can't fail.
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// RFC 3986's unreserved characters stay; everything else is `%XX` (upper-case), as SigV4
/// encodes query keys and values.
fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// An absolute path of unreserved characters and single slashes, with no `.` or `..` segments.
fn canonical_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains("//")
        && path
            .split('/')
            .all(|segment| segment != "." && segment != "..")
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/'))
}

/// The date (`YYYYMMDD`) and timestamp (`YYYYMMDDTHHMMSSZ`) of `now`, in UTC.
fn amz_date(now: SystemTime) -> Result<(String, String), SignError> {
    let seconds = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SignError::Clock)?
        .as_secs();
    let days = i64::try_from(seconds / 86_400).map_err(|_| SignError::Clock)?;
    let (year, month, day) = civil(days);
    let rest = seconds % 86_400;
    let date = format!("{year:04}{month:02}{day:02}");
    let timestamp = format!(
        "{date}T{:02}{:02}{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    );
    Ok((date, timestamp))
}

/// The proleptic Gregorian date of `days` since 1970-01-01 (Howard Hinnant's algorithm).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

#[cfg(test)]
mod tests;
