//! The web module's HTTP side (LLD 13, sections 3 to 5): the console's files, its
//! `config.json`, signing in and out, and the local Control API behind a session.
//!
//! [`serve`] answers one request; [`super::server`] runs it for each connection. Every response
//! carries the console's security headers: a content security policy of its own origin (React
//! Router's inline scripts allowed by hash, as the cloud's CloudFront does), no framing, no
//! referrer, no sniffing. No HSTS: the console is plain HTTP (owner, 2026-11-27).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::auth::{self, Sessions, Throttle};
use super::control::{self, Device};

/// The session cookie's name.
pub(crate) const COOKIE: &str = "helios-session";
/// The header every write must carry, against cross-site request forgery.
pub(crate) const WRITE_HEADER: &str = "x-helios-request";
/// The largest request body read.
pub(crate) const MAX_BODY: usize = 64 * 1024;

/// A request, as far as the module reads one.
#[derive(Debug, Clone, Default)]
pub(crate) struct Request {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    /// Lower-case names.
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub peer: Option<IpAddr>,
}

/// A response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn json(status: u16, value: &Value) -> Self {
        let mut response = Self::new(status);
        response.header("content-type", "application/json");
        response.header("cache-control", "no-store");
        response.body = value.to_string().into_bytes();
        response
    }

    fn api(answer: &control::Answer) -> Self {
        let mut response = Self::json(answer.status, &answer.body);
        if let Some(error) = answer.error {
            response.header("x-amzn-errortype", error);
        }
        response
    }

    fn error(status: u16, error: &str, message: &str) -> Self {
        let mut response = Self::json(status, &json!({ "message": message }));
        response.header("x-amzn-errortype", error);
        response
    }

    fn header(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_owned(), value.to_owned()));
    }

    /// The value of header `name`, if set.
    #[cfg(test)]
    pub(crate) fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// What the HTTP side holds: the device, the password, the sessions and the console's files.
#[derive(Debug)]
pub(crate) struct Web {
    pub device: Device,
    pub name: String,
    pub password_hash: String,
    pub console_dir: PathBuf,
    pub sessions: Mutex<Sessions>,
    pub throttle: Mutex<Throttle>,
}

/// Answers `request`.
pub(crate) async fn serve(web: &Web, request: &Request) -> Response {
    let mut response = route(web, request).await;
    secure(&mut response, &web.console_dir);
    response
}

async fn route(web: &Web, request: &Request) -> Response {
    let path = request.path.as_str();
    match (request.method.as_str(), path) {
        ("GET", "/config.json") => Response::json(
            200,
            &json!({ "apiUrl": "", "auth": { "kind": "device" }, "name": web.name }),
        ),
        (method, "/v1/local/session") => session(web, method, request),
        (_, _) if path.starts_with("/v1/") => {
            let Some(session) = signed_in(web, request) else {
                return Response::error(401, "Unauthorized", "Sign in first.");
            };
            if request.method != "GET"
                && let Err(response) = write_allowed(request)
            {
                return response;
            }
            let body = if request.body.is_empty() {
                Value::Null
            } else {
                match serde_json::from_slice(&request.body) {
                    Ok(body) => body,
                    Err(_) => {
                        return Response::error(
                            400,
                            "SerializationException",
                            "The body isn't JSON.",
                        );
                    }
                }
            };
            let answer =
                control::handle(&web.device, &request.method, path, &request.query, &body).await;
            if request.method != "GET" {
                // The audit line: what, from where, which session (its start), the result.
                // Never the body, which can hold a passphrase.
                tracing::info!(
                    target: "helios::audit",
                    method = %request.method,
                    path,
                    source = %request.peer.map_or_else(|| "unknown".into(), |p| p.to_string()),
                    session = &session[..8],
                    status = answer.status,
                    error = answer.error.unwrap_or(""),
                    "local console change"
                );
            }
            Response::api(&answer)
        }
        ("GET" | "HEAD", _) => file(&web.console_dir, path),
        _ => Response::error(405, "MethodNotAllowed", "Not here."),
    }
}

/// `POST` signs in (`{"password"}`), `GET` says whether the cookie's session is live, `DELETE`
/// signs out.
fn session(web: &Web, method: &str, request: &Request) -> Response {
    let now = Instant::now();
    match method {
        "GET" => match signed_in(web, request) {
            Some(_) => Response::json(200, &json!({ "signedIn": true, "name": web.name })),
            None => Response::error(401, "Unauthorized", "Not signed in."),
        },
        "DELETE" => {
            if let Some(id) = cookie(request) {
                lock(&web.sessions).end(&id);
            }
            let mut response = Response::new(204);
            response.header(
                "set-cookie",
                &format!("{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),
            );
            response
        }
        "POST" => {
            if let Err(response) = write_allowed(request) {
                return response;
            }
            let peer = request.peer.unwrap_or(IpAddr::from([0, 0, 0, 0]));
            if let Some(wait) = lock(&web.throttle).wait(peer, now) {
                let mut response = Response::error(
                    429,
                    "TooManyRequestsException",
                    "Too many wrong passwords: wait, then try again.",
                );
                response.header("retry-after", &wait.as_secs().max(1).to_string());
                return response;
            }
            let password = serde_json::from_slice::<Value>(&request.body)
                .ok()
                .and_then(|body| body.get("password")?.as_str().map(str::to_owned));
            let Some(password) = password else {
                return Response::error(400, "ValidationException", "password is required");
            };
            if !auth::password_matches(&web.password_hash, password.as_bytes()) {
                lock(&web.throttle).failed(peer, now);
                tracing::warn!(target: "helios::audit", source = %peer, "local console: wrong password");
                return Response::error(401, "Unauthorized", "That's not the password.");
            }
            lock(&web.throttle).succeeded(peer);
            let Ok(id) = auth::new_session_id() else {
                return Response::error(500, "InternalError", "No session could be made.");
            };
            lock(&web.sessions).start(id.clone(), now);
            tracing::info!(target: "helios::audit", source = %peer, session = &id[..8], "local console: signed in");
            let mut response = Response::new(204);
            response.header(
                "set-cookie",
                &format!(
                    "{COOKIE}={id}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
                    auth::LIFETIME.as_secs()
                ),
            );
            response
        }
        _ => Response::error(405, "MethodNotAllowed", "Not here."),
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn cookie(request: &Request) -> Option<String> {
    request.headers.get("cookie")?.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        (name == COOKIE && !value.is_empty()).then(|| value.to_owned())
    })
}

/// The request's live session ID, if it has one.
fn signed_in(web: &Web, request: &Request) -> Option<String> {
    let id = cookie(request)?;
    lock(&web.sessions).check(&id, Instant::now()).then_some(id)
}

/// A write must say it's the console's own (a custom header a cross-site form can't send) and,
/// if the browser names an origin, come from this host.
fn write_allowed(request: &Request) -> Result<(), Response> {
    if request.headers.get(WRITE_HEADER).map(String::as_str) != Some("1") {
        return Err(Response::error(
            403,
            "Forbidden",
            "Changes must come from the console.",
        ));
    }
    if let Some(origin) = request.headers.get("origin") {
        let host = request
            .headers
            .get("host")
            .map(String::as_str)
            .unwrap_or("");
        let from = origin
            .strip_prefix("http://")
            .or_else(|| origin.strip_prefix("https://"))
            .unwrap_or("");
        if from != host {
            return Err(Response::error(
                403,
                "Forbidden",
                "Changes must come from this console's own page.",
            ));
        }
    }
    Ok(())
}

/// A file from the console's build: `index.html` for `/` and for the app's own routes (any path
/// that isn't a file). 503 if the console isn't installed.
fn file(dir: &Path, path: &str) -> Response {
    let index = dir.join("index.html");
    let Ok(index_bytes) = std::fs::read(&index) else {
        let mut response = Response::new(503);
        response.header("content-type", "text/plain; charset=utf-8");
        response.body =
            b"The Helios console isn't installed on this device (apt install helios-console).\n"
                .to_vec();
        return response;
    };
    let relative = Path::new(path.trim_start_matches('/'));
    let safe = relative
        .components()
        .all(|c| matches!(c, Component::Normal(_)));
    let candidate = dir.join(relative);
    let found = (safe && !path.ends_with('/'))
        .then(|| {
            std::fs::read(&candidate)
                .ok()
                .map(|bytes| (candidate, bytes))
        })
        .flatten();
    let (served, bytes) = found.unwrap_or((index, index_bytes));
    let mut response = Response::new(200);
    response.header("content-type", content_type(&served));
    let hashed = served
        .strip_prefix(dir)
        .is_ok_and(|p| p.starts_with("assets"));
    response.header(
        "cache-control",
        if hashed {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        },
    );
    response.body = bytes;
    response
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Adds the console's security headers.
fn secure(response: &mut Response, dir: &Path) {
    let hashes = std::fs::read_to_string(dir.join("index.html"))
        .map(|html| inline_script_hashes(&html))
        .unwrap_or_default();
    response.header("content-security-policy", &content_security_policy(&hashes));
    response.header("x-frame-options", "DENY");
    response.header("x-content-type-options", "nosniff");
    response.header("referrer-policy", "no-referrer");
}

/// The CSP source (`'sha256-...'`) of each inline script in `html`, as helios-cloud's
/// `ConsoleStack` computes them: React Router writes its bootstrap into `index.html`.
pub(crate) fn inline_script_hashes(html: &str) -> Vec<String> {
    let mut hashes: Vec<String> = Vec::new();
    let lower = html.to_ascii_lowercase();
    let mut from = 0;
    while let Some(open) = lower[from..].find("<script") {
        let open = from + open;
        let Some(tag_end) = lower[open..].find('>') else {
            break;
        };
        let tag_end = open + tag_end;
        let attributes = &lower[open + "<script".len()..tag_end];
        let Some(close) = lower[tag_end..].find("</script>") else {
            break;
        };
        let close = tag_end + close;
        let body = &html[tag_end + 1..close];
        let has_src = attributes
            .split(|c: char| c.is_whitespace())
            .any(|attribute| attribute.starts_with("src="));
        if !has_src && !body.is_empty() {
            use base64::Engine as _;
            let digest = Sha256::digest(body.as_bytes());
            let source = format!(
                "'sha256-{}'",
                base64::engine::general_purpose::STANDARD.encode(digest)
            );
            if !hashes.contains(&source) {
                hashes.push(source);
            }
        }
        from = close + "</script>".len();
    }
    hashes
}

/// The console's content security policy: its own origin only, and the inline scripts by hash.
pub(crate) fn content_security_policy(hashes: &[String]) -> String {
    [
        "default-src 'self'".to_owned(),
        format!("script-src 'self' {}", hashes.join(" "))
            .trim()
            .to_owned(),
        "style-src 'self'".to_owned(),
        "img-src 'self' data:".to_owned(),
        "connect-src 'self'".to_owned(),
        "font-src 'self'".to_owned(),
        "object-src 'none'".to_owned(),
        "base-uri 'self'".to_owned(),
        "form-action 'self'".to_owned(),
        "frame-ancestors 'none'".to_owned(),
    ]
    .join("; ")
}

#[cfg(test)]
mod tests;
