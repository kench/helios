//! `rtmp-ingest` (LLD 4, section 4): nginx with the RTMP module runs under systemd
//! (`helios-rtmp.service`, static config `/etc/helios/rtmp/nginx.conf`); this side is the
//! daemon's half.
//!
//! - **The publish hook:** nginx POSTs `on_publish` / `on_publish_done` to
//!   `http://127.0.0.1:<hook_port>/rtmp/...`. Each call goes to the engine, which accepts a
//!   publish (200) if its key belongs to a stream and isn't already publishing, or refuses it (403,
//!   and nginx drops the camera). No token: the hook is on loopback, and local processes are
//!   trusted (owner, 2026-11-21).
//! - **The statistics page:** at start and every 10 s (2 s after a failure) the daemon reads
//!   nginx's `rtmp_stat`, so it learns about cameras already publishing when it (re)starts,
//!   notices a `publish_done` it missed, and follows each camera's video bitrate (`bw_video`),
//!   which sets an adaptive stream's ceiling.
//!
//! nginx's requests are small and fixed, so the HTTP here is a minimal HTTP/1.x parser over a
//! loopback socket rather than a server library.

use std::collections::BTreeMap;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

/// How often the statistics page is read (a second in tests, which run on real sockets).
const STAT_INTERVAL: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 10 });
/// How soon a failed read is tried again: at boot the daemon starts before nginx listens.
const STAT_RETRY: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 2 });
/// How long one hook request or statistics read may take.
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// The largest hook request and statistics page read.
const MAX_REQUEST: usize = 16 * 1024;
const MAX_STAT: usize = 1024 * 1024;
/// The RTMP application cameras publish to.
pub(crate) const APP: &str = "live";

/// What the ingest side tells the engine.
#[derive(Debug)]
pub(crate) enum IngestEvent {
    /// nginx asks whether a camera may publish `key`; answer on `accept`.
    Publish {
        key: String,
        address: String,
        accept: oneshot::Sender<bool>,
    },
    /// The camera publishing `key` stopped.
    PublishDone { key: String },
    /// Who is publishing, by key, from the statistics page; or why it couldn't be read.
    Publishers(Result<BTreeMap<String, Seen>, String>),
    /// The hook couldn't listen.
    HookFailed(String),
}

/// Runs the hook server and the statistics reader until `cancel` fires.
pub(crate) async fn run(
    hook_port: u16,
    stat_url: String,
    events: mpsc::UnboundedSender<IngestEvent>,
    cancel: CancellationToken,
) {
    let hook = serve_hook(hook_port, events.clone(), cancel.clone());
    let stats = async {
        loop {
            let publishers = read_stat(&stat_url).await;
            let wait = if publishers.is_ok() {
                STAT_INTERVAL
            } else {
                STAT_RETRY
            };
            if events.send(IngestEvent::Publishers(publishers)).is_err() {
                return;
            }
            tokio::select! {
                () = cancel.cancelled() => return,
                () = tokio::time::sleep(wait) => {}
            }
        }
    };
    tokio::join!(hook, stats);
}

async fn serve_hook(
    port: u16,
    events: mpsc::UnboundedSender<IngestEvent>,
    cancel: CancellationToken,
) {
    let listener = loop {
        match TcpListener::bind(("127.0.0.1", port)).await {
            Ok(listener) => break listener,
            Err(error) => {
                let _ = events.send(IngestEvent::HookFailed(format!(
                    "can't listen on 127.0.0.1:{port}: {error}"
                )));
                tokio::select! {
                    () = cancel.cancelled() => return,
                    () = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
            }
        }
    };
    tracing::info!(port, "RTMP publish hook listening");
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            accepted = listener.accept() => {
                if let Ok((stream, _)) = accepted {
                    tokio::spawn(hook_request(stream, events.clone()));
                }
            }
        }
    }
}

/// One request from nginx: parse it, ask the engine, answer.
async fn hook_request(mut stream: TcpStream, events: mpsc::UnboundedSender<IngestEvent>) {
    let status = match tokio::time::timeout(IO_TIMEOUT, read_request(&mut stream)).await {
        Ok(Some((path, body))) => decide(&path, &body, &events).await,
        _ => 400,
    };
    let reason = match status {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Bad Request",
    };
    let response =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let _ = tokio::time::timeout(IO_TIMEOUT, stream.write_all(response.as_bytes())).await;
}

/// The status for one hook call.
async fn decide(path: &str, body: &str, events: &mpsc::UnboundedSender<IngestEvent>) -> u16 {
    let form = parse_form(body);
    let field = |name: &str| form.get(name).cloned().unwrap_or_default();
    if form.get("app").is_some_and(|app| app != APP) {
        return 403;
    }
    match (path, field("call").as_str()) {
        ("/rtmp/publish", "publish") => {
            let (accept, answer) = oneshot::channel();
            let event = IngestEvent::Publish {
                key: field("name"),
                address: field("addr"),
                accept,
            };
            if events.send(event).is_err() {
                return 403;
            }
            match tokio::time::timeout(IO_TIMEOUT, answer).await {
                Ok(Ok(true)) => 200,
                _ => 403,
            }
        }
        ("/rtmp/publish_done", "publish_done") => {
            let _ = events.send(IngestEvent::PublishDone { key: field("name") });
            200
        }
        ("/rtmp/publish" | "/rtmp/publish_done", _) => 400,
        _ => 404,
    }
}

/// Reads a POST request: its path (without the query) and body. `None` if it isn't one.
async fn read_request(stream: &mut TcpStream) -> Option<(String, String)> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 2048];
    let header_end = loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(end) = find(&buffer, b"\r\n\r\n") {
            break end;
        }
        if buffer.len() > MAX_REQUEST {
            return None;
        }
    };
    let head = std::str::from_utf8(&buffer[..header_end]).ok()?;
    let mut lines = head.split("\r\n");
    let mut request = lines.next()?.split(' ');
    if request.next()? != "POST" {
        return None;
    }
    let path = request.next()?.split('?').next()?.to_owned();
    let length: usize = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse().ok())
        .unwrap_or(0);
    if length > MAX_REQUEST {
        return None;
    }
    let mut body = buffer[header_end + 4..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(length);
    Some((path, String::from_utf8(body).ok()?))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// An `application/x-www-form-urlencoded` body.
pub(crate) fn parse_form(body: &str) -> BTreeMap<String, String> {
    body.split('&')
        .filter_map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            Some((decode(name)?, decode(value)?))
        })
        .filter(|(name, _)| !name.is_empty())
        .collect()
}

/// Percent-decoding, with `+` as a space.
fn decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = text.get(i + 1..i + 3)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 2;
            }
            byte => out.push(byte),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// Reads the statistics page (`http://127.0.0.1:<port><path>`) and returns who is publishing.
async fn read_stat(url: &str) -> Result<BTreeMap<String, Seen>, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("{url}: not an http:// URL"))?;
    let (authority, path) = rest
        .split_once('/')
        .map_or((rest, "/".to_owned()), |(a, p)| (a, format!("/{p}")));
    let fetch = async {
        let mut stream = TcpStream::connect(authority)
            .await
            .map_err(|e| format!("can't connect to {authority}: {e}"))?;
        let request = format!("GET {path} HTTP/1.0\r\nHost: {authority}\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("can't ask {url}: {e}"))?;
        let mut response = Vec::new();
        (&mut stream)
            .take(u64::try_from(MAX_STAT).unwrap_or(u64::MAX))
            .read_to_end(&mut response)
            .await
            .map_err(|e| format!("can't read {url}: {e}"))?;
        Ok::<_, String>(response)
    };
    let response = tokio::time::timeout(IO_TIMEOUT, fetch)
        .await
        .map_err(|_| format!("{url} didn't answer in time"))??;
    let text = String::from_utf8_lossy(&response);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("{url}: not an HTTP response"))?;
    if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
        return Err(format!(
            "{url} answered {}",
            head.lines().next().unwrap_or_default()
        ));
    }
    Ok(publishers(body))
}

/// A publisher on the statistics page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Seen {
    pub address: String,
    /// The stream's incoming video bitrate (nginx's `bw_video`, averaged over its bandwidth
    /// window), if it has measured one yet.
    pub video_kbps: Option<u32>,
}

/// The keys being published to the `live` application, with each publisher, from the RTMP
/// module's statistics XML.
pub(crate) fn publishers(xml: &str) -> BTreeMap<String, Seen> {
    let mut found = BTreeMap::new();
    for application in blocks(xml, "application") {
        if text_of(application, "name").as_deref() != Some(APP) {
            continue;
        }
        for stream in blocks(application, "stream") {
            let Some(name) = text_of(stream, "name") else {
                continue;
            };
            if let Some(publisher) =
                blocks(stream, "client").find(|client| client.contains("<publishing/>"))
            {
                let video_kbps = text_of(stream, "bw_video")
                    .and_then(|bps| bps.parse::<u64>().ok())
                    .filter(|&bps| bps > 0)
                    .map(|bps| u32::try_from(bps.div_ceil(1000)).unwrap_or(u32::MAX));
                let address = text_of(publisher, "address").unwrap_or_default();
                found.insert(
                    name,
                    Seen {
                        address,
                        video_kbps,
                    },
                );
            }
        }
    }
    found
}

/// The contents of each `<tag>…</tag>` in `xml`, outermost first (no nesting of the same tag).
fn blocks<'a>(xml: &'a str, tag: &str) -> impl Iterator<Item = &'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut rest = xml;
    std::iter::from_fn(move || {
        let start = rest.find(&open)? + open.len();
        let end = rest[start..].find(&close)? + start;
        let block = &rest[start..end];
        rest = &rest[end + close.len()..];
        Some(block)
    })
}

/// The text of the first `<tag>…</tag>` directly in `xml`.
fn text_of(xml: &str, tag: &str) -> Option<String> {
    blocks(xml, tag).next().map(|text| text.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nginx_forms() {
        let form = parse_form(
            "call=publish&app=live&name=ingest-1&addr=192.168.8.20&clientid=7&tcurl=rtmp%3A%2F%2F192.168.8.1%2Flive&flashver=FMLE%2F3.0+%28compatible%29",
        );
        assert_eq!(form["call"], "publish");
        assert_eq!(form["name"], "ingest-1");
        assert_eq!(form["tcurl"], "rtmp://192.168.8.1/live");
        assert_eq!(form["flashver"], "FMLE/3.0 (compatible)");
        assert!(parse_form("name=%zz").is_empty(), "bad escapes are dropped");
        assert!(parse_form("").is_empty());
    }

    #[test]
    fn finds_publishers_in_the_statistics() {
        let xml = r"<rtmp><server><application><name>live</name><live>
            <stream><name>ingest</name><client><id>3</id><address>192.168.8.20</address><publishing/><active/></client>
              <client><id>4</id><address>127.0.0.1</address><dropped>0</dropped></client></stream>
            <stream><name>ingest-1</name><client><id>5</id><address>127.0.0.1</address></client></stream>
            </live></application>
            <application><name>other</name><live><stream><name>x</name><client><address>1.2.3.4</address><publishing/></client></stream></live></application>
            </server></rtmp>";
        let found = publishers(xml);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found["ingest"].address, "192.168.8.20");
        assert_eq!(found["ingest"].video_kbps, None, "no bw_video yet");
        let measured = xml.replace(
            "<stream><name>ingest</name>",
            "<stream><name>ingest</name><bw_in>3950000</bw_in><bw_video>3812345</bw_video>",
        );
        assert_eq!(publishers(&measured)["ingest"].video_kbps, Some(3813));
        let warming = xml.replace(
            "<stream><name>ingest</name>",
            "<stream><name>ingest</name><bw_video>0</bw_video>",
        );
        assert_eq!(
            publishers(&warming)["ingest"].video_kbps,
            None,
            "0: still warming up"
        );
    }

    async fn answer_with(accept: bool, path: &str, body: &str) -> (u16, Option<String>) {
        let (events, mut rx) = mpsc::unbounded_channel();
        let engine = tokio::spawn(async move {
            match rx.recv().await {
                Some(IngestEvent::Publish {
                    key, accept: tx, ..
                }) => {
                    let _ = tx.send(accept);
                    Some(key)
                }
                Some(IngestEvent::PublishDone { key }) => Some(format!("done:{key}")),
                _ => None,
            }
        });
        let status = decide(path, body, &events).await;
        drop(events);
        (status, engine.await.unwrap())
    }

    #[tokio::test]
    async fn the_hook_asks_the_engine() {
        let body = "call=publish&app=live&name=ingest&addr=192.168.8.20";
        assert_eq!(
            answer_with(true, "/rtmp/publish", body).await,
            (200, Some("ingest".into()))
        );
        assert_eq!(
            answer_with(false, "/rtmp/publish", body).await,
            (403, Some("ingest".into()))
        );
        assert_eq!(
            answer_with(
                true,
                "/rtmp/publish_done",
                "call=publish_done&app=live&name=ingest"
            )
            .await,
            (200, Some("done:ingest".into()))
        );
        assert_eq!(
            answer_with(true, "/rtmp/publish", "call=publish&app=other&name=ingest")
                .await
                .0,
            403
        );
        assert_eq!(
            answer_with(true, "/rtmp/publish", "call=play&app=live&name=ingest")
                .await
                .0,
            400
        );
        assert_eq!(answer_with(true, "/elsewhere", body).await.0, 404);
    }

    #[tokio::test]
    async fn serves_requests_over_loopback() {
        let (events, mut rx) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        tokio::spawn(serve_hook(port, events, cancel.clone()));
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if let IngestEvent::Publish { key, accept, .. } = event {
                    let _ = accept.send(key == "ingest");
                }
            }
        });
        for (key, expected) in [("ingest", "200"), ("ingest-9", "403")] {
            let body = format!("call=publish&app=live&name={key}&addr=1.2.3.4");
            let mut reply = String::new();
            for _ in 0..50 {
                if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)).await {
                    let request = format!(
                        "POST /rtmp/publish?x=1 HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    stream.write_all(request.as_bytes()).await.unwrap();
                    stream.read_to_string(&mut reply).await.unwrap();
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(
                reply.starts_with(&format!("HTTP/1.1 {expected}")),
                "{key}: {reply:?}"
            );
        }
        cancel.cancel();
    }
}
