//! The web module's listener: HTTP/1.1 with hyper, each connection on its own task, each
//! request answered by [`super::http::serve`].

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use super::http::{self, MAX_BODY, Request, Web};

/// Serves `web` on `listener` until `cancel`.
pub(crate) async fn run(listener: TcpListener, web: Arc<Web>, cancel: CancellationToken) {
    loop {
        let (stream, peer) = tokio::select! {
            () = cancel.cancelled() => return,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::warn!(%error, "web: can't accept a connection");
                    continue;
                }
            },
        };
        let web = Arc::clone(&web);
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |request: hyper::Request<Incoming>| {
                let web = Arc::clone(&web);
                async move { Ok::<_, Infallible>(answer(&web, request, peer).await) }
            });
            let connection = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service);
            tokio::select! {
                () = cancel.cancelled() => {}
                _ = connection => {}
            }
        });
    }
}

async fn answer(
    web: &Web,
    request: hyper::Request<Incoming>,
    peer: SocketAddr,
) -> hyper::Response<Full<Bytes>> {
    let (parts, body) = request.into_parts();
    let body = match Limited::new(body, MAX_BODY).collect().await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(_) => {
            return hyper::Response::builder()
                .status(413)
                .body(Full::new(Bytes::from_static(b"Too large.\n")))
                .unwrap_or_default();
        }
    };
    let query = parts.uri.query().map(parse_query).unwrap_or_default();
    let headers: HashMap<String, String> = parts
        .headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_ascii_lowercase(), v.to_owned()))
        })
        .collect();
    let request = Request {
        method: parts.method.to_string(),
        path: parts.uri.path().to_owned(),
        query,
        headers,
        body,
        peer: Some(peer.ip()),
    };
    let response = http::serve(web, &request).await;
    let mut builder = hyper::Response::builder().status(response.status);
    for (name, value) in &response.headers {
        builder = builder.header(name, value);
    }
    let body = if request.method == "HEAD" {
        Bytes::new()
    } else {
        Bytes::from(response.body)
    };
    builder.body(Full::new(body)).unwrap_or_default()
}

/// A query string's `name=value` pairs, `+` and `%XX` decoded.
pub(crate) fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode(name), decode(value))
        })
        .collect()
}

fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = text
                    .get(i + 1..i + 3)
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(byte) => {
                        out.push(byte);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            byte => out.push(byte),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::parse_query;

    #[test]
    fn decodes_query_strings() {
        assert_eq!(
            parse_query("ssid=My+Cafe%21&includePublicAddresses=true&odd=%zz&flag"),
            vec![
                ("ssid".to_owned(), "My Cafe!".to_owned()),
                ("includePublicAddresses".to_owned(), "true".to_owned()),
                ("odd".to_owned(), "%zz".to_owned()),
                ("flag".to_owned(), String::new()),
            ]
        );
        assert_eq!(parse_query(""), vec![]);
        assert_eq!(
            parse_query("a=%E2%9C%93"),
            vec![("a".to_owned(), "\u{2713}".to_owned())]
        );
    }
}
