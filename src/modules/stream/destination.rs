//! SRT and SRTLA destination URLs, as operators set them through the `stream` shadow (HLD
//! section 7.3.7): `srt://host:port` or `srtla://host:port`, with only `streamid`, `latency`
//! (milliseconds) and `passphrase`, each at most once. The rules and the normal form are the
//! Control API's (`Destinations.java` in helios-cloud), which checks them first; the device checks
//! them again, since the desired state can come from anywhere that may write the shadow.

use super::settings::Output;

/// A checked destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Destination {
    /// `srtla` rather than `srt`.
    pub bonded: bool,
    /// A host name or IP address (IPv6 without brackets).
    pub host: String,
    pub port: u16,
    pub streamid: Option<String>,
    pub latency_ms: Option<u32>,
    pub passphrase: Option<String>,
}

const STREAM_ID: &[u8] = b"/_.:=,-";
const PASSPHRASE: &[u8] = b"._~!$'()*+,;:@-";

impl Destination {
    /// Parses and checks `url`.
    ///
    /// # Errors
    ///
    /// Why it isn't a destination, naming the part that's wrong.
    pub(crate) fn parse(url: &str) -> Result<Self, String> {
        let (bonded, rest) = if let Some(rest) = url.strip_prefix("srt://") {
            (false, rest)
        } else if let Some(rest) = url.strip_prefix("srtla://") {
            (true, rest)
        } else {
            return Err("scheme: the destination must be an srt:// or srtla:// URL".into());
        };
        if rest.contains('#') {
            return Err("fragment: the destination can't have a #fragment".into());
        }
        let (authority, query) = rest.split_once('?').unwrap_or((rest, ""));
        let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
            let Some((host, port)) = bracketed
                .split_once(']')
                .and_then(|(host, rest)| Some((host, rest.strip_prefix(':')?)))
            else {
                return Err("host: an IPv6 address needs brackets, then :port".into());
            };
            if !(2..=45).contains(&host.len())
                || !host
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() || b":.".contains(&b))
            {
                return Err("host: not an IPv6 address".into());
            }
            (host, port)
        } else {
            let Some((host, port)) = authority.rsplit_once(':') else {
                return Err("port: the destination needs a port: host:port".into());
            };
            if !(1..=253).contains(&host.len())
                || !host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                return Err("host: the host must be a host name or IP address".into());
            }
            (host, port)
        };
        let port = digits(port)
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port >= 1)
            .ok_or("port: the port must be 1 to 65535")?;

        let mut destination = Self {
            bonded,
            host: host.to_owned(),
            port,
            streamid: None,
            latency_ms: None,
            passphrase: None,
        };
        if query.is_empty() {
            return Ok(destination);
        }
        for pair in query.split('&') {
            let (name, value) = match pair.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (pair, None),
            };
            if !["streamid", "latency", "passphrase"].contains(&name) {
                let part = if name.is_empty() { "parameter" } else { name };
                return Err(format!(
                    "{part}: only streamid, latency and passphrase are allowed"
                ));
            }
            let value = value.ok_or_else(|| format!("{name}: {name} needs a value"))?;
            let value = decode(value, name)?;
            let given = match name {
                "streamid" => destination.streamid.is_some(),
                "latency" => destination.latency_ms.is_some(),
                _ => destination.passphrase.is_some(),
            };
            if given {
                return Err(format!("{name}: {name} is given more than once"));
            }
            match name {
                "streamid" => {
                    if !(1..=512).contains(&value.len())
                        || !value
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || STREAM_ID.contains(&b))
                    {
                        return Err("streamid: streamid must be up to 512 letters, digits and \
                                    / _ . - : = , characters"
                            .into());
                    }
                    destination.streamid = Some(value);
                }
                "latency" => {
                    let latency = digits(&value)
                        .filter(|ms| (20..=30_000).contains(ms))
                        .ok_or("latency: latency must be 20 to 30000 milliseconds")?;
                    destination.latency_ms = Some(latency);
                }
                _ => {
                    if !(10..=79).contains(&value.len())
                        || !value
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || PASSPHRASE.contains(&b))
                    {
                        return Err("passphrase: passphrase must be 10 to 79 letters, digits \
                                    and - . _ ~ ! $ ' ( ) * + , ; : @ characters"
                            .into());
                    }
                    destination.passphrase = Some(value);
                }
            }
        }
        Ok(destination)
    }

    /// A configured output and stream ID as a destination, with everything given.
    pub(crate) fn of_output(output: &Output, streamid: &str) -> Self {
        Self {
            bonded: output.mode == "srtla",
            host: output.host.clone(),
            port: output.port,
            streamid: Some(streamid.to_owned()),
            latency_ms: Some(output.latency_ms),
            passphrase: output.passphrase.clone(),
        }
    }

    /// The normal form: the parameters given, in the order streamid, latency, passphrase,
    /// nothing percent-encoded. The device reports a destination override in this form, so the
    /// Control API sees it equal to the one it wrote.
    pub(crate) fn url(&self) -> String {
        let mut query = Vec::new();
        if let Some(streamid) = &self.streamid {
            query.push(format!("streamid={streamid}"));
        }
        if let Some(latency) = self.latency_ms {
            query.push(format!("latency={latency}"));
        }
        if let Some(passphrase) = &self.passphrase {
            query.push(format!("passphrase={passphrase}"));
        }
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let scheme = if self.bonded { "srtla" } else { "srt" };
        let mut url = format!("{scheme}://{host}:{}", self.port);
        if !query.is_empty() {
            url.push('?');
            url.push_str(&query.join("&"));
        }
        url
    }

    /// The output it makes for a stream whose configured output is `base`: the latency the URL
    /// doesn't give is `base`'s, and an SRTLA destination bonds `base`'s uplinks if `base` is an
    /// SRTLA output, else `default_uplinks` (`modules.stream.srtla_uplinks`). The passphrase is
    /// only the URL's: it belongs to the server.
    pub(crate) fn output(&self, base: &Output, default_uplinks: &[String]) -> Output {
        let uplinks = match (self.bonded, base.mode.as_str()) {
            (false, _) => Vec::new(),
            (true, "srtla") => base.uplinks.clone(),
            (true, _) => default_uplinks.to_vec(),
        };
        Output {
            mode: if self.bonded { "srtla" } else { "direct" }.into(),
            host: self.host.clone(),
            port: self.port,
            latency_ms: self.latency_ms.unwrap_or(base.latency_ms),
            uplinks,
            passphrase: self.passphrase.clone(),
        }
    }
}

/// One to five ASCII digits.
fn digits(text: &str) -> Option<u32> {
    if text.is_empty() || text.len() > 5 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Percent-decoding as in RFC 3986: `+` is a plus sign, not a space.
fn decode(value: &str, name: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = |b: Option<&u8>| b.and_then(|b| char::from(*b).to_digit(16));
                let (Some(high), Some(low)) = (hex(bytes.get(i + 1)), hex(bytes.get(i + 2))) else {
                    return Err(format!("{name}: a % escape needs two hex digits"));
                };
                #[allow(clippy::cast_possible_truncation)]
                out.push((high * 16 + low) as u8);
                i += 3;
            }
            b @ 0x21..=0x7e => {
                out.push(b);
                i += 1;
            }
            _ => {
                return Err(format!(
                    "{name}: {name} has a character that must be percent-encoded"
                ));
            }
        }
    }
    String::from_utf8(out).map_err(|_| format!("{name}: {name} isn't UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(mode: &str) -> Output {
        Output {
            mode: mode.into(),
            host: "ingest.example.com".into(),
            port: 4001,
            latency_ms: 1500,
            uplinks: if mode == "srtla" {
                vec!["usb:cellular".into()]
            } else {
                Vec::new()
            },
            passphrase: Some("configured-secret".into()),
        }
    }

    #[test]
    fn parses_and_writes_the_normal_form() {
        for (url, normal) in [
            ("srt://h.example:4001", "srt://h.example:4001"),
            (
                "srtla://10.0.0.5:5000?passphrase=not-a-secret-1&latency=800&streamid=a/b",
                "srtla://10.0.0.5:5000?streamid=a/b&latency=800&passphrase=not-a-secret-1",
            ),
            (
                "srt://[2001:db8::1]:4001?latency=20",
                "srt://[2001:db8::1]:4001?latency=20",
            ),
            (
                "srt://h:1?streamid=publish%2Flive%2Fx",
                "srt://h:1?streamid=publish/live/x",
            ),
            (
                "srt://h:1?passphrase=a+b+c+d+e+f",
                "srt://h:1?passphrase=a+b+c+d+e+f",
            ),
        ] {
            assert_eq!(Destination::parse(url).expect(url).url(), normal, "{url}");
        }
    }

    #[test]
    fn names_the_part_that_is_wrong() {
        for (url, part) in [
            ("rtmp://h:1", "scheme"),
            ("srt://h:1#x", "fragment"),
            ("srt://h", "port"),
            ("srt://h:0", "port"),
            ("srt://h:65536", "port"),
            ("srt://a b:1", "host"),
            ("srt://[zz::1]:1", "host"),
            ("srt://[::1]1", "host"),
            ("srt://h:1?mode=listener", "mode"),
            ("srt://h:1?&latency=20", "parameter"),
            ("srt://h:1?latency", "latency"),
            ("srt://h:1?latency=10", "latency"),
            ("srt://h:1?latency=20&latency=30", "latency"),
            ("srt://h:1?passphrase=short", "passphrase"),
            ("srt://h:1?streamid=a%2", "streamid"),
            ("srt://h:1?streamid=a%26b", "streamid"),
            ("srt://h:1?streamid=caf\u{e9}", "streamid"),
        ] {
            let error = Destination::parse(url).expect_err(url);
            assert!(error.starts_with(&format!("{part}: ")), "{url}: {error}");
        }
    }

    #[test]
    fn makes_an_output_from_the_configured_one() {
        let direct = Destination::parse("srt://other.example:4000").expect("valid");
        let output = direct.output(&base("srtla"), &["usb:wifi".into()]);
        assert_eq!(output.mode, "direct");
        assert_eq!((output.host.as_str(), output.port), ("other.example", 4000));
        assert_eq!(output.latency_ms, 1500, "the configured latency");
        assert!(output.uplinks.is_empty());
        assert_eq!(output.passphrase, None, "the passphrase is the server's");

        let bonded = Destination::parse("srtla://other.example:5000?latency=900").expect("valid");
        let defaults = ["usb:wifi".to_owned()];
        assert_eq!(
            bonded.output(&base("srtla"), &defaults).uplinks,
            ["usb:cellular"]
        );
        assert_eq!(
            bonded.output(&base("direct"), &defaults).uplinks,
            ["usb:wifi"]
        );
        assert_eq!(bonded.output(&base("direct"), &defaults).latency_ms, 900);

        assert_eq!(
            Destination::of_output(&base("srtla"), "publish/live/x").url(),
            "srtla://ingest.example.com:4001?streamid=publish/live/x&latency=1500\
             &passphrase=configured-secret"
        );
    }
}
