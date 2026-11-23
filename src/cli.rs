//! The `helios` command line (LLD 1, section 4.10).
//!
//! Without a subcommand, `helios` runs the service ([`crate::service`]). The `helios provision`
//! subcommands run on the device as the `helios` user, with the same `SOFTHSM2_CONF` as the
//! service. The PIN comes from a terminal prompt, or from `--pin-file` in scripts, never from a
//! command-line argument.
//!
//! Exit codes: 0 on success, 1 on error, 78 (`EX_CONFIG`) for configuration errors.

use std::ffi::OsString;
use std::io::{self, BufRead, Write};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use secrecy::SecretString;

use crate::identity::pin::PinSpec;
use crate::provision::{
    DEFAULT_CHALLENGE_LABEL, DEFAULT_MODULE, DEFAULT_TOKEN_LABEL, ProvisionError, ProvisionToken,
    hex,
};

/// Success.
pub const EXIT_OK: u8 = 0;
/// An error.
pub const EXIT_ERROR: u8 = 1;
/// A configuration error (`EX_CONFIG`).
pub const EXIT_CONFIG: u8 = 78;

#[derive(Debug, Parser)]
#[command(
    name = "helios",
    version,
    about = "Helios on-device agent",
    long_about = "Helios on-device agent. Without a subcommand, runs the service (as \
                  helios.service does) with the config at --config."
)]
struct Cli {
    /// The service's config file.
    #[arg(long, default_value = crate::config::DEFAULT_PATH)]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[cfg(feature = "module-net")]
mod net;
mod token;
#[cfg(feature = "module-usb")]
mod usb;
#[cfg(feature = "module-net")]
mod wifi;

#[derive(Debug, Subcommand)]
#[allow(
    clippy::large_enum_variant,
    reason = "only one command is parsed per process"
)]
enum Command {
    /// Inspect USB devices and kernel events.
    #[cfg(feature = "module-usb")]
    #[command(subcommand)]
    Usb(usb::Command),
    /// Inspect network interfaces, addresses and default routes.
    #[cfg(feature = "module-net")]
    #[command(subcommand)]
    Net(net::Command),
    /// Set the Wi-Fi networks the WLAN adapter joins.
    #[cfg(feature = "module-net")]
    #[command(subcommand)]
    Wifi(wifi::Command),
    /// Apply the Wi-Fi networks to netplan or NetworkManager, as root (helios-wifi.service runs
    /// this when they change).
    #[cfg(feature = "module-net")]
    WifiApply,
    /// Set up and inspect the device's token.
    Provision(ProvisionArgs),
    /// The token's working copy (LLD 1, section 4.12): helios.service runs `token prepare`.
    #[command(subcommand)]
    Token(token::Command),
    /// Run the stream daemon (helios-stream.service): video streams that outlive Helios's
    /// restarts (LLD 4, section 15).
    #[cfg(feature = "module-stream")]
    StreamDaemon,
}

#[derive(Debug, clap::Args)]
struct ProvisionArgs {
    /// The PKCS#11 module.
    #[arg(long, default_value = DEFAULT_MODULE, global = true)]
    module: PathBuf,
    /// The token label.
    #[arg(long, default_value = DEFAULT_TOKEN_LABEL, global = true)]
    token_label: String,
    /// Read the user PIN from this file (mode 0400 or 0600) instead of prompting.
    #[arg(long, global = true)]
    pin_file: Option<PathBuf>,
    #[command(subcommand)]
    command: ProvisionCommand,
}

#[derive(Debug, Subcommand)]
enum ProvisionCommand {
    /// Create the PIN-less challenge key for bootstrap challenges and export its public key.
    ChallengeKey {
        /// The key label.
        #[arg(long, default_value = DEFAULT_CHALLENGE_LABEL)]
        label: String,
        /// The key's CKA_ID, in hex.
        #[arg(long, default_value = "02", value_parser = parse_id)]
        id: KeyId,
        /// Where to write the public key (PEM SubjectPublicKeyInfo).
        #[arg(long, default_value = "challenge-key.pub.pem")]
        out: PathBuf,
        /// Delete an existing challenge key pair with this label and ID first.
        #[arg(long)]
        replace: bool,
        /// Don't ask before replacing.
        #[arg(long, requires = "replace")]
        yes: bool,
    },
    /// List the token's objects and certificates. Prints no secrets.
    Show,
    /// Run the startup checks, and sign a test message with the challenge key without logging
    /// in.
    Verify(VerifyArgs),
}

#[derive(Debug, clap::Args)]
struct VerifyArgs {
    /// The thing name. Required unless --bootstrap, which gets it from the service.
    #[arg(long)]
    thing_name: Option<String>,
    /// The device key label (default device-key; with --bootstrap, from the service).
    #[arg(long)]
    key_label: Option<String>,
    /// The challenge key label. A missing challenge key is reported, not an error.
    #[arg(long, default_value = DEFAULT_CHALLENGE_LABEL)]
    challenge_label: String,
    /// How long to wait for the identity to be ready, in seconds.
    #[arg(long, default_value_t = 30)]
    timeout: u64,
    /// Also look the device up in the bootstrap service and log in with its PIN.
    #[arg(long)]
    bootstrap: bool,
    /// The bootstrap service URL.
    #[arg(long, default_value = DEFAULT_BOOTSTRAP_URL)]
    bootstrap_url: String,
    /// The CA bundle the bootstrap service's certificate is checked against.
    #[arg(long, default_value = DEFAULT_BOOTSTRAP_CA)]
    bootstrap_ca: PathBuf,
    /// The network interfaces to report: "auto" or a comma-separated list.
    #[arg(long, default_value = "auto")]
    interfaces: String,
}

/// The decided bootstrap service URL (Bootstrap API, section 7).
const DEFAULT_BOOTSTRAP_URL: &str = "https://device-management.services.kenley.tv/v1";
/// The Amazon root CA bundle (LLD 1, section 3).
const DEFAULT_BOOTSTRAP_CA: &str = "/etc/helios/amazon-root-cas.pem";

/// A `CKA_ID`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyId(Vec<u8>);

/// A `CKA_ID` in hex, such as `02` or `0a1b`.
fn parse_id(text: &str) -> Result<KeyId, String> {
    let invalid = || format!("{text:?} is not a hex CKA_ID such as 02");
    if text.is_empty() || !text.len().is_multiple_of(2) || text.len() > 64 {
        return Err(invalid());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| invalid()))
        .collect::<Result<_, _>>()
        .map(KeyId)
}

/// Where prompts and output go. The real one is [`Terminal`]; tests use their own.
pub trait Console {
    /// Asks for a secret without echoing it.
    ///
    /// # Errors
    ///
    /// If there is no terminal to ask on.
    fn read_secret(&mut self, prompt: &str) -> io::Result<SecretString>;
    /// Asks a yes/no question. Anything but `y` or `yes` is no.
    ///
    /// # Errors
    ///
    /// If there is no terminal to ask on.
    fn confirm(&mut self, question: &str) -> io::Result<bool>;
    /// Standard output.
    fn out(&mut self) -> &mut dyn Write;
    /// Standard error.
    fn err(&mut self) -> &mut dyn Write;
}

/// The process's terminal.
#[derive(Debug)]
pub struct Terminal {
    stdout: io::Stdout,
    stderr: io::Stderr,
}

impl Default for Terminal {
    fn default() -> Self {
        Self {
            stdout: io::stdout(),
            stderr: io::stderr(),
        }
    }
}

impl Terminal {
    fn read_line(&mut self, prompt: &str, echo: bool) -> io::Result<String> {
        let stdin = io::stdin();
        let mut input = stdin.lock();
        read_line_from(stdin.as_fd(), &mut input, &mut self.stderr, prompt, echo)
    }
}

/// Prompts on `prompt_out` and reads a line from `input`, which must be the terminal `tty`.
/// Without `echo`, the terminal doesn't echo what is typed, and the echo setting is restored
/// afterwards.
fn read_line_from(
    tty: std::os::fd::BorrowedFd<'_>,
    input: &mut dyn BufRead,
    prompt_out: &mut dyn Write,
    prompt: &str,
    echo: bool,
) -> io::Result<String> {
    use rustix::termios::{LocalModes, OptionalActions, isatty, tcgetattr, tcsetattr};

    if !isatty(tty) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "standard input is not a terminal; use --pin-file",
        ));
    }
    write!(prompt_out, "{prompt}")?;
    prompt_out.flush()?;
    let saved = tcgetattr(tty)?;
    if !echo {
        let mut quiet = saved.clone();
        quiet.local_modes.remove(LocalModes::ECHO);
        tcsetattr(tty, OptionalActions::Now, &quiet)?;
    }
    let mut line = String::new();
    let read = input.read_line(&mut line);
    if !echo {
        tcsetattr(tty, OptionalActions::Now, &saved)?;
        writeln!(prompt_out)?;
    }
    read?;
    let trimmed = line.trim_end_matches(['\n', '\r']).to_owned();
    secrecy::zeroize::Zeroize::zeroize(&mut line);
    Ok(trimmed)
}

impl Console for Terminal {
    fn read_secret(&mut self, prompt: &str) -> io::Result<SecretString> {
        self.read_line(prompt, false).map(SecretString::new)
    }

    fn confirm(&mut self, question: &str) -> io::Result<bool> {
        let answer = self.read_line(&format!("{question} [y/N] "), true)?;
        Ok(matches!(
            answer.trim().to_ascii_lowercase().as_str(),
            "y" | "yes"
        ))
    }

    fn out(&mut self) -> &mut dyn Write {
        &mut self.stdout
    }

    fn err(&mut self) -> &mut dyn Write {
        &mut self.stderr
    }
}

/// A command failed. `config` errors exit with 78.
#[derive(Debug)]
struct Failure {
    message: String,
    config: bool,
}

impl Failure {
    fn error(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            config: false,
        }
    }

    fn config(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            config: true,
        }
    }
}

impl From<ProvisionError> for Failure {
    fn from(error: ProvisionError) -> Self {
        Self {
            config: error.is_config(),
            message: error.to_string(),
        }
    }
}

impl From<io::Error> for Failure {
    fn from(error: io::Error) -> Self {
        Self::error(error.to_string())
    }
}

/// Runs `helios` with `args` (including the program name) and returns the exit code.
pub fn run(args: impl IntoIterator<Item = OsString>, console: &mut dyn Console) -> u8 {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let code = if error.use_stderr() { 2 } else { EXIT_OK };
            let _ = write!(
                if error.use_stderr() {
                    console.err()
                } else {
                    console.out()
                },
                "{}",
                error.render()
            );
            return code;
        }
    };
    let result = match cli.command {
        None => return crate::service::main(&cli.config),
        Some(Command::Provision(args)) => provision(&args, console),
        Some(Command::Token(command)) => token::run(command, &cli.config, console),
        #[cfg(feature = "module-usb")]
        Some(Command::Usb(command)) => usb::run(command, console.out()),
        #[cfg(feature = "module-net")]
        Some(Command::Net(command)) => net::run(command, &cli.config, console.out()),
        #[cfg(feature = "module-net")]
        Some(Command::Wifi(command)) => wifi::run(command, console),
        #[cfg(feature = "module-net")]
        Some(Command::WifiApply) => wifi::apply(console.out()),
        #[cfg(feature = "module-stream")]
        Some(Command::StreamDaemon) => return crate::modules::stream::daemon::main(&cli.config),
    };
    match result {
        Ok(()) => EXIT_OK,
        Err(failure) => {
            let _ = writeln!(console.err(), "helios: {}", failure.message);
            if failure.config {
                EXIT_CONFIG
            } else {
                EXIT_ERROR
            }
        }
    }
}

fn provision(args: &ProvisionArgs, console: &mut dyn Console) -> Result<(), Failure> {
    if let ProvisionCommand::Verify(verify_args) = &args.command {
        return verify(args, verify_args, console);
    }
    let token = ProvisionToken::open(&args.module, &args.token_label)?;
    let pin = read_pin(args.pin_file.as_deref(), console)?;
    token.login(&pin)?;
    drop(pin);
    match &args.command {
        ProvisionCommand::ChallengeKey {
            label,
            id,
            out,
            replace,
            yes,
        } => challenge_key(&token, label, &id.0, out, *replace, *yes, console),
        ProvisionCommand::Show => show(&token, console),
        ProvisionCommand::Verify(_) => unreachable!("handled above"),
    }
}

fn verify(
    args: &ProvisionArgs,
    verify_args: &VerifyArgs,
    console: &mut dyn Console,
) -> Result<(), Failure> {
    use crate::identity::cryptoki::CryptokiToken;
    use crate::identity::manager::{ManagerConfig, PinSetting};
    use crate::identity::pin::FixedPin;
    use crate::provision::verify::{
        ChallengeCheck, Verified, check_challenge_key, describe, verify_identity,
    };

    // The challenge key first: each check has the module to itself.
    match check_challenge_key(
        &args.module,
        &args.token_label,
        &verify_args.challenge_label,
    )? {
        ChallengeCheck::Signed { fingerprint } => writeln!(
            console.out(),
            "challenge key {:?}: signs without login (public key SHA-256 {fingerprint})",
            verify_args.challenge_label
        )?,
        ChallengeCheck::Missing => writeln!(
            console.out(),
            "challenge key {:?}: not on the token (optional; needed for bootstrap challenges)",
            verify_args.challenge_label
        )?,
    }

    let mut config = ManagerConfig::for_bootstrap();
    config.token_label = Some(args.token_label.clone());
    config.key_label = verify_args.key_label.clone();
    config.thing_name = verify_args.thing_name.clone();
    let pin = if verify_args.bootstrap {
        PinSetting::Bootstrap(Box::new(bootstrap_setup(verify_args)?))
    } else {
        if config.thing_name.is_none() {
            return Err(Failure::config(
                "--thing-name is required without --bootstrap",
            ));
        }
        config
            .key_label
            .get_or_insert_with(|| "device-key".to_owned());
        let pin = read_pin(args.pin_file.as_deref(), console)?;
        PinSetting::Local(std::sync::Arc::new(FixedPin::new(pin)))
    };
    let backend = Box::new(CryptokiToken::new(&args.module, &args.token_label));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let timeout = std::time::Duration::from_secs(verify_args.timeout);
    let verified = runtime
        .block_on(verify_identity(config, backend, pin, timeout))
        .map_err(|error| Failure::config(error.to_string()))?;
    match verified {
        Verified::Ready(identity) => {
            writeln!(console.out(), "identity: ready")?;
            for line in describe(&identity) {
                writeln!(console.out(), "  {line}")?;
            }
            Ok(())
        }
        Verified::Fatal(reason) => Err(Failure::config(format!("identity: {reason}"))),
        Verified::TimedOut(state) => {
            let detail = match &state {
                crate::identity::manager::IdentityState::Unavailable { reason, .. } => {
                    format!(": {reason}")
                }
                crate::identity::manager::IdentityState::Bootstrapping {
                    attempts,
                    last_error,
                } => format!(
                    " after {attempts} lookups: {}",
                    last_error.as_deref().unwrap_or("waiting for the service")
                ),
                _ => String::new(),
            };
            Err(Failure::error(format!(
                "identity still {} after {} s{detail}",
                state.name(),
                verify_args.timeout
            )))
        }
    }
}

/// The bootstrap settings from the command line, with the device's own adapters and model.
fn bootstrap_setup(args: &VerifyArgs) -> Result<crate::identity::manager::BootstrapSetup, Failure> {
    use crate::identity::bootstrap::adapters::{Interfaces, Rtnetlink};
    use crate::identity::bootstrap::client::{BootstrapClient, DEFAULT_TIMEOUT};
    use crate::identity::bootstrap::{DEVICE_TREE_MODEL, hardware_model};
    use crate::identity::manager::{BootstrapSetup, BootstrapTiming};

    let pem = std::fs::read(&args.bootstrap_ca)
        .map_err(|error| Failure::config(format!("{}: {error}", args.bootstrap_ca.display())))?;
    let roots = crate::identity::tls::root_store_from_pem(&pem)
        .map_err(|error| Failure::config(format!("{}: {error}", args.bootstrap_ca.display())))?;
    let client = BootstrapClient::new(&args.bootstrap_url, roots, DEFAULT_TIMEOUT)
        .map_err(|error| Failure::config(error.to_string()))?;
    let interfaces = match args.interfaces.as_str() {
        "auto" => Interfaces::Auto,
        list => Interfaces::Named(
            list.split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect(),
        ),
    };
    Ok(BootstrapSetup {
        client,
        interfaces,
        sysfs: PathBuf::from("/sys"),
        permanent_addresses: std::sync::Arc::new(Rtnetlink),
        hardware_model: hardware_model(Path::new(DEVICE_TREE_MODEL)),
        challenge_key_label: Some(args.challenge_label.clone()),
        aws: None,
        timing: BootstrapTiming::default(),
    })
}

fn read_pin(pin_file: Option<&Path>, console: &mut dyn Console) -> Result<SecretString, Failure> {
    match pin_file {
        Some(path) => {
            let source = PinSpec::File(path.to_owned())
                .local_source(None)
                .map_err(|error| Failure::config(error.to_string()))?
                .ok_or_else(|| Failure::config("no PIN source"))?;
            source
                .read()
                .map_err(|error| Failure::config(error.to_string()))
        }
        None => console
            .read_secret("Token user PIN: ")
            .map_err(|error| Failure::config(format!("can't read the PIN: {error}"))),
    }
}

fn challenge_key(
    token: &ProvisionToken,
    label: &str,
    id: &[u8],
    out: &Path,
    replace: bool,
    yes: bool,
    console: &mut dyn Console,
) -> Result<(), Failure> {
    if out.exists() && !replace {
        return Err(Failure::error(format!(
            "{} already exists; use --replace to overwrite it",
            out.display()
        )));
    }
    if replace {
        let existing: Vec<_> = token
            .conflicts(label, id)?
            .into_iter()
            .filter(|object| object.label == label && object.id == id)
            .collect();
        if !existing.is_empty() {
            for object in &existing {
                writeln!(console.out(), "existing: {object}")?;
            }
            let question = format!(
                "Delete the existing challenge key {label:?} (CKA_ID {})? The bootstrap \
                 service must then get the new public key.",
                hex(id)
            );
            if !yes && !console.confirm(&question)? {
                return Err(Failure::error("not replaced"));
            }
            let deleted = token.delete_key_pair(label, id)?;
            writeln!(console.out(), "deleted {deleted} objects")?;
        }
    }
    let key = token.generate_challenge_key(label, id)?;
    std::fs::write(out, key.pem())
        .map_err(|error| Failure::error(format!("{}: {error}", out.display())))?;
    writeln!(
        console.out(),
        "created challenge key {label:?} (CKA_ID {}) on token {:?}",
        hex(id),
        token.summary().label
    )?;
    writeln!(console.out(), "public key: {}", out.display())?;
    writeln!(
        console.out(),
        "fingerprint (SHA-256 of the SPKI): {}",
        key.fingerprint()
    )?;
    Ok(())
}

fn show(token: &ProvisionToken, console: &mut dyn Console) -> Result<(), Failure> {
    let summary = token.summary();
    let out = console.out();
    writeln!(
        out,
        "token {:?}: {} {} serial {} ({})",
        summary.label,
        summary.manufacturer,
        summary.model,
        summary.serial,
        summary.module.display()
    )?;
    let objects = token.objects()?;
    writeln!(out, "objects ({}):", objects.len())?;
    for object in &objects {
        writeln!(out, "  {object}")?;
    }
    for info in token.certificates()? {
        match &info.certificate {
            Ok(certificate) => writeln!(
                out,
                "certificate {:?} (CKA_ID {}): subject CN {}, not after {}, SHA-256 {}",
                info.object.label,
                hex(&info.object.id),
                certificate.subject_cn().unwrap_or("(none)"),
                httpdate::fmt_http_date(certificate.not_after()),
                certificate.fingerprint_hex()
            )?,
            Err(error) => writeln!(
                out,
                "certificate {:?} (CKA_ID {}): {error}",
                info.object.label,
                hex(&info.object.id)
            )?,
        }
    }
    Ok(())
}

/// A console for tests: answers prompts from queues and captures output.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct ScriptedConsole {
    /// Secrets to answer prompts with, in order.
    pub secrets: Vec<String>,
    /// What was written to standard output.
    pub stdout: Vec<u8>,
    /// What was written to standard error.
    pub stderr: Vec<u8>,
}

#[cfg(test)]
impl Console for ScriptedConsole {
    fn read_secret(&mut self, _: &str) -> io::Result<SecretString> {
        if self.secrets.is_empty() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no terminal"));
        }
        Ok(SecretString::new(self.secrets.remove(0)))
    }

    fn confirm(&mut self, _: &str) -> io::Result<bool> {
        Ok(false)
    }

    fn out(&mut self) -> &mut dyn Write {
        &mut self.stdout
    }

    fn err(&mut self) -> &mut dyn Write {
        &mut self.stderr
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;
    use crate::provision::DEFAULT_CHALLENGE_ID;

    fn run_with(args: &[&str], console: &mut ScriptedConsole) -> u8 {
        let args = std::iter::once("helios")
            .chain(args.iter().copied())
            .map(OsString::from);
        run(args, console)
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    #[test]
    fn without_a_command_runs_the_service() {
        let mut console = ScriptedConsole::default();

        // The service reads its config first; a missing one is a config error.
        assert_eq!(
            run_with(&["--config", "/nonexistent/helios.toml"], &mut console),
            EXIT_CONFIG
        );
    }

    #[test]
    fn help_describes_the_service() {
        let mut console = ScriptedConsole::default();

        assert_eq!(run_with(&["--help"], &mut console), EXIT_OK);

        let help = text(&console.stdout);
        assert!(help.contains("--config"), "{help}");
        assert!(help.contains(crate::config::DEFAULT_PATH), "{help}");
    }

    #[test]
    fn prints_help_and_rejects_bad_arguments() {
        let mut console = ScriptedConsole::default();
        assert_eq!(run_with(&["provision", "--help"], &mut console), EXIT_OK);
        let help = text(&console.stdout);
        assert!(
            help.contains("challenge-key") && help.contains("show"),
            "{help}"
        );

        let mut console = ScriptedConsole::default();
        assert_eq!(run_with(&["provision", "frobnicate"], &mut console), 2);
        assert!(!console.stderr.is_empty());

        let mut console = ScriptedConsole::default();
        assert_eq!(
            run_with(&["provision", "challenge-key", "--yes"], &mut console),
            2,
            "--yes needs --replace"
        );
    }

    #[test]
    fn parses_challenge_key_arguments() {
        let cli = Cli::try_parse_from(["helios", "provision", "--pin-file", "/p", "challenge-key"])
            .unwrap();
        let Some(Command::Provision(args)) = cli.command else {
            panic!("expected provision");
        };
        assert_eq!(args.module, Path::new(DEFAULT_MODULE));
        assert_eq!(args.token_label, "helios");
        assert_eq!(args.pin_file.as_deref(), Some(Path::new("/p")));
        let ProvisionCommand::ChallengeKey {
            label,
            id,
            out,
            replace,
            yes,
        } = args.command
        else {
            panic!("expected challenge-key");
        };
        assert_eq!(label, "challenge-key");
        assert_eq!(id, KeyId(vec![DEFAULT_CHALLENGE_ID]));
        assert_eq!(out, Path::new("challenge-key.pub.pem"));
        assert!(!replace && !yes);

        let cli = Cli::try_parse_from([
            "helios",
            "provision",
            "challenge-key",
            "--id",
            "0a",
            "--replace",
            "--yes",
        ])
        .unwrap();
        let Some(Command::Provision(ProvisionArgs {
            command:
                ProvisionCommand::ChallengeKey {
                    id, replace, yes, ..
                },
            ..
        })) = cli.command
        else {
            panic!("expected challenge-key");
        };
        assert_eq!(id, KeyId(vec![0x0a]));
        assert!(replace && yes);
    }

    #[test]
    fn parses_hex_ids() {
        assert_eq!(parse_id("02"), Ok(KeyId(vec![2])));
        assert_eq!(parse_id("0a1B"), Ok(KeyId(vec![0x0a, 0x1b])));
        for bad in ["", "2", "zz", "021", &"0".repeat(66)] {
            assert!(parse_id(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_missing_module_is_a_configuration_error() {
        let mut console = ScriptedConsole::default();

        let code = run_with(
            &["provision", "--module", "/nonexistent/libpkcs11.so", "show"],
            &mut console,
        );

        assert_eq!(code, EXIT_CONFIG);
        assert!(text(&console.stderr).starts_with("helios: PKCS#11 module could not be loaded"));
    }

    #[test]
    fn pin_problems_are_configuration_errors() {
        let mut console = ScriptedConsole::default();
        assert!(matches!(
            read_pin(None, &mut console),
            Err(Failure { config: true, .. })
        ));
        let mut console = ScriptedConsole {
            secrets: vec!["123456".into()],
            ..ScriptedConsole::default()
        };
        assert_eq!(
            read_pin(None, &mut console).unwrap().expose_secret(),
            "123456"
        );
        let failure = read_pin(Some(Path::new("/nonexistent/pin")), &mut console).unwrap_err();
        assert!(failure.config && failure.message.contains("/nonexistent/pin"));
    }

    #[test]
    fn the_terminal_needs_a_tty() {
        // Test runners don't give tests a terminal on standard input.
        if rustix::termios::isatty(io::stdin().as_fd()) {
            return;
        }
        let mut terminal = Terminal::default();
        let error = terminal.read_secret("PIN: ").unwrap_err();
        assert!(error.to_string().contains("--pin-file"), "{error}");
        assert!(terminal.confirm("Sure?").is_err());
        let _ = terminal.out().flush();
        let _ = terminal.err().flush();
    }

    /// A pseudo-terminal: the controller end and the terminal end.
    fn pty() -> (std::fs::File, std::fs::File) {
        use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

        let controller = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
        grantpt(&controller).unwrap();
        unlockpt(&controller).unwrap();
        let name = ptsname(&controller, Vec::new()).unwrap();
        let terminal = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(name.to_str().unwrap())
            .unwrap();
        (std::fs::File::from(controller), terminal)
    }

    #[test]
    fn reads_a_secret_without_echo_and_restores_the_terminal() {
        use std::io::Read;

        use rustix::termios::{LocalModes, tcgetattr};

        let (mut controller, terminal) = pty();
        assert!(
            tcgetattr(&terminal)
                .unwrap()
                .local_modes
                .contains(LocalModes::ECHO)
        );
        let reader = terminal.try_clone().unwrap();
        let reading = std::thread::spawn(move || {
            let mut input = io::BufReader::new(reader.try_clone().unwrap());
            let mut prompt = Vec::new();
            let line = read_line_from(reader.as_fd(), &mut input, &mut prompt, "PIN: ", false);
            (line, prompt, input)
        });

        // Type the secret once the prompt has turned echo off, as a person would.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while tcgetattr(&terminal)
            .unwrap()
            .local_modes
            .contains(LocalModes::ECHO)
        {
            assert!(
                std::time::Instant::now() < deadline,
                "echo never turned off"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        controller.write_all(b"s3cret\n").unwrap();
        let (line, prompt, mut input) = reading.join().unwrap();

        assert_eq!(line.unwrap(), "s3cret");
        assert_eq!(prompt, b"PIN: \n");
        assert!(
            tcgetattr(&terminal)
                .unwrap()
                .local_modes
                .contains(LocalModes::ECHO)
        );
        // Nothing was echoed back to the controller.
        rustix::fs::fcntl_setfl(&controller, rustix::fs::OFlags::NONBLOCK).unwrap();
        let mut echoed = [0u8; 64];
        let echoed = controller.read(&mut echoed).unwrap_or(0);
        assert_eq!(echoed, 0, "the secret was echoed");
        let mut prompt = Vec::new();

        // With echo (yes/no questions), the answer is read the same way.
        controller.write_all(b"yes\r\n").unwrap();
        let line =
            read_line_from(terminal.as_fd(), &mut input, &mut prompt, "Sure? ", true).unwrap();
        assert_eq!(line, "yes");
    }

    #[test]
    fn verify_needs_a_thing_name_or_bootstrap_settings() {
        let mut console = ScriptedConsole::default();
        assert_eq!(
            run_with(
                &["provision", "--module", "/nonexistent/lib.so", "verify"],
                &mut console
            ),
            EXIT_CONFIG
        );

        let directory = tempfile::tempdir().unwrap();
        let ca = directory.path().join("ca.pem");
        std::fs::write(&ca, crate::identity::testing::ca("roots").pem).unwrap();
        let args = |url: &str, ca: &Path, interfaces: &str| VerifyArgs {
            thing_name: None,
            key_label: None,
            challenge_label: "challenge-key".into(),
            timeout: 1,
            bootstrap: true,
            bootstrap_url: url.into(),
            bootstrap_ca: ca.to_owned(),
            interfaces: interfaces.into(),
        };
        let setup = bootstrap_setup(&args("https://localhost/v1", &ca, "eth0, wlan0,")).unwrap();
        assert_eq!(
            setup.interfaces,
            crate::identity::bootstrap::adapters::Interfaces::Named(vec![
                "eth0".into(),
                "wlan0".into()
            ])
        );
        assert_eq!(setup.challenge_key_label.as_deref(), Some("challenge-key"));
        let setup = bootstrap_setup(&args("https://localhost/v1", &ca, "auto")).unwrap();
        assert_eq!(
            setup.interfaces,
            crate::identity::bootstrap::adapters::Interfaces::Auto
        );

        for (url, ca_path) in [
            ("http://localhost/v1", ca.clone()),
            ("https://localhost/v1", directory.path().join("missing.pem")),
            ("https://localhost/v1", directory.path().to_owned()),
        ] {
            let failure = bootstrap_setup(&args(url, &ca_path, "auto")).unwrap_err();
            assert!(failure.config, "{url} {}", ca_path.display());
        }
        let not_pem = directory.path().join("not.pem");
        std::fs::write(&not_pem, "nothing").unwrap();
        assert!(
            bootstrap_setup(&args("https://localhost/v1", &not_pem, "auto"))
                .unwrap_err()
                .config
        );
    }
}
