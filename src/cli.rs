//! The `helios` command line (LLD 1, section 4.10).
//!
//! `helios provision` subcommands run on the device as the `helios` user, with the same
//! `SOFTHSM2_CONF` as the service. The PIN comes from a terminal prompt, or from `--pin-file`
//! in scripts, never from a command-line argument.
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
#[command(name = "helios", version, about = "Helios on-device agent")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Set up and inspect the device's token.
    Provision(ProvisionArgs),
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
}

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
        None => {
            let _ = writeln!(
                console.out(),
                "helios {}: the agent isn't wired up yet; see `helios provision --help`",
                env!("CARGO_PKG_VERSION")
            );
            Ok(())
        }
        Some(Command::Provision(args)) => provision(&args, console),
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
    }
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
    fn without_a_command_says_the_agent_is_not_wired_up() {
        let mut console = ScriptedConsole::default();

        assert_eq!(run_with(&[], &mut console), EXIT_OK);

        assert!(text(&console.stdout).contains("see `helios provision --help`"));
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
}
