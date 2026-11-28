//! `helios web`: the on-device console's tools (LLD 13).
//!
//! `hash-password` makes the Argon2id hash `[modules.web] password_hash` takes, from a password
//! read from a file or asked for without echo; never from the command line.

use std::io::{self, BufRead};
use std::path::PathBuf;

use clap::Subcommand;
use secrecy::{ExposeSecret, SecretString};

use super::{Console, Failure};
use crate::modules::web::auth;

#[derive(Debug, Subcommand)]
pub(super) enum Command {
    /// Print the Argon2id hash of a console password, for [modules.web] password_hash. Asks for
    /// the password twice unless --password-file.
    HashPassword {
        /// Read the password from this file's first line instead of asking (- for stdin).
        #[arg(long)]
        password_file: Option<PathBuf>,
    },
}

/// The shortest password the console takes.
const MIN_PASSWORD: usize = 12;

pub(super) fn run(command: Command, console: &mut dyn Console) -> Result<(), Failure> {
    match command {
        Command::HashPassword { password_file } => {
            let password = match password_file {
                Some(path) => first_line(&path)?,
                None => asked(console)?,
            };
            if password.expose_secret().chars().count() < MIN_PASSWORD {
                return Err(Failure::error(format!(
                    "the password must be at least {MIN_PASSWORD} characters"
                )));
            }
            let hash =
                auth::hash_password(password.expose_secret().as_bytes()).map_err(Failure::error)?;
            writeln!(console.out(), "{hash}").map_err(|e| Failure::error(e.to_string()))
        }
    }
}

fn first_line(path: &PathBuf) -> Result<SecretString, Failure> {
    let mut line = String::new();
    let read = if path.as_os_str() == "-" {
        io::stdin().lock().read_line(&mut line)
    } else {
        std::fs::File::open(path).and_then(|file| io::BufReader::new(file).read_line(&mut line))
    };
    read.map_err(|e| Failure::error(format!("can't read {}: {e}", path.display())))?;
    let password = line.trim_end_matches(['\r', '\n']).to_owned();
    if password.is_empty() {
        return Err(Failure::error(format!(
            "{} has no password",
            path.display()
        )));
    }
    Ok(SecretString::from(password))
}

fn asked(console: &mut dyn Console) -> Result<SecretString, Failure> {
    let ask = |console: &mut dyn Console, prompt: &str| {
        console
            .read_secret(prompt)
            .map_err(|e| Failure::error(format!("can't ask for the password: {e}")))
    };
    let first = ask(console, "Console password: ")?;
    let again = ask(console, "Again: ")?;
    if first.expose_secret() != again.expose_secret() {
        return Err(Failure::error("the passwords don't match"));
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::{Command, run};
    use crate::cli::ScriptedConsole;
    use crate::modules::web::auth;

    fn hash(command: Command, secrets: &[&str]) -> Result<String, String> {
        let mut console = ScriptedConsole {
            secrets: secrets.iter().map(|s| (*s).to_owned()).collect(),
            ..ScriptedConsole::default()
        };
        run(command, &mut console).map_err(|failure| failure.message)?;
        Ok(String::from_utf8(console.stdout).unwrap())
    }

    #[test]
    fn hashes_a_password_asked_for_twice() {
        let out = hash(
            Command::HashPassword {
                password_file: None,
            },
            &["a long console password", "a long console password"],
        )
        .unwrap();
        let line = out.trim_end();
        assert!(auth::is_argon2id(line), "{out}");
        assert!(auth::password_matches(line, b"a long console password"));
        assert!(!out.contains("a long console password"), "never echoed");

        let error = hash(
            Command::HashPassword {
                password_file: None,
            },
            &["a long console password", "another long password"],
        )
        .unwrap_err();
        assert!(error.contains("don't match"), "{error}");
        let short = hash(
            Command::HashPassword {
                password_file: None,
            },
            &["short", "short"],
        )
        .unwrap_err();
        assert!(short.contains("at least 12"), "{short}");
    }

    #[test]
    fn hashes_a_password_from_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("console-password");
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "a long console password").unwrap();
        let out = hash(
            Command::HashPassword {
                password_file: Some(path),
            },
            &[],
        )
        .unwrap();
        assert!(auth::password_matches(
            out.trim_end(),
            b"a long console password"
        ));

        let empty = dir.path().join("empty");
        std::fs::write(&empty, "\n").unwrap();
        let error = hash(
            Command::HashPassword {
                password_file: Some(empty),
            },
            &[],
        )
        .unwrap_err();
        assert!(error.contains("has no password"), "{error}");
    }
}
