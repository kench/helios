//! Where the token PIN comes from (LLD 1, section 4.5).
//!
//! The `identity.pin` setting is one of:
//!
//! - `bootstrap`: the bootstrap service returns the PIN once per process start, and Helios keeps
//!   it in a [`FixedPin`] (zeroized when dropped).
//! - `credential:<name>`: a systemd credential, read from `$CREDENTIALS_DIRECTORY/<name>`. For
//!   development, with `LoadCredential=` in the unit.
//! - `file:<path>`: a file owned by root or the user Helios runs as, with no group or other
//!   permissions (mode `0400` or `0600`).
//!
//! The identity manager reads the PIN from a [`PinSource`] on the signer thread just before each
//! login, and drops it straight after. The credential and file sources read it again every time,
//! so it isn't kept in memory between logins.

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use secrecy::zeroize::Zeroizing;
use secrecy::{ExposeSecret, SecretString};

/// The longest PIN file accepted, in bytes. PKCS#11 PINs are short (a YubiKey's is at most 8
/// characters), so anything much longer is the wrong file.
pub const MAX_PIN_LEN: usize = 256;

/// The PIN couldn't be read. This is a configuration problem, so it is fatal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("token PIN could not be read: {reason}")]
pub struct PinError {
    reason: String,
}

impl PinError {
    /// An error with `reason`, which must not contain the PIN.
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

/// Supplies the token PIN for each login.
pub trait PinSource: Send + Sync + 'static {
    /// Reads the PIN.
    ///
    /// # Errors
    ///
    /// [`PinError`] if the PIN isn't available.
    fn read(&self) -> Result<SecretString, PinError>;
}

/// A PIN held in memory, such as the one the bootstrap service returns. Zeroized when dropped.
#[derive(Debug)]
pub struct FixedPin(SecretString);

impl FixedPin {
    /// Holds `pin`.
    #[must_use]
    pub fn new(pin: SecretString) -> Self {
        Self(pin)
    }
}

impl PinSource for FixedPin {
    fn read(&self) -> Result<SecretString, PinError> {
        Ok(SecretString::new(self.0.expose_secret().clone()))
    }
}

/// The `identity.pin` setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinSpec {
    /// From the bootstrap service.
    Bootstrap,
    /// The systemd credential with this name.
    Credential(String),
    /// A file at this absolute path.
    File(PathBuf),
}

/// The `identity.pin` setting isn't valid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PinSpecError {
    /// Not one of the three forms.
    #[error(
        "identity.pin must be \"bootstrap\", \"credential:<name>\" or \"file:<path>\", not {0:?}"
    )]
    Form(String),
    /// The credential name is empty or contains `/`.
    #[error("identity.pin credential name {0:?} is not valid")]
    CredentialName(String),
    /// The file path isn't absolute.
    #[error("identity.pin file path {0:?} must be absolute")]
    RelativePath(PathBuf),
    /// `credential:` was used but systemd didn't set `CREDENTIALS_DIRECTORY`.
    #[error(
        "identity.pin uses credential {0:?}, but CREDENTIALS_DIRECTORY is not set; add \
         LoadCredential= to the unit"
    )]
    NoCredentialsDirectory(String),
}

impl FromStr for PinSpec {
    type Err = PinSpecError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "bootstrap" {
            return Ok(Self::Bootstrap);
        }
        if let Some(name) = value.strip_prefix("credential:") {
            if name.is_empty() || name == "." || name == ".." || name.contains('/') {
                return Err(PinSpecError::CredentialName(name.to_owned()));
            }
            return Ok(Self::Credential(name.to_owned()));
        }
        if let Some(path) = value.strip_prefix("file:") {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err(PinSpecError::RelativePath(path));
            }
            return Ok(Self::File(path));
        }
        Err(PinSpecError::Form(value.to_owned()))
    }
}

impl fmt::Display for PinSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bootstrap => f.write_str("bootstrap"),
            Self::Credential(name) => write!(f, "credential:{name}"),
            Self::File(path) => write!(f, "file:{}", path.display()),
        }
    }
}

impl PinSpec {
    /// The source for a local PIN setting, or `None` for [`Bootstrap`](Self::Bootstrap), whose
    /// PIN comes later from the bootstrap service. The PIN itself isn't read yet.
    ///
    /// `credentials_directory` is `$CREDENTIALS_DIRECTORY`, from
    /// [`credentials_directory_from_env`].
    ///
    /// # Errors
    ///
    /// [`PinSpecError::NoCredentialsDirectory`] for a credential when systemd didn't set the
    /// directory.
    pub fn local_source(
        &self,
        credentials_directory: Option<&Path>,
    ) -> Result<Option<Arc<dyn PinSource>>, PinSpecError> {
        match self {
            Self::Bootstrap => Ok(None),
            Self::Credential(name) => {
                let directory = credentials_directory
                    .ok_or_else(|| PinSpecError::NoCredentialsDirectory(name.clone()))?;
                Ok(Some(Arc::new(CredentialPin {
                    path: directory.join(name),
                })))
            }
            Self::File(path) => Ok(Some(Arc::new(FilePin { path: path.clone() }))),
        }
    }
}

/// `$CREDENTIALS_DIRECTORY`, which systemd sets for units with `LoadCredential=`.
#[must_use]
pub fn credentials_directory_from_env() -> Option<PathBuf> {
    std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from)
}

/// A systemd credential. systemd makes it readable only by the service, so its permissions
/// aren't checked.
#[derive(Debug)]
struct CredentialPin {
    path: PathBuf,
}

impl PinSource for CredentialPin {
    fn read(&self) -> Result<SecretString, PinError> {
        let file = open(&self.path)?;
        read_pin(file, &self.path)
    }
}

/// A PIN file, checked for ownership and permissions on every read.
#[derive(Debug)]
struct FilePin {
    path: PathBuf,
}

impl PinSource for FilePin {
    fn read(&self) -> Result<SecretString, PinError> {
        let file = open(&self.path)?;
        // Checked on the open file, so it can't be swapped between the check and the read.
        let metadata = file
            .metadata()
            .map_err(|error| PinError::new(format!("{}: {error}", self.path.display())))?;
        check_permissions(
            &self.path,
            metadata.is_file(),
            metadata.uid(),
            metadata.mode(),
            rustix::process::geteuid().as_raw(),
        )?;
        read_pin(file, &self.path)
    }
}

fn open(path: &Path) -> Result<File, PinError> {
    File::open(path).map_err(|error| PinError::new(format!("{}: {error}", path.display())))
}

/// A PIN file must be a regular file owned by root or by `euid`, with no group or other
/// permissions.
fn check_permissions(
    path: &Path,
    is_file: bool,
    owner: u32,
    mode: u32,
    euid: u32,
) -> Result<(), PinError> {
    let path = path.display();
    if !is_file {
        return Err(PinError::new(format!("{path} is not a regular file")));
    }
    if owner != 0 && owner != euid {
        return Err(PinError::new(format!(
            "{path} is owned by uid {owner}; it must be owned by root or uid {euid}"
        )));
    }
    if mode & 0o077 != 0 {
        return Err(PinError::new(format!(
            "{path} has mode {:04o}; it must have no group or other permissions (0400 or 0600)",
            mode & 0o7777
        )));
    }
    Ok(())
}

/// Reads a PIN, removing one trailing newline. The buffer is zeroized afterwards.
fn read_pin(file: File, path: &Path) -> Result<SecretString, PinError> {
    let display = path.display();
    let mut buffer = Zeroizing::new([0u8; MAX_PIN_LEN + 1]);
    let mut len = 0;
    let mut file = file.take(u64::try_from(buffer.len()).unwrap_or(u64::MAX));
    loop {
        let read = file
            .read(&mut buffer[len..])
            .map_err(|error| PinError::new(format!("{display}: {error}")))?;
        if read == 0 {
            break;
        }
        len += read;
    }
    let mut pin = &buffer[..len];
    pin = pin.strip_suffix(b"\n").unwrap_or(pin);
    pin = pin.strip_suffix(b"\r").unwrap_or(pin);
    if len > MAX_PIN_LEN {
        return Err(PinError::new(format!(
            "{display} is longer than {MAX_PIN_LEN} bytes"
        )));
    }
    if pin.is_empty() {
        return Err(PinError::new(format!("{display} is empty")));
    }
    let pin = std::str::from_utf8(pin)
        .map_err(|_| PinError::new(format!("{display} is not valid UTF-8")))?;
    Ok(SecretString::new(pin.to_owned()))
}

#[cfg(test)]
mod tests {
    use std::fs::Permissions;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn a_fixed_pin_is_read_every_time() {
        let pin = FixedPin::new(SecretString::new("123456".into()));

        assert_eq!(pin.read().unwrap().expose_secret(), "123456");
        assert_eq!(pin.read().unwrap().expose_secret(), "123456");
        assert!(!format!("{pin:?}").contains("123456"));
    }

    #[test]
    fn errors_describe_the_reason() {
        assert_eq!(
            PinError::new("credential helios-pin is missing").to_string(),
            "token PIN could not be read: credential helios-pin is missing"
        );
    }

    #[test]
    fn parses_the_three_forms() {
        assert_eq!("bootstrap".parse(), Ok(PinSpec::Bootstrap));
        assert_eq!(
            "credential:helios-pin".parse(),
            Ok(PinSpec::Credential("helios-pin".into()))
        );
        assert_eq!(
            "file:/etc/helios/pin".parse(),
            Ok(PinSpec::File("/etc/helios/pin".into()))
        );
        for spec in ["bootstrap", "credential:helios-pin", "file:/etc/helios/pin"] {
            assert_eq!(spec.parse::<PinSpec>().unwrap().to_string(), spec);
        }
    }

    #[test]
    fn rejects_other_settings() {
        for value in ["", "1234", "env:PIN", "Bootstrap", "file", "credential"] {
            assert_eq!(
                value.parse::<PinSpec>(),
                Err(PinSpecError::Form(value.into())),
                "{value}"
            );
        }
        for name in ["", ".", "..", "a/b", "../pin"] {
            assert_eq!(
                format!("credential:{name}").parse::<PinSpec>(),
                Err(PinSpecError::CredentialName(name.into())),
                "{name}"
            );
        }
        assert_eq!(
            "file:pin".parse::<PinSpec>(),
            Err(PinSpecError::RelativePath("pin".into()))
        );
        assert!(
            PinSpecError::Form("1234".into())
                .to_string()
                .contains("\"bootstrap\", \"credential:<name>\" or \"file:<path>\"")
        );
    }

    fn pin_file(contents: &[u8], mode: u32) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(contents).unwrap();
        std::fs::set_permissions(file.path(), Permissions::from_mode(mode)).unwrap();
        file
    }

    fn file_source(path: &Path) -> Arc<dyn PinSource> {
        PinSpec::File(path.to_owned())
            .local_source(None)
            .unwrap()
            .unwrap()
    }

    #[test]
    fn reads_a_private_pin_file_on_every_read() {
        for mode in [0o400, 0o600] {
            let file = pin_file(b"123456\n", mode);
            let source = file_source(file.path());

            assert_eq!(source.read().unwrap().expose_secret(), "123456");
            std::fs::set_permissions(file.path(), Permissions::from_mode(0o600)).unwrap();
            std::fs::write(file.path(), b"654321").unwrap();
            assert_eq!(source.read().unwrap().expose_secret(), "654321");
        }
    }

    #[test]
    fn refuses_pin_files_others_can_access() {
        for mode in [0o640, 0o604, 0o644, 0o660, 0o700 | 0o004] {
            let file = pin_file(b"123456", mode);

            let error = file_source(file.path()).read().unwrap_err();

            assert!(
                error
                    .to_string()
                    .contains("must have no group or other permissions"),
                "{mode:o}: {error}"
            );
        }
    }

    #[test]
    fn refuses_pin_files_owned_by_other_users() {
        let path = Path::new("/etc/helios/pin");

        assert_eq!(check_permissions(path, true, 0, 0o100_400, 998), Ok(()));
        assert_eq!(check_permissions(path, true, 998, 0o100_600, 998), Ok(()));
        let error = check_permissions(path, true, 1000, 0o100_600, 998).unwrap_err();
        assert_eq!(
            error.to_string(),
            "token PIN could not be read: /etc/helios/pin is owned by uid 1000; it must be owned \
             by root or uid 998"
        );
        let error = check_permissions(path, true, 0, 0o100_640, 998).unwrap_err();
        assert!(error.to_string().contains("has mode 0640"), "{error}");
    }

    #[test]
    fn refuses_anything_but_a_regular_file() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), Permissions::from_mode(0o700)).unwrap();

        let error = file_source(directory.path()).read().unwrap_err();

        assert!(
            error.to_string().contains("is not a regular file"),
            "{error}"
        );
    }

    #[test]
    fn a_missing_file_names_the_path() {
        let error = file_source(Path::new("/nonexistent/helios/pin"))
            .read()
            .unwrap_err();

        assert!(
            error.to_string().contains("/nonexistent/helios/pin: "),
            "{error}"
        );
    }

    #[test]
    fn strips_one_trailing_newline_only() {
        for (contents, expected) in [
            (&b"1234"[..], "1234"),
            (b"1234\n", "1234"),
            (b"1234\r\n", "1234"),
            (b"1234\n\n", "1234\n"),
            (b" 1234 ", " 1234 "),
        ] {
            let file = pin_file(contents, 0o600);
            let pin = file_source(file.path()).read().unwrap();
            assert_eq!(pin.expose_secret(), expected, "{contents:?}");
        }
    }

    #[test]
    fn rejects_empty_long_and_binary_pins() {
        for (contents, problem) in [
            (Vec::new(), "is empty"),
            (b"\n".to_vec(), "is empty"),
            (vec![b'1'; MAX_PIN_LEN + 1], "is longer than 256 bytes"),
            (vec![0xff, 0xfe], "is not valid UTF-8"),
        ] {
            let file = pin_file(&contents, 0o600);

            let error = file_source(file.path()).read().unwrap_err();

            assert!(error.to_string().contains(problem), "{error}");
            assert!(!error.to_string().contains("111111"));
        }
        let longest = pin_file(&[b'1'; MAX_PIN_LEN], 0o600);
        assert_eq!(
            file_source(longest.path())
                .read()
                .unwrap()
                .expose_secret()
                .len(),
            MAX_PIN_LEN
        );
    }

    #[test]
    fn reads_systemd_credentials_from_the_credentials_directory() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("helios-pin"), b"123456\n").unwrap();
        let spec = PinSpec::Credential("helios-pin".into());

        let source = spec.local_source(Some(directory.path())).unwrap().unwrap();
        assert_eq!(source.read().unwrap().expose_secret(), "123456");

        let missing = PinSpec::Credential("other".into())
            .local_source(Some(directory.path()))
            .unwrap()
            .unwrap();
        assert!(missing.read().unwrap_err().to_string().contains("other: "));

        let error = spec.local_source(None).err().unwrap();
        assert_eq!(
            error,
            PinSpecError::NoCredentialsDirectory("helios-pin".into())
        );
        assert!(
            error
                .to_string()
                .contains("add LoadCredential= to the unit")
        );
    }

    #[test]
    fn the_bootstrap_pin_has_no_local_source() {
        assert!(PinSpec::Bootstrap.local_source(None).unwrap().is_none());
    }

    #[test]
    fn credentials_directory_comes_from_the_environment() {
        // The test environment has no systemd credentials, unless run under a unit that has.
        assert_eq!(
            credentials_directory_from_env(),
            std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from)
        );
    }
}
