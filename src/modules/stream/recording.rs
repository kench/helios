//! Local recordings (LLD 4, section 16): each recording stream's own encoding, as sent, written
//! by its encoder as MPEG-TS segments under `[modules.stream.recording] dir`
//! (`<dir>/<stream>/<UTC start>-<n>.ts`). Once a minute the daemon checks the filesystem and
//! deletes the oldest closed segments, across every stream, while its usage is above
//! `max_usage_percent`.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::Deserialize;

use crate::mqtt::envelope::timestamp;

/// `[modules.stream.recording]`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Recording {
    /// Where segments go: one directory per stream.
    pub(crate) dir: PathBuf,
    /// How long each segment is: a new one starts at the first keyframe after this.
    pub(crate) segment_s: u32,
    /// Above this much of the filesystem in use, the oldest closed segments are deleted.
    pub(crate) max_usage_percent: u8,
    /// Records only when `dir` is a mounted filesystem's root, so a missing SSD (the fstab
    /// entry is `nofail`) can't fill the root filesystem.
    pub(crate) require_mountpoint: bool,
}

impl Default for Recording {
    fn default() -> Self {
        Self {
            dir: "/var/lib/helios-stream/recordings".into(),
            segment_s: 600,
            max_usage_percent: 90,
            require_mountpoint: true,
        }
    }
}

/// A segment written to this recently may still be open: it's never deleted.
const OPEN: Duration = Duration::from_secs(120);

impl Recording {
    /// Checks the settings.
    ///
    /// # Errors
    ///
    /// A message naming the setting that's wrong.
    pub(crate) fn check(&self) -> Result<(), String> {
        if !self.dir.is_absolute() {
            return Err("modules.stream.recording.dir must be an absolute path".into());
        }
        // It goes into ffmpeg's tee and a GStreamer pipeline, which give other characters
        // meanings.
        let plain = |c: char| c.is_ascii_alphanumeric() || "/._-".contains(c);
        if !self.dir.to_str().is_some_and(|dir| dir.chars().all(plain)) {
            return Err(
                "modules.stream.recording.dir may only use letters, digits, '/', '.', '_' and '-'"
                    .into(),
            );
        }
        if !(60..=3600).contains(&self.segment_s) {
            return Err("modules.stream.recording.segment_s must be 60 to 3600".into());
        }
        if !(10..=99).contains(&self.max_usage_percent) {
            return Err("modules.stream.recording.max_usage_percent must be 10 to 99".into());
        }
        Ok(())
    }

    /// One encoder run's files: the stream's directory, the run's name (its UTC start, such
    /// as `20261126T101500Z`) and the encoder's file pattern.
    pub(crate) fn files(&self, stream: &str, start: SystemTime) -> (PathBuf, String, PathBuf) {
        let dir = self.dir.join(stream);
        let name = file_time(start);
        let pattern = dir.join(format!("{name}-%05d.ts"));
        (dir, name, pattern)
    }
}

/// `2026-11-26T10:15:00.123Z` as `20261126T101500Z`.
fn file_time(time: SystemTime) -> String {
    let stamp = timestamp(time);
    let mut name: String = stamp
        .chars()
        .take(19)
        .filter(|c| *c != '-' && *c != ':')
        .collect();
    name.push('Z');
    name
}

/// What the recordings' filesystem looks like.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Disk {
    /// `dir` is a mount point (or one isn't required).
    pub mounted: bool,
    pub total_bytes: u64,
    pub free_bytes: u64,
    /// Segments on it, across all streams.
    pub segments: usize,
    pub oldest: Option<SystemTime>,
    /// Each stream's newest segment's file name.
    pub latest: BTreeMap<String, String>,
    /// Still above the limit with nothing left that may be deleted.
    pub full: bool,
    /// Why the filesystem can't be read.
    pub error: Option<String>,
}

impl Disk {
    /// Whether a stream starting now may record.
    pub(crate) fn usable(&self) -> bool {
        self.mounted && !self.full && self.error.is_none()
    }

    /// For the shadow. The figures change all the time, so `precise` leaves them out of the
    /// report that decides when to send.
    pub(crate) fn report(&self, dir: &Path, precise: bool) -> serde_json::Value {
        let mut report = serde_json::json!({
            "dir": dir.display().to_string(), "mounted": self.mounted, "full": self.full,
            "last_error": self.error,
        });
        if precise {
            report["total_bytes"] = self.total_bytes.into();
            report["free_bytes"] = self.free_bytes.into();
            report["segments"] = self.segments.into();
            report["oldest"] = self.oldest.map(timestamp).into();
        }
        report
    }
}

struct Segment {
    path: PathBuf,
    modified: SystemTime,
    bytes: u64,
}

/// Checks the filesystem and deletes the oldest closed segments while it's above the limit.
pub(crate) fn check(settings: &Recording) -> Disk {
    check_at(settings, SystemTime::now(), &|| {
        std::fs::read_to_string("/proc/self/mountinfo")
    })
}

fn check_at(
    settings: &Recording,
    now: SystemTime,
    mountinfo: &dyn Fn() -> std::io::Result<String>,
) -> Disk {
    let dir = &settings.dir;
    let mounted =
        !settings.require_mountpoint || mountinfo().is_ok_and(|text| is_mount_point(&text, dir));
    if !mounted {
        return Disk::default();
    }
    let (total, free) = match usage(dir) {
        Ok(usage) => usage,
        Err(error) => {
            return Disk {
                mounted,
                error: Some(format!("can't read {}: {error}", dir.display())),
                ..Disk::default()
            };
        }
    };
    let mut segments = segments(dir);
    segments.sort_by_key(|segment| segment.modified);
    let limit = total / 100 * u64::from(settings.max_usage_percent);
    let mut used = total.saturating_sub(free);
    let mut kept = Vec::with_capacity(segments.len());
    for segment in segments {
        let closed = now
            .duration_since(segment.modified)
            .is_ok_and(|age| age >= OPEN);
        if used > limit && closed {
            match std::fs::remove_file(&segment.path) {
                Ok(()) => {
                    tracing::info!(file = %segment.path.display(), "recordings: disk above \
                        its limit, deleted the oldest segment");
                    used = used.saturating_sub(segment.bytes);
                    continue;
                }
                Err(error) => tracing::warn!(
                    file = %segment.path.display(), %error, "recordings: can't delete a segment"
                ),
            }
        }
        kept.push(segment);
    }
    let mut latest = BTreeMap::new();
    for segment in &kept {
        if let (Some(stream), Some(name)) = (
            segment
                .path
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str()),
            segment.path.file_name().and_then(|n| n.to_str()),
        ) {
            // Sorted oldest first, so the last one seen is the newest.
            latest.insert(stream.to_owned(), name.to_owned());
        }
    }
    Disk {
        mounted,
        total_bytes: total,
        free_bytes: total.saturating_sub(used),
        segments: kept.len(),
        oldest: kept.first().map(|segment| segment.modified),
        latest,
        full: used > limit,
        error: None,
    }
}

/// The filesystem's size and the space unprivileged users may still use, in bytes.
fn usage(dir: &Path) -> std::io::Result<(u64, u64)> {
    let stat = rustix::fs::statvfs(dir)?;
    Ok((
        stat.f_blocks.saturating_mul(stat.f_frsize),
        stat.f_bavail.saturating_mul(stat.f_frsize),
    ))
}

/// Every stream's `.ts` segments, with the space each takes on disk.
fn segments(dir: &Path) -> Vec<Segment> {
    let mut found = Vec::new();
    let Ok(streams) = std::fs::read_dir(dir) else {
        return found;
    };
    for stream in streams.flatten() {
        if !stream.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let Ok(files) = std::fs::read_dir(stream.path()) else {
            continue;
        };
        for file in files.flatten() {
            let path = file.path();
            if path.extension().is_none_or(|ext| ext != "ts") {
                continue;
            }
            let Ok(metadata) = file.metadata() else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            found.push(Segment {
                path,
                modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                bytes: metadata.blocks().saturating_mul(512),
            });
        }
    }
    found
}

/// Whether `dir` is a mount point in `/proc/self/mountinfo` (the fifth field, with spaces and
/// other special characters written as octal escapes).
fn is_mount_point(mountinfo: &str, dir: &Path) -> bool {
    let wanted = dir.to_string_lossy();
    let wanted = match wanted.trim_end_matches('/') {
        "" => "/",
        trimmed => trimmed,
    };
    mountinfo
        .lines()
        .filter_map(|line| line.split(' ').nth(4))
        .any(|point| unescape(point) == wanted)
}

fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..=i + 3]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
        {
            let value = bytes[i + 1..=i + 3]
                .iter()
                .fold(0u32, |acc, b| acc * 8 + u32::from(b - b'0'));
            if let Ok(byte) = u8::try_from(value) {
                out.push(byte);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTINFO: &str = "\
22 1 179:2 / / rw,noatime shared:1 - ext4 /dev/mmcblk0p2 rw
40 22 259:1 / /var/lib/helios-stream/recordings rw,noatime shared:20 - ext4 /dev/nvme0n1p1 rw
41 22 259:2 / /mnt/with\\040space rw shared:21 - ext4 /dev/sda1 rw
";

    #[test]
    fn finds_mount_points() {
        let dir = Path::new("/var/lib/helios-stream/recordings");
        assert!(is_mount_point(MOUNTINFO, dir));
        assert!(is_mount_point(
            MOUNTINFO,
            Path::new("/var/lib/helios-stream/recordings/")
        ));
        assert!(is_mount_point(MOUNTINFO, Path::new("/mnt/with space")));
        assert!(is_mount_point(MOUNTINFO, Path::new("/")));
        assert!(!is_mount_point(MOUNTINFO, Path::new("/var/lib")));
        assert_eq!(unescape("a\\134b\\9"), "a\\b\\9");
    }

    #[test]
    fn checks_its_settings_and_names_files_by_utc_start() {
        assert!(Recording::default().check().is_ok());
        for (change, message) in [
            (
                Recording {
                    dir: "relative".into(),
                    ..Recording::default()
                },
                "absolute",
            ),
            (
                Recording {
                    dir: "/mnt/a b".into(),
                    ..Recording::default()
                },
                "may only use",
            ),
            (
                Recording {
                    segment_s: 10,
                    ..Recording::default()
                },
                "segment_s",
            ),
            (
                Recording {
                    max_usage_percent: 100,
                    ..Recording::default()
                },
                "max_usage_percent",
            ),
        ] {
            assert!(change.check().expect_err("refused").contains(message));
        }
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_795_688_100);
        let (dir, name, pattern) = Recording::default().files("pocket", start);
        assert_eq!(dir, Path::new("/var/lib/helios-stream/recordings/pocket"));
        assert_eq!(name, "20261126T101500Z");
        assert_eq!(
            pattern,
            Path::new("/var/lib/helios-stream/recordings/pocket/20261126T101500Z-%05d.ts")
        );
    }

    #[test]
    fn records_only_on_a_mounted_filesystem() {
        let temp = tempfile::tempdir().expect("tempdir");
        let settings = Recording {
            dir: temp.path().to_owned(),
            ..Recording::default()
        };
        let none = || Ok(String::new());
        let disk = check_at(&settings, SystemTime::now(), &none);
        assert_eq!(disk, Disk::default());
        assert!(!disk.usable());
        let mounted = format!(
            "40 22 259:1 / {} rw - ext4 /dev/x rw\n",
            temp.path().display()
        );
        let disk = check_at(&settings, SystemTime::now(), &|| Ok(mounted.clone()));
        assert!(
            disk.mounted && disk.usable() && disk.total_bytes > 0,
            "{disk:?}"
        );
        let missing = Recording {
            dir: temp.path().join("gone"),
            require_mountpoint: false,
            ..Recording::default()
        };
        let disk = check_at(&missing, SystemTime::now(), &none);
        assert!(disk.error.is_some() && !disk.usable());
        let report = disk.report(&missing.dir, true);
        assert!(report["last_error"].is_string() && report["total_bytes"] == 0);
        assert!(disk.report(&missing.dir, false).get("free_bytes").is_none());
    }

    #[test]
    fn deletes_the_oldest_closed_segments_above_the_limit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let write = |stream: &str, name: &str, age_s: u64| {
            let dir = temp.path().join(stream);
            std::fs::create_dir_all(&dir).expect("dir");
            let path = dir.join(name);
            std::fs::write(&path, vec![0u8; 64 * 1024]).expect("write");
            let file = std::fs::File::options()
                .write(true)
                .open(&path)
                .expect("open");
            file.set_modified(SystemTime::now() - Duration::from_secs(age_s))
                .expect("mtime");
            path
        };
        let oldest = write("a", "20261126T100000Z-00000.ts", 3600);
        let older = write("b", "20261126T101000Z-00000.ts", 3000);
        let open = write("a", "20261126T110000Z-00000.ts", 10);
        std::fs::write(temp.path().join("a/notes.txt"), "x").expect("write");
        std::fs::write(temp.path().join("stray.ts"), "x").expect("write");
        let generous = Recording {
            dir: temp.path().to_owned(),
            require_mountpoint: false,
            max_usage_percent: 99,
            ..Recording::default()
        };
        let disk = check_at(&generous, SystemTime::now(), &|| Ok(String::new()));
        assert_eq!(disk.segments, 3, "{disk:?}");
        assert!(disk.oldest.is_some());
        assert_eq!(disk.latest["a"], "20261126T110000Z-00000.ts");
        assert_eq!(disk.latest["b"], "20261126T101000Z-00000.ts");

        // A limit the temporary filesystem is surely above: every closed segment goes, the
        // open one stays, and the disk counts as full.
        let tight = Recording {
            max_usage_percent: 10,
            ..generous
        };
        let used = usage(temp.path()).map(|(total, free)| (total - free) * 100 / total.max(1));
        if used.is_ok_and(|percent| percent > 10) {
            let disk = check_at(&tight, SystemTime::now(), &|| Ok(String::new()));
            assert!(!oldest.exists() && !older.exists() && open.exists());
            assert_eq!(disk.segments, 1);
            assert!(disk.full && !disk.usable());
            assert!(!disk.latest.contains_key("b"));
        }
    }
}
