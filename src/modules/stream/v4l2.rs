//! A camera's capture formats over V4L2, for the `stream` shadow's `inputs` (HLD 7.3.7): each
//! pixel format, its frame sizes and, for each size, its frame rates.
//!
//! Three read-only enumerate ioctls (`VIDIOC_ENUM_FMT`, `VIDIOC_ENUM_FRAMESIZES`,
//! `VIDIOC_ENUM_FRAMEINTERVALS`) on a descriptor opened read-only and non-blocking: they don't
//! change the device and work while another process streams from it. These are one of Helios's
//! approved `unsafe` sites (owner, 2026-11-22): rustix has no safe V4L2 wrappers, and its
//! `ioctl` is an `unsafe fn` whose caller vouches for the opcode and the argument's layout.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use rustix::ioctl::{Opcode, Updater, opcode};

/// At most this many pixel formats, sizes per format and rates per size are reported: the
/// whole shadow document must stay under AWS IoT's 8 KB.
const MAX_FORMATS: usize = 6;
const MAX_SIZES: usize = 12;
const MAX_RATES: usize = 6;
/// Enumeration stops here whatever the driver says, so a buggy one can't loop forever.
const MAX_INDEX: u32 = 256;

const V4L2_BUF_TYPE_VIDEO_CAPTURE: u32 = 1;
const V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE: u32 = 9;
const V4L2_FRMSIZE_TYPE_DISCRETE: u32 = 1;
const V4L2_FRMIVAL_TYPE_DISCRETE: u32 = 1;

/// `struct v4l2_fmtdesc` (64 bytes).
#[repr(C)]
#[derive(Debug, Default)]
struct FmtDesc {
    index: u32,
    kind: u32,
    flags: u32,
    description: [u8; 32],
    pixel_format: u32,
    mbus_code: u32,
    reserved: [u32; 3],
}

/// `struct v4l2_frmsizeenum` (44 bytes). `size` is the union: `{width, height}` when discrete,
/// else `{min_width, max_width, step_width, min_height, max_height, step_height}`.
#[repr(C)]
#[derive(Debug, Default)]
struct FrmSizeEnum {
    index: u32,
    pixel_format: u32,
    kind: u32,
    size: [u32; 6],
    reserved: [u32; 2],
}

/// `struct v4l2_frmivalenum` (52 bytes). `interval` is the union: `{numerator, denominator}`
/// when discrete, else the `min`, `max` and `step` fractions.
#[repr(C)]
#[derive(Debug, Default)]
struct FrmIvalEnum {
    index: u32,
    pixel_format: u32,
    width: u32,
    height: u32,
    kind: u32,
    interval: [u32; 6],
    reserved: [u32; 2],
}

const _: () = assert!(size_of::<FmtDesc>() == 64);
const _: () = assert!(size_of::<FrmSizeEnum>() == 44);
const _: () = assert!(size_of::<FrmIvalEnum>() == 52);

/// `_IOWR('V', 2, struct v4l2_fmtdesc)`
const VIDIOC_ENUM_FMT: Opcode = opcode::read_write::<FmtDesc>(b'V', 2);
/// `_IOWR('V', 74, struct v4l2_frmsizeenum)`
const VIDIOC_ENUM_FRAMESIZES: Opcode = opcode::read_write::<FrmSizeEnum>(b'V', 74);
/// `_IOWR('V', 75, struct v4l2_frmivalenum)`
const VIDIOC_ENUM_FRAMEINTERVALS: Opcode = opcode::read_write::<FrmIvalEnum>(b'V', 75);

/// One pixel format at one frame size, with its frame rates (highest first).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Format {
    /// ffmpeg's name for it (`mjpeg`, `yuyv422`, `h264`, …), as a profile's `input.format`
    /// takes it.
    pub pixel_format: String,
    pub width: u32,
    pub height: u32,
    pub fps: Vec<f64>,
}

/// The capture formats of the V4L2 device at `path`.
///
/// # Errors
///
/// Opening the device, or an enumeration error other than the end of a list.
pub(crate) fn formats(path: &Path) -> io::Result<Vec<Format>> {
    let device = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let mut found = Vec::new();
    let mut pixel_formats = Vec::new();
    for kind in [
        V4L2_BUF_TYPE_VIDEO_CAPTURE,
        V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
    ] {
        for index in 0..MAX_INDEX {
            let mut desc = FmtDesc {
                index,
                kind,
                ..FmtDesc::default()
            };
            if !next(enum_fmt(&device, &mut desc))? {
                break;
            }
            if !pixel_formats.contains(&desc.pixel_format) {
                pixel_formats.push(desc.pixel_format);
            }
        }
    }
    for pixel_format in pixel_formats.into_iter().take(MAX_FORMATS) {
        for (width, height) in sizes(&device, pixel_format)? {
            found.push(Format {
                pixel_format: name(pixel_format),
                width,
                height,
                fps: rates(&device, pixel_format, width, height)?,
            });
        }
    }
    Ok(found)
}

/// `Ok(true)` for an entry, `Ok(false)` at the end of the list (`EINVAL`).
fn next(result: rustix::io::Result<()>) -> io::Result<bool> {
    match result {
        Ok(()) => Ok(true),
        Err(rustix::io::Errno::INVAL) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// A format's frame sizes, largest first. A stepwise or continuous range gives its two ends.
fn sizes(device: &File, pixel_format: u32) -> io::Result<Vec<(u32, u32)>> {
    let mut sizes = Vec::new();
    for index in 0..MAX_INDEX {
        let mut size = FrmSizeEnum {
            index,
            pixel_format,
            ..FrmSizeEnum::default()
        };
        if !next(enum_framesizes(device, &mut size))? {
            break;
        }
        if size.kind == V4L2_FRMSIZE_TYPE_DISCRETE {
            sizes.push((size.size[0], size.size[1]));
        } else {
            let [min_width, max_width, _, min_height, max_height, _] = size.size;
            sizes.push((max_width, max_height));
            sizes.push((min_width, min_height));
            break;
        }
    }
    sizes.retain(|&(width, height)| width > 0 && height > 0);
    sizes.sort_by_key(|&(width, height)| {
        std::cmp::Reverse((u64::from(width) * u64::from(height), width))
    });
    sizes.dedup();
    sizes.truncate(MAX_SIZES);
    Ok(sizes)
}

/// A size's frame rates, highest first. A stepwise or continuous range gives its two ends.
fn rates(device: &File, pixel_format: u32, width: u32, height: u32) -> io::Result<Vec<f64>> {
    let mut rates = Vec::new();
    for index in 0..MAX_INDEX {
        let mut interval = FrmIvalEnum {
            index,
            pixel_format,
            width,
            height,
            ..FrmIvalEnum::default()
        };
        if !next(enum_frameintervals(device, &mut interval))? {
            break;
        }
        let [numerator, denominator, max_numerator, max_denominator, ..] = interval.interval;
        rates.extend(fps(numerator, denominator));
        if interval.kind != V4L2_FRMIVAL_TYPE_DISCRETE {
            // The shortest interval (`min`) is the highest rate; `max` the lowest.
            rates.extend(fps(max_numerator, max_denominator));
            break;
        }
    }
    rates.sort_by(|a, b| b.total_cmp(a));
    rates.dedup();
    rates.truncate(MAX_RATES);
    Ok(rates)
}

/// Frames a second for an interval of `numerator / denominator` seconds, to 3 decimals.
fn fps(numerator: u32, denominator: u32) -> Option<f64> {
    (numerator > 0 && denominator > 0)
        .then(|| (f64::from(denominator) / f64::from(numerator) * 1000.0).round() / 1000.0)
}

/// ffmpeg's name for a V4L2 fourcc, or the fourcc itself, lowercased.
fn name(fourcc: u32) -> String {
    let code: String = fourcc
        .to_le_bytes()
        .iter()
        .map(|&byte| char::from(byte))
        .collect::<String>()
        .trim_end()
        .to_owned();
    match code.as_str() {
        "MJPG" | "JPEG" => "mjpeg".into(),
        "YUYV" => "yuyv422".into(),
        "UYVY" => "uyvy422".into(),
        "NV12" => "nv12".into(),
        "NV21" => "nv21".into(),
        "YU12" => "yuv420p".into(),
        "H264" => "h264".into(),
        "HEVC" => "hevc".into(),
        "RGB3" => "rgb24".into(),
        "BGR3" => "bgr24".into(),
        "GREY" => "gray".into(),
        _ => code
            .chars()
            .filter(char::is_ascii_graphic)
            .collect::<String>()
            .to_ascii_lowercase(),
    }
}

#[allow(unsafe_code)]
fn enum_fmt(device: &File, desc: &mut FmtDesc) -> rustix::io::Result<()> {
    // SAFETY: VIDIOC_ENUM_FMT is _IOWR('V', 2, struct v4l2_fmtdesc), and `FmtDesc` is that
    // struct's #[repr(C)] layout (size checked above), every field plain integers, so any bytes
    // the kernel writes are a valid `FmtDesc`. The borrow outlives the call. Read-only query.
    unsafe { rustix::ioctl::ioctl(device, Updater::<VIDIOC_ENUM_FMT, FmtDesc>::new(desc)) }
}

#[allow(unsafe_code)]
fn enum_framesizes(device: &File, size: &mut FrmSizeEnum) -> rustix::io::Result<()> {
    // SAFETY: VIDIOC_ENUM_FRAMESIZES is _IOWR('V', 74, struct v4l2_frmsizeenum), and
    // `FrmSizeEnum` is that struct's #[repr(C)] layout (size checked above; the union as six
    // u32s, its largest member), all plain integers. The borrow outlives the call. Read-only.
    unsafe {
        rustix::ioctl::ioctl(
            device,
            Updater::<VIDIOC_ENUM_FRAMESIZES, FrmSizeEnum>::new(size),
        )
    }
}

#[allow(unsafe_code)]
fn enum_frameintervals(device: &File, interval: &mut FrmIvalEnum) -> rustix::io::Result<()> {
    // SAFETY: VIDIOC_ENUM_FRAMEINTERVALS is _IOWR('V', 75, struct v4l2_frmivalenum), and
    // `FrmIvalEnum` is that struct's #[repr(C)] layout (size checked above; the union as six
    // u32s, its largest member), all plain integers. The borrow outlives the call. Read-only.
    unsafe {
        rustix::ioctl::ioctl(
            device,
            Updater::<VIDIOC_ENUM_FRAMEINTERVALS, FrmIvalEnum>::new(interval),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcodes_match_the_kernel_headers() {
        // From <linux/videodev2.h> on x86_64 and arm64.
        assert_eq!(VIDIOC_ENUM_FMT, 0xc040_5602);
        assert_eq!(VIDIOC_ENUM_FRAMESIZES, 0xc02c_564a);
        assert_eq!(VIDIOC_ENUM_FRAMEINTERVALS, 0xc034_564b);
    }

    #[test]
    fn names_pixel_formats_as_ffmpeg_does() {
        let fourcc = |code: &[u8; 4]| u32::from_le_bytes(*code);
        assert_eq!(name(fourcc(b"MJPG")), "mjpeg");
        assert_eq!(name(fourcc(b"YUYV")), "yuyv422");
        assert_eq!(name(fourcc(b"H264")), "h264");
        assert_eq!(name(fourcc(b"Y16 ")), "y16");
    }

    #[test]
    fn turns_intervals_into_rates() {
        assert_eq!(fps(1, 30), Some(30.0));
        assert_eq!(fps(1001, 30000), Some(29.97));
        assert_eq!(fps(0, 30), None);
        assert_eq!(fps(1, 0), None);
    }

    #[test]
    fn reports_errors_other_than_the_end_of_a_list() {
        assert!(!next(Err(rustix::io::Errno::INVAL)).unwrap());
        assert!(next(Ok(())).unwrap());
        assert!(next(Err(rustix::io::Errno::NODEV)).is_err());
    }

    #[test]
    fn a_file_that_isnt_a_camera_lists_nothing_or_fails() {
        // /dev/null takes no V4L2 ioctls: ENOTTY.
        assert!(formats(Path::new("/dev/null")).is_err());
        assert!(formats(Path::new("/nonexistent/video0")).is_err());
    }
}
