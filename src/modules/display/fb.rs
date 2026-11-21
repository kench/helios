//! The framebuffer (LLD 9, sections 2–4): its geometry from sysfs, whether the kernel's console
//! still draws on it, and writing screens to it with positioned writes, only the rows that
//! changed. No `mmap`, so no `unsafe` code.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use super::canvas::{BYTES_PER_PIXEL, Canvas};

/// A framebuffer's layout, as sysfs reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    /// Visible width in pixels.
    pub width: usize,
    /// Visible height in pixels.
    pub height: usize,
    /// Bits per pixel.
    pub bits_per_pixel: usize,
    /// Bytes from one row to the next.
    pub stride: usize,
}

impl Geometry {
    /// Reads the geometry of `device` (for example `/dev/fb0`) from `sysfs`
    /// (`<sysfs>/class/graphics/fb0/`), and checks Helios can draw on it: 32 bits per pixel, and
    /// rows at least as long as their pixels.
    ///
    /// # Errors
    ///
    /// A message for the shadow if it can't be read or isn't supported.
    pub fn read(sysfs: &Path, device: &Path) -> Result<Self, String> {
        let name = device
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or_else(|| format!("{} isn't a framebuffer device", device.display()))?;
        let dir = sysfs.join("class/graphics").join(&name);
        let read = |attribute: &str| {
            std::fs::read_to_string(dir.join(attribute))
                .map(|text| text.trim().to_owned())
                .map_err(|error| format!("can't read {}: {error}", dir.join(attribute).display()))
        };
        let number = |attribute: &str, text: &str| {
            text.parse::<usize>()
                .map_err(|_| format!("{name} {attribute} isn't a number: {text:?}"))
        };
        let size = read("virtual_size")?;
        let (width, height) = size
            .split_once(',')
            .ok_or_else(|| format!("{name} virtual_size isn't width,height: {size:?}"))?;
        let geometry = Self {
            width: number("virtual_size", width)?,
            height: number("virtual_size", height)?,
            bits_per_pixel: number("bits_per_pixel", &read("bits_per_pixel")?)?,
            stride: number("stride", &read("stride")?)?,
        };
        if geometry.bits_per_pixel != 32 {
            return Err(format!(
                "{name} has {} bits per pixel; only 32 is supported",
                geometry.bits_per_pixel
            ));
        }
        if geometry.width == 0
            || geometry.height == 0
            || geometry.stride < geometry.width * BYTES_PER_PIXEL
        {
            return Err(format!(
                "{name} has an unusable layout: {}x{}, stride {}",
                geometry.width, geometry.height, geometry.stride
            ));
        }
        Ok(geometry)
    }
}

/// Whether the kernel's framebuffer console is attached (`<sysfs>/class/vtconsole/*`), so it may
/// draw over the screen. `autorun.sh` detaches it on the scanner (LLD 9, section 3).
#[must_use]
pub fn console_bound(sysfs: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(sysfs.join("class/vtconsole")) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let dir = entry.path();
        let name = std::fs::read_to_string(dir.join("name")).unwrap_or_default();
        let bind = std::fs::read_to_string(dir.join("bind")).unwrap_or_default();
        name.contains("frame buffer") && bind.trim() == "1"
    })
}

/// An open framebuffer and what was last written to it.
#[derive(Debug)]
pub struct Framebuffer {
    file: File,
    path: PathBuf,
    geometry: Geometry,
    /// The last screen written, row by row, to find the rows that changed.
    last: Option<Canvas>,
}

impl Framebuffer {
    /// Opens `path` for writing.
    ///
    /// # Errors
    ///
    /// If it can't be opened, for example without the `video` group.
    pub fn open(path: &Path, geometry: Geometry) -> io::Result<Self> {
        let file = OpenOptions::new().write(true).open(path)?;
        Ok(Self {
            file,
            path: path.to_owned(),
            geometry,
            last: None,
        })
    }

    /// The geometry it was opened with.
    #[must_use]
    pub fn geometry(&self) -> Geometry {
        self.geometry
    }

    /// The device path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Writes `canvas`, which must match the geometry's width and height. Only rows that differ
    /// from the last write go out, in runs of consecutive rows; `force` writes them all. Returns
    /// the number of rows written.
    ///
    /// # Errors
    ///
    /// If a write fails. The next write then sends every row again.
    pub fn write(&mut self, canvas: &Canvas, force: bool) -> io::Result<usize> {
        if canvas.width() != self.geometry.width || canvas.height() != self.geometry.height {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the screen doesn't match the framebuffer's size",
            ));
        }
        let previous = if force { None } else { self.last.take() };
        self.last = None;
        let changed = |y: usize| {
            previous
                .as_ref()
                .is_none_or(|last| last.row(y) != canvas.row(y))
        };
        let row_bytes = self.geometry.width * BYTES_PER_PIXEL;
        let mut written = 0;
        let mut y = 0;
        while y < canvas.height() {
            if !changed(y) {
                y += 1;
                continue;
            }
            let start = y;
            while y < canvas.height() && changed(y) {
                y += 1;
            }
            if self.geometry.stride == row_bytes {
                let bytes = &canvas.bytes()[start * row_bytes..y * row_bytes];
                self.file
                    .write_all_at(bytes, offset(start, self.geometry.stride))?;
            } else {
                for row in start..y {
                    self.file
                        .write_all_at(canvas.row(row), offset(row, self.geometry.stride))?;
                }
            }
            written += y - start;
        }
        self.last = Some(canvas.clone());
        Ok(written)
    }
}

fn offset(row: usize, stride: usize) -> u64 {
    u64::try_from(row * stride).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::display::canvas::Color;

    struct Fixture {
        dir: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("helios-fb-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("class/graphics/fb0")).unwrap();
            Self { dir }
        }

        fn geometry(&self, size: &str, bpp: &str, stride: &str) {
            let fb = self.dir.join("class/graphics/fb0");
            std::fs::write(fb.join("virtual_size"), format!("{size}\n")).unwrap();
            std::fs::write(fb.join("bits_per_pixel"), format!("{bpp}\n")).unwrap();
            std::fs::write(fb.join("stride"), format!("{stride}\n")).unwrap();
        }

        fn vtconsole(&self, n: u32, name: &str, bind: &str) {
            let dir = self.dir.join(format!("class/vtconsole/vtcon{n}"));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("name"), name).unwrap();
            std::fs::write(dir.join("bind"), bind).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn reads_the_scanners_geometry() {
        let fixture = Fixture::new("geometry");
        fixture.geometry("800,480", "32", "3200");

        let geometry = Geometry::read(&fixture.dir, Path::new("/dev/fb0")).unwrap();
        assert_eq!(
            geometry,
            Geometry {
                width: 800,
                height: 480,
                bits_per_pixel: 32,
                stride: 3200
            }
        );
    }

    #[test]
    fn refuses_layouts_it_cant_draw() {
        let fixture = Fixture::new("refuse");
        for (size, bpp, stride, expected) in [
            ("800,480", "16", "1600", "bits per pixel"),
            ("800,480", "32", "3000", "unusable layout"),
            ("800x480", "32", "3200", "width,height"),
            ("800,abc", "32", "3200", "isn't a number"),
        ] {
            fixture.geometry(size, bpp, stride);
            let error = Geometry::read(&fixture.dir, Path::new("/dev/fb0")).unwrap_err();
            assert!(error.contains(expected), "{error}");
        }
        let missing = Geometry::read(&fixture.dir, Path::new("/dev/fb7")).unwrap_err();
        assert!(missing.contains("can't read"), "{missing}");
        assert!(Geometry::read(&fixture.dir, Path::new("/")).is_err());
    }

    #[test]
    fn finds_a_bound_framebuffer_console() {
        let fixture = Fixture::new("console");
        assert!(!console_bound(&fixture.dir));
        fixture.vtconsole(0, "(S) dummy device\n", "1\n");
        fixture.vtconsole(1, "(M) frame buffer device\n", "0\n");
        assert!(!console_bound(&fixture.dir));
        fixture.vtconsole(1, "(M) frame buffer device\n", "1\n");
        assert!(console_bound(&fixture.dir));
    }

    fn geometry(stride: usize) -> Geometry {
        Geometry {
            width: 4,
            height: 3,
            bits_per_pixel: 32,
            stride,
        }
    }

    #[test]
    fn writes_only_rows_that_changed() {
        let fixture = Fixture::new("write");
        let path = fixture.dir.join("fb");
        std::fs::write(&path, vec![0u8; 48]).unwrap();
        let mut fb = Framebuffer::open(&path, geometry(16)).unwrap();
        assert_eq!(fb.geometry().stride, 16);
        assert_eq!(fb.path(), path);

        let mut canvas = Canvas::new(4, 3);
        assert_eq!(fb.write(&canvas, false).unwrap(), 3);
        assert_eq!(fb.write(&canvas, false).unwrap(), 0);
        canvas.fill_rect(0, 1, 1, 1, Color::WHITE);
        assert_eq!(fb.write(&canvas, false).unwrap(), 1);
        assert_eq!(fb.write(&canvas, true).unwrap(), 3);

        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(&bytes[16..20], &[255, 255, 255, 255]);
        assert_eq!(&bytes[0..4], &[0, 0, 0, 255]);
    }

    #[test]
    fn writes_rows_with_padding() {
        let fixture = Fixture::new("padding");
        let path = fixture.dir.join("fb");
        std::fs::write(&path, vec![9u8; 60]).unwrap();
        let mut fb = Framebuffer::open(&path, geometry(20)).unwrap();

        let mut canvas = Canvas::new(4, 3);
        canvas.fill_rect(0, 2, 4, 1, Color::WHITE);
        fb.write(&canvas, false).unwrap();

        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(&bytes[16..20], &[9, 9, 9, 9], "padding untouched");
        assert_eq!(&bytes[40..44], &[255, 255, 255, 255]);
    }

    #[test]
    fn refuses_a_screen_of_the_wrong_size() {
        let fixture = Fixture::new("size");
        let path = fixture.dir.join("fb");
        std::fs::write(&path, vec![0u8; 48]).unwrap();
        let mut fb = Framebuffer::open(&path, geometry(16)).unwrap();

        let error = fb.write(&Canvas::new(5, 3), false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(Framebuffer::open(&fixture.dir.join("missing/fb"), geometry(16)).is_err());
    }
}
