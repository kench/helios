//! An in-memory screen in the framebuffer's pixel format (LLD 9, section 4): 32 bits per pixel,
//! bytes in B, G, R, A order, rows packed with no padding. Shapes are drawn with anti-aliased
//! edges where it matters (circles, thick lines), by blending a coverage value over what's there.

/// A colour, opaque.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Color {
    /// Red.
    pub r: u8,
    /// Green.
    pub g: u8,
    /// Blue.
    pub b: u8,
}

impl Color {
    /// A colour from its red, green and blue parts.
    #[must_use]
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    /// Black.
    pub const BLACK: Self = Self::rgb(0, 0, 0);
    /// White.
    pub const WHITE: Self = Self::rgb(255, 255, 255);
}

/// Bytes per pixel.
pub const BYTES_PER_PIXEL: usize = 4;

/// A screen's worth of pixels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canvas {
    width: usize,
    height: usize,
    pixels: Vec<u8>,
}

impl Canvas {
    /// A black canvas of `width` × `height` pixels.
    #[must_use]
    pub fn new(width: usize, height: usize) -> Self {
        let mut canvas = Self {
            width,
            height,
            pixels: vec![0; width * height * BYTES_PER_PIXEL],
        };
        canvas.clear(Color::BLACK);
        canvas
    }

    /// The width in pixels.
    #[must_use]
    pub fn width(&self) -> usize {
        self.width
    }

    /// The height in pixels.
    #[must_use]
    pub fn height(&self) -> usize {
        self.height
    }

    /// The pixels, row by row, B, G, R, A.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.pixels
    }

    /// One row of pixels.
    #[must_use]
    pub fn row(&self, y: usize) -> &[u8] {
        let len = self.width * BYTES_PER_PIXEL;
        &self.pixels[y * len..(y + 1) * len]
    }

    /// The colour at (`x`, `y`), for tests and checks.
    #[must_use]
    pub fn pixel(&self, x: usize, y: usize) -> Color {
        let i = (y * self.width + x) * BYTES_PER_PIXEL;
        Color::rgb(self.pixels[i + 2], self.pixels[i + 1], self.pixels[i])
    }

    /// Fills the whole canvas.
    pub fn clear(&mut self, color: Color) {
        for pixel in self.pixels.as_chunks_mut::<BYTES_PER_PIXEL>().0 {
            *pixel = [color.b, color.g, color.r, 0xff];
        }
    }

    /// Blends `color` over the pixel at (`x`, `y`) with `coverage` (0 = none, 255 = full).
    /// Points outside the canvas are ignored.
    pub fn blend(&mut self, x: i64, y: i64, color: Color, coverage: u8) {
        if coverage == 0 || x < 0 || y < 0 {
            return;
        }
        let (Ok(x), Ok(y)) = (usize::try_from(x), usize::try_from(y)) else {
            return;
        };
        if x >= self.width || y >= self.height {
            return;
        }
        let i = (y * self.width + x) * BYTES_PER_PIXEL;
        let a = u32::from(coverage);
        let mix = |old: u8, new: u8| {
            let mixed = (u32::from(new) * a + u32::from(old) * (255 - a) + 127) / 255;
            u8::try_from(mixed).unwrap_or(u8::MAX)
        };
        self.pixels[i] = mix(self.pixels[i], color.b);
        self.pixels[i + 1] = mix(self.pixels[i + 1], color.g);
        self.pixels[i + 2] = mix(self.pixels[i + 2], color.r);
        self.pixels[i + 3] = 0xff;
    }

    /// Fills the rectangle at (`x`, `y`) of `width` × `height`, clipped to the canvas.
    pub fn fill_rect(&mut self, x: i64, y: i64, width: i64, height: i64, color: Color) {
        let (x0, x1) = clip(x, width, self.width);
        let (y0, y1) = clip(y, height, self.height);
        for row in y0..y1 {
            for col in x0..x1 {
                let i = (row * self.width + col) * BYTES_PER_PIXEL;
                self.pixels[i..i + BYTES_PER_PIXEL]
                    .copy_from_slice(&[color.b, color.g, color.r, 0xff]);
            }
        }
    }

    /// Fills a rectangle with corners rounded to `radius`.
    pub fn fill_rounded_rect(
        &mut self,
        x: i64,
        y: i64,
        width: i64,
        height: i64,
        radius: i64,
        color: Color,
    ) {
        let radius = radius.clamp(0, width.min(height) / 2);
        self.fill_rect(x + radius, y, width - 2 * radius, height, color);
        self.fill_rect(x, y + radius, radius, height - 2 * radius, color);
        self.fill_rect(
            x + width - radius,
            y + radius,
            radius,
            height - 2 * radius,
            color,
        );
        let r = radius as f64;
        for (cx, cy, dx0, dy0) in [
            (x + radius, y + radius, -radius, -radius),
            (x + width - radius, y + radius, 0, -radius),
            (x + radius, y + height - radius, -radius, 0),
            (x + width - radius, y + height - radius, 0, 0),
        ] {
            for dy in dy0..dy0 + radius {
                for dx in dx0..dx0 + radius {
                    let px = dx as f64 + 0.5;
                    let py = dy as f64 + 0.5;
                    let coverage = edge_coverage(r - (px * px + py * py).sqrt());
                    self.blend(cx + dx, cy + dy, color, coverage);
                }
            }
        }
    }

    /// Fills a circle centred on (`cx`, `cy`).
    pub fn fill_circle(&mut self, cx: f64, cy: f64, radius: f64, color: Color) {
        let x0 = (cx - radius).floor() as i64 - 1;
        let x1 = (cx + radius).ceil() as i64 + 1;
        let y0 = (cy - radius).floor() as i64 - 1;
        let y1 = (cy + radius).ceil() as i64 + 1;
        for y in y0..=y1 {
            for x in x0..=x1 {
                let dx = x as f64 + 0.5 - cx;
                let dy = y as f64 + 0.5 - cy;
                let coverage = edge_coverage(radius - (dx * dx + dy * dy).sqrt());
                self.blend(x, y, color, coverage);
            }
        }
    }

    /// Draws a line `thickness` wide with round ends, from (`x0`, `y0`) to (`x1`, `y1`).
    pub fn line(&mut self, from: (f64, f64), to: (f64, f64), thickness: f64, color: Color) {
        let half = thickness / 2.0;
        let (x0, y0) = from;
        let (x1, y1) = to;
        let left = (x0.min(x1) - half).floor() as i64 - 1;
        let right = (x0.max(x1) + half).ceil() as i64 + 1;
        let top = (y0.min(y1) - half).floor() as i64 - 1;
        let bottom = (y0.max(y1) + half).ceil() as i64 + 1;
        let (dx, dy) = (x1 - x0, y1 - y0);
        let length_sq = dx * dx + dy * dy;
        for y in top..=bottom {
            for x in left..=right {
                let (px, py) = (x as f64 + 0.5, y as f64 + 0.5);
                let t = if length_sq == 0.0 {
                    0.0
                } else {
                    (((px - x0) * dx + (py - y0) * dy) / length_sq).clamp(0.0, 1.0)
                };
                let (nx, ny) = (x0 + t * dx - px, y0 + t * dy - py);
                let coverage = edge_coverage(half - (nx * nx + ny * ny).sqrt());
                self.blend(x, y, color, coverage);
            }
        }
    }

    /// Fills the triangle with corners `a`, `b` and `c`, with anti-aliased edges.
    pub fn fill_triangle(&mut self, a: (f64, f64), b: (f64, f64), c: (f64, f64), color: Color) {
        let left = a.0.min(b.0).min(c.0).floor() as i64 - 1;
        let right = a.0.max(b.0).max(c.0).ceil() as i64 + 1;
        let top = a.1.min(b.1).min(c.1).floor() as i64 - 1;
        let bottom = a.1.max(b.1).max(c.1).ceil() as i64 + 1;
        let edges = [(a, b), (b, c), (c, a)];
        // Positive inside for either winding.
        let sign = if cross(a, b, c) < 0.0 { -1.0 } else { 1.0 };
        for y in top..=bottom {
            for x in left..=right {
                let p = (x as f64 + 0.5, y as f64 + 0.5);
                let inside = edges
                    .iter()
                    .map(|&(e0, e1)| {
                        let length = ((e1.0 - e0.0).powi(2) + (e1.1 - e0.1).powi(2)).sqrt();
                        sign * cross(e0, e1, p) / length.max(f64::EPSILON)
                    })
                    .fold(f64::INFINITY, f64::min);
                self.blend(x, y, color, edge_coverage(inside));
            }
        }
    }
}

/// The 2D cross product of `b - a` and `p - a`.
fn cross(a: (f64, f64), b: (f64, f64), p: (f64, f64)) -> f64 {
    (b.0 - a.0) * (p.1 - a.1) - (b.1 - a.1) * (p.0 - a.0)
}

/// Coverage from the signed distance to a shape's edge (positive inside): full one pixel in,
/// none half a pixel out.
fn edge_coverage(distance: f64) -> u8 {
    let coverage = (distance + 0.5).clamp(0.0, 1.0);
    (coverage * 255.0).round() as u8
}

/// The part of `start..start + len` inside `0..limit`.
fn clip(start: i64, len: i64, limit: usize) -> (usize, usize) {
    let limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let from = start.clamp(0, limit);
    let to = start.saturating_add(len.max(0)).clamp(0, limit);
    (
        usize::try_from(from).unwrap_or(0),
        usize::try_from(to).unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const RED: Color = Color::rgb(255, 0, 0);

    #[test]
    fn stores_pixels_as_bgra() {
        let mut canvas = Canvas::new(2, 1);
        canvas.fill_rect(0, 0, 1, 1, Color::rgb(1, 2, 3));

        assert_eq!(&canvas.bytes()[..8], &[3, 2, 1, 255, 0, 0, 0, 255]);
        assert_eq!(canvas.pixel(0, 0), Color::rgb(1, 2, 3));
        assert_eq!(canvas.row(0).len(), 8);
        assert_eq!((canvas.width(), canvas.height()), (2, 1));
    }

    #[test]
    fn clips_rectangles() {
        let mut canvas = Canvas::new(4, 4);
        canvas.fill_rect(-2, -2, 4, 4, RED);
        canvas.fill_rect(3, 3, 10, 10, RED);
        canvas.fill_rect(1, 1, -5, 2, Color::WHITE);

        assert_eq!(canvas.pixel(1, 1), RED);
        assert_eq!(canvas.pixel(2, 2), Color::BLACK);
        assert_eq!(canvas.pixel(3, 3), RED);
    }

    #[test]
    fn blends_partial_coverage_and_ignores_points_outside() {
        let mut canvas = Canvas::new(2, 2);
        canvas.blend(0, 0, Color::WHITE, 128);
        canvas.blend(-1, 0, Color::WHITE, 255);
        canvas.blend(5, 5, Color::WHITE, 255);
        canvas.blend(1, 1, Color::WHITE, 0);

        assert_eq!(canvas.pixel(0, 0), Color::rgb(128, 128, 128));
        assert_eq!(canvas.pixel(1, 1), Color::BLACK);
    }

    #[test]
    fn draws_shapes_inside_their_bounds() {
        let mut canvas = Canvas::new(40, 40);
        canvas.fill_circle(10.0, 10.0, 5.0, RED);
        canvas.line((20.0, 20.0), (35.0, 35.0), 3.0, Color::WHITE);
        canvas.line((5.0, 35.0), (5.0, 35.0), 2.0, Color::WHITE);
        canvas.fill_triangle((20.0, 2.0), (38.0, 2.0), (29.0, 15.0), RED);
        canvas.fill_rounded_rect(2, 20, 12, 12, 4, Color::WHITE);

        assert_eq!(canvas.pixel(10, 10), RED);
        assert_eq!(canvas.pixel(0, 0), Color::BLACK);
        assert_eq!(canvas.pixel(27, 27), Color::WHITE);
        assert_eq!(canvas.pixel(29, 5), RED);
        assert_eq!(canvas.pixel(8, 26), Color::WHITE);
        // The rounded corner leaves the very corner pixel dark.
        assert_eq!(canvas.pixel(2, 20), Color::BLACK);
        assert_ne!(canvas.pixel(5, 35), Color::BLACK);
    }
}
