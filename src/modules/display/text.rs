//! Text (LLD 9, section 5): Noto Sans Regular and Bold, subset to Latin and compiled in
//! (`assets/fonts`), rasterized with `fontdue`, anti-aliased by blending each glyph's coverage
//! over the canvas. Glyphs are cached per character, weight and size.

use std::collections::HashMap;

use fontdue::{Font, FontSettings, Metrics};

use super::canvas::{Canvas, Color};

static REGULAR: &[u8] = include_bytes!("../../../assets/fonts/NotoSans-Regular-subset.ttf");
static BOLD: &[u8] = include_bytes!("../../../assets/fonts/NotoSans-Bold-subset.ttf");

/// Appended to text cut off at the end of its last line.
const ELLIPSIS: char = '…';

/// The font weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Weight {
    /// Regular.
    Regular,
    /// Bold.
    Bold,
}

/// Horizontal alignment within a box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    /// Flush left.
    Left,
    /// Centred.
    Center,
    /// Flush right.
    Right,
}

/// How to draw a piece of text.
#[derive(Debug, Clone, Copy)]
pub struct Style {
    /// The size in pixels (the font's em size).
    pub size: f32,
    /// The weight.
    pub weight: Weight,
    /// The colour.
    pub color: Color,
    /// The alignment within the box.
    pub align: Align,
    /// At most this many lines; the last is cut off with "…" if the text doesn't fit.
    pub max_lines: usize,
}

/// A text box: the left edge, the top, and the width to wrap at.
#[derive(Debug, Clone, Copy)]
pub struct TextBox {
    /// The left edge.
    pub x: i64,
    /// The top of the first line.
    pub y: i64,
    /// The width to wrap at.
    pub width: f32,
}

/// The fonts and their glyph cache.
pub struct Fonts {
    regular: Font,
    bold: Font,
    glyphs: HashMap<(char, Weight, u32), (Metrics, Vec<u8>)>,
}

impl std::fmt::Debug for Fonts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fonts")
            .field("cached_glyphs", &self.glyphs.len())
            .finish_non_exhaustive()
    }
}

impl Fonts {
    /// Loads the compiled-in fonts.
    ///
    /// # Errors
    ///
    /// If a font can't be parsed, which only happens if the files in `assets/fonts` are broken.
    pub fn load() -> Result<Self, String> {
        let load = |bytes: &'static [u8], name: &str| {
            Font::from_bytes(bytes, FontSettings::default())
                .map_err(|error| format!("can't load {name}: {error}"))
        };
        Ok(Self {
            regular: load(REGULAR, "Noto Sans Regular")?,
            bold: load(BOLD, "Noto Sans Bold")?,
            glyphs: HashMap::new(),
        })
    }

    fn font(&self, weight: Weight) -> &Font {
        match weight {
            Weight::Regular => &self.regular,
            Weight::Bold => &self.bold,
        }
    }

    /// The height of a line of text at `size`.
    #[must_use]
    pub fn line_height(&self, size: f32, weight: Weight) -> f32 {
        self.font(weight)
            .horizontal_line_metrics(size)
            .map_or(size * 1.4, |metrics| metrics.new_line_size)
    }

    fn ascent(&self, size: f32, weight: Weight) -> f32 {
        self.font(weight)
            .horizontal_line_metrics(size)
            .map_or(size, |metrics| metrics.ascent)
    }

    /// The width of `text` on one line at `size`.
    #[must_use]
    pub fn width(&self, text: &str, size: f32, weight: Weight) -> f32 {
        let font = self.font(weight);
        let mut width = 0.0;
        let mut previous = None;
        for c in text.chars() {
            if let Some(p) = previous {
                width += font.horizontal_kern(p, c, size).unwrap_or(0.0);
            }
            width += font.metrics(c, size).advance_width;
            previous = Some(c);
        }
        width
    }

    /// Splits `text` into lines that fit `width`, at most `max_lines`, the last cut off with
    /// "…" if there's more. Breaks at spaces and at explicit line breaks; a word longer than a
    /// line is broken anywhere.
    #[must_use]
    pub fn wrap(&self, text: &str, width: f32, style: &Style) -> Vec<String> {
        let (size, weight) = (style.size, style.weight);
        let mut lines: Vec<String> = Vec::new();
        let mut cut = false;
        'paragraphs: for paragraph in text.split('\n') {
            let mut line = String::new();
            for word in paragraph.split(' ').filter(|word| !word.is_empty()) {
                let candidate = if line.is_empty() {
                    word.to_owned()
                } else {
                    format!("{line} {word}")
                };
                if self.width(&candidate, size, weight) <= width {
                    line = candidate;
                    continue;
                }
                if !line.is_empty() {
                    lines.push(std::mem::take(&mut line));
                    if lines.len() >= style.max_lines {
                        cut = true;
                        break 'paragraphs;
                    }
                }
                // Break a word that's too long for a line of its own.
                for c in word.chars() {
                    let mut longer = line.clone();
                    longer.push(c);
                    if !line.is_empty() && self.width(&longer, size, weight) > width {
                        lines.push(std::mem::take(&mut line));
                        if lines.len() >= style.max_lines {
                            cut = true;
                            break 'paragraphs;
                        }
                        longer = c.to_string();
                    }
                    line = longer;
                }
            }
            lines.push(line);
            if lines.len() >= style.max_lines {
                break;
            }
        }
        let used: usize = lines.iter().map(|line| line.chars().count()).sum();
        let total = text.chars().filter(|c| !c.is_whitespace()).count();
        let shown = lines
            .iter()
            .map(|line| line.chars().filter(|c| !c.is_whitespace()).count())
            .sum::<usize>();
        if (cut || shown < total)
            && used > 0
            && let Some(last) = lines.last_mut()
        {
            *last = self.with_ellipsis(last, width, style);
        }
        lines
    }

    /// `line` shortened until it fits `width` with "…" after it.
    fn with_ellipsis(&self, line: &str, width: f32, style: &Style) -> String {
        let mut text: String = line.trim_end().to_owned();
        loop {
            let candidate = format!("{text}{ELLIPSIS}");
            if text.is_empty() || self.width(&candidate, style.size, style.weight) <= width {
                return candidate;
            }
            text.pop();
            text = text.trim_end().to_owned();
        }
    }

    /// Draws `text` in `area`, wrapped and aligned. Returns the height used.
    pub fn draw(&mut self, canvas: &mut Canvas, text: &str, area: TextBox, style: &Style) -> f32 {
        let lines = self.wrap(text, area.width, style);
        let line_height = self.line_height(style.size, style.weight);
        let ascent = self.ascent(style.size, style.weight);
        for (n, line) in lines.iter().enumerate() {
            let width = self.width(line, style.size, style.weight);
            let left = match style.align {
                Align::Left => 0.0,
                Align::Center => (area.width - width) / 2.0,
                Align::Right => area.width - width,
            };
            let baseline = area.y as f32 + ascent + line_height * n as f32;
            self.draw_line(canvas, line, area.x as f32 + left, baseline, style);
        }
        line_height * lines.len() as f32
    }

    fn draw_line(&mut self, canvas: &mut Canvas, line: &str, x: f32, baseline: f32, style: &Style) {
        let mut pen = x;
        let mut previous = None;
        for c in line.chars() {
            if let Some(p) = previous {
                pen += self
                    .font(style.weight)
                    .horizontal_kern(p, c, style.size)
                    .unwrap_or(0.0);
            }
            let key = (c, style.weight, style.size.to_bits());
            let font = match style.weight {
                Weight::Regular => &self.regular,
                Weight::Bold => &self.bold,
            };
            let (metrics, bitmap) = self
                .glyphs
                .entry(key)
                .or_insert_with(|| font.rasterize(c, style.size));
            let left = (pen + metrics.xmin as f32).round() as i64;
            let top = (baseline - metrics.ymin as f32 - metrics.height as f32).round() as i64;
            for row in 0..metrics.height {
                for col in 0..metrics.width {
                    let coverage = bitmap[row * metrics.width + col];
                    canvas.blend(left + col as i64, top + row as i64, style.color, coverage);
                }
            }
            pen += metrics.advance_width;
            previous = Some(c);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn style(max_lines: usize) -> Style {
        Style {
            size: 20.0,
            weight: Weight::Regular,
            color: Color::WHITE,
            align: Align::Left,
            max_lines,
        }
    }

    #[test]
    fn measures_text() {
        let fonts = Fonts::load().unwrap();

        let short = fonts.width("Hi", 20.0, Weight::Regular);
        let long = fonts.width("Hello, world", 20.0, Weight::Regular);
        assert!(short > 10.0 && long > short * 3.0, "{short} {long}");
        assert!(
            fonts.width("Hello", 20.0, Weight::Bold) > fonts.width("Hello", 20.0, Weight::Regular)
        );
        assert!(fonts.line_height(20.0, Weight::Regular) > 20.0);
        assert!(format!("{fonts:?}").starts_with("Fonts"));
    }

    #[test]
    fn wraps_at_spaces_and_cuts_off_with_an_ellipsis() {
        let fonts = Fonts::load().unwrap();
        let width = fonts.width("the quick brown", 20.0, Weight::Regular) + 1.0;

        let lines = fonts.wrap(
            "the quick brown fox jumps over the lazy dog",
            width,
            &style(5),
        );
        assert_eq!(lines, ["the quick brown", "fox jumps over", "the lazy dog"]);

        let cut = fonts.wrap(
            "the quick brown fox jumps over the lazy dog",
            width,
            &style(2),
        );
        assert_eq!(cut.len(), 2);
        assert!(cut[1].ends_with('…'), "{cut:?}");
        assert!(fonts.width(&cut[1], 20.0, Weight::Regular) <= width);
    }

    #[test]
    fn keeps_line_breaks_and_breaks_long_words() {
        let fonts = Fonts::load().unwrap();
        let width = fonts.width("abcdef", 20.0, Weight::Regular) + 1.0;

        assert_eq!(fonts.wrap("ab\ncd", width, &style(5)), ["ab", "cd"]);
        let broken = fonts.wrap("abcdefghijkl", width, &style(5));
        assert_eq!(broken.concat(), "abcdefghijkl");
        assert!(broken.len() >= 2);
        let cut = fonts.wrap("abcdefghijklmnopqrstuvwxyz", width, &style(1));
        assert_eq!(cut.len(), 1);
        assert!(cut[0].ends_with('…'));
        assert!(
            fonts
                .wrap("", width, &style(1))
                .iter()
                .all(String::is_empty)
        );
    }

    #[test]
    fn draws_text_in_its_box() {
        let mut fonts = Fonts::load().unwrap();
        let mut canvas = Canvas::new(200, 60);
        let area = TextBox {
            x: 10,
            y: 10,
            width: 180.0,
        };

        let height = fonts.draw(&mut canvas, "Helios", area, &style(1));
        assert!(height > 20.0);
        let lit = |x0: usize, x1: usize| {
            (0..60).any(|y| (x0..x1).any(|x| canvas.pixel(x, y) != Color::BLACK))
        };
        assert!(lit(10, 80));
        assert!(!lit(0, 9));
        assert!(!lit(120, 200));

        let mut centred = Canvas::new(200, 60);
        let mut s = style(1);
        s.align = Align::Center;
        fonts.draw(&mut centred, "Hi", area, &s);
        assert!((0..60).any(|y| (95..110).any(|x| centred.pixel(x, y) != Color::BLACK)));
        s.align = Align::Right;
        s.weight = Weight::Bold;
        let mut right = Canvas::new(200, 60);
        fonts.draw(&mut right, "Hi", area, &s);
        assert!((0..60).any(|y| (170..190).any(|x| right.pixel(x, y) != Color::BLACK)));
    }
}
