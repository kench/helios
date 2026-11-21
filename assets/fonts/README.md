# Fonts

Noto Sans Regular and Bold, subset for the display module (LLD 9, section 5). Licensed under the
SIL Open Font License 1.1 (`OFL.txt`), which allows modified versions such as these subsets to be
bundled with software. The subsets keep the name "Noto Sans"; the OFL reserves no font names for
Noto.

Source (2026-11-21): `https://github.com/notofonts/notofonts.github.io/raw/main/fonts/NotoSans/hinted/ttf/`

| File | SHA-256 |
| --- | --- |
| `NotoSans-Regular.ttf` (original) | `478c558ea716033cd60c03438f628dfa75694dcf6b5f6d505a2f05fd2b4f3823` |
| `NotoSans-Bold.ttf` (original) | `1df075a380fc7cb898acf64c1f7b3b4dd780de3caa860178bf929de35817a913` |
| `NotoSans-Regular-subset.ttf` | `411c131701b484274b09666d169586a91f74abaa5aec8384864e7ddafc68ca28` |
| `NotoSans-Bold-subset.ttf` | `633aa0eddbfdc6d2767fcf59d00a3fc45c8404734f56240062084b659f4c62ce` |

Made with fonttools 4.55.3:

```sh
pyftsubset NotoSans-Regular.ttf --output-file=NotoSans-Regular-subset.ttf \
  --unicodes="U+0020-007E,U+00A0-00FF,U+0100-017F,U+2010-2027,U+2030-203A,U+20AC,U+2122" \
  --no-hinting --layout-features='kern' --name-IDs='*' --notdef-outline
```

and the same for `NotoSans-Bold.ttf`. That covers ASCII, Latin-1, Latin Extended-A, general
punctuation (including the ellipsis and bullet), the euro and trade mark signs. Other characters
are drawn as the font's missing-glyph box.
