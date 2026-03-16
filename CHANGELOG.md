# Changelog

All notable changes to forenzik are documented here.

---

## [Unreleased]

---

## [0.3.0] - 2026-03-15

### Added

- **`zsteg`** — pure Python multi-plane bit extraction. Tests all channel combinations
  (R, G, B, A, RG, RB, GB, RGB, RGBA) × bit planes 0-3 × MSB-first/LSB-first bit ordering.
  Ranks every combination by printability score and surfaces flag matches immediately.
  Covers the same attack surface as the zsteg Ruby gem, no gem install required.

- **`planes`** — extracts all 24 bit-plane images (R/G/B channels × bits 0-7) and saves
  them as PNG files to the results directory. Essential for visually detecting hidden images
  or patterns embedded in specific bit planes.

- **`stegdetect`** — statistical steganalysis using two methods:
  - *Chi-square attack* (Westfeld & Pfitzmann 1999): measures how evenly color-value pairs
    (2k, 2k+1) are distributed per channel. High p-value → equalized pairs → suspicious.
  - *RS analysis* (simplified): compares group smoothness before and after LSB flip.
    |d| near 0 → Rm ≈ R-1 and Sm ≈ S-1 → suspicious. Useful for confirming stego presence
    before spending time on extraction attempts.

- **`entropy`** — Shannon entropy analysis with a sliding window ASCII heatmap. Reports
  overall entropy with an interpretation, then shows entropy per window with a bar chart.
  Flags low-entropy pockets (potential plaintext regions) with their ASCII preview.

- **`xor`** — two-stage XOR analysis:
  1. Single-byte brute-force over all 256 keys, ranked by printability + flag detection.
  2. Repeating-key detection: estimates likely key lengths via normalized Hamming distance
     (Cryptopals method), then solves each position independently by frequency scoring.
     Handles key lengths 2-32.

- **`audio`** — WAV/audio steganography analysis: parses WAV headers via stdlib `wave`,
  extracts LSB stream from audio samples (8-bit and 16-bit), and scans raw file bytes
  for printable strings. Falls back to raw byte LSB analysis for non-WAV files.

- **`hexdump`** — hex + ASCII dump of the first 512 bytes. Classic forensics baseline.

- **`strings`** now also detects UTF-16LE wide strings and attempts inline base64 decoding
  for any matched base64 candidates, printing the decoded value next to the string.

- **`exif`** now supplements exifread output with PIL image properties (mode, size, format,
  frame count) and the full `img.info` dict, which includes embedded metadata not captured
  by EXIF alone.

- **`pngcheck`** improvements:
  - `iTXt` chunks fully decoded (keyword, compression flag, language, text content).
  - CRC mismatch values now shown with `0x` prefix for clarity.
  - Trailing data after `IEND` is hex-dumped inline (first 256 bytes) rather than just counted.
  - IDAT summary (chunk count + total compressed bytes) appended at end.
  - Warning emitted when no `IEND` chunk is found.

- **`lsb`** improvements:
  - Text extraction replaced bare-dot substitution with a printability-scored approach:
    shows clean text when ratio is high, labels partial/binary output honestly.
  - Added BGR channel-order scan and column-order pixel scan as additional extraction methods
    (8 total methods, up from 4).
  - Reports original image mode before RGBA conversion so alpha-channel results are
    correctly interpreted.

- Results directory renamed from `stego_results_<timestamp>` to `forenzik_results_<timestamp>`.

### Fixed

- **All bare `except Exception` handlers** replaced with typed exception handling.
  Specific exception types (`zlib.error`, `zipfile.BadZipFile`, `gzip.BadGzipFile`,
  `wave.Error`, `FileNotFoundError`, `subprocess.TimeoutExpired`) are caught explicitly;
  fallthrough `except Exception as e` preserves `type(e).__name__` in all error messages.

- **File picker** now loops on invalid input instead of returning `None` and exiting.
  Bad selection or non-existent manual path prompts again. Added `q` / `quit` to exit
  the picker intentionally.

- **Terminal width guard** updated to `max(40, min(console.width, 84))` — prevents
  negative-width tables on very narrow terminals.

- README rewritten to reflect the actual tool set. Removed references to `zsteg` (gem),
  `stegseek`, `mat2`, and `rockyou.txt`, which are not part of the current tool.

---

## [0.2.0] - 2026-03-15

### Added
- LSB steganography analyzer — pure Python, Pillow-based. Four extraction methods.
- Click CLI: `FILE` argument, `--all`, `--tool`, `--output`, `-h`/`--help`.
- Pillow added to requirements.

### Changed
- `binwalk` pip package removed — replaced with pure Python signature scanner.
- `zsteg` and `stegseek` removed from menu.
- `mat2` removed.
- venv auto-sync: pip install runs on every out-of-venv launch.

### Fixed
- Dependency check no longer blocks startup on missing optional tools.
- Extracted files now land in the timestamped results folder.
- Rich panel layout issues inside `console.pager()`.
- Panel/table widths capped at terminal width.

---

## [0.1.0] - 2026-03-15

### Changed
- Full rewrite from Bash to Python.
- `gum` dependency removed — all UI via `rich`.
- Auto-venv setup on first run.
- File picker via numbered Rich table.
- Flag pattern detection with inline highlighting and summary panel.
- All output saved to timestamped directory.
- `exiftool`, `file`, `strings`, `pngcheck` replaced with pure Python implementations.

---

## [0.0.1] - Original Bash version

- Bash script wrapping: `file`, `strings`, `exiftool`, `binwalk`, `pngcheck`, `mat2`, `aperisolve`.
- Interactive menu via `gum choose`, file picker via `gum file`.
- Timestamped output directory per session.
