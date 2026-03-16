# forenzik

Python CTF forensics + steganography toolkit. Built to cover the most common challenge types fast, without hunting for tools mid-competition.

> **Note:** The original Bash version of forenzik has been deprecated. The tool is now Python-only.

## Requirements

No manual setup. On first run, forenzik creates a virtual environment and installs its Python dependencies automatically:

```
python3 forenzik.py
```

## Optional external tools

The following tools are optional. forenzik skips them gracefully at runtime if they aren't installed:

| Tool | Install |
|---|---|
| `steghide` | `sudo apt install steghide` |
| `foremost` | `sudo apt install foremost` |

Everything else (`file`, `strings`, `exif`, `pngcheck`, `binwalk`, `lsb`, `zsteg`, `stegdetect`, `entropy`, `xor`, `audio`, `planes`) is pure Python — no system dependencies needed.

## Installation

```
git clone https://github.com/hungry-bogart/forenzik.git
cd forenzik
python3 forenzik.py
```

Run it from the directory containing the file you want to analyze, or pass the file path as an argument.

## Usage

**Interactive mode:**
```
python3 forenzik.py
```
Select your file from the picker, then choose tools from the menu. `Run All` runs everything in sequence.

**Non-interactive:**
```
python3 forenzik.py image.png --all
python3 forenzik.py image.png -t exif -t lsb -t zsteg
python3 forenzik.py image.png -t pngcheck -o /tmp/results
```

Results are saved to a timestamped `forenzik_results_<timestamp>/` directory.

## Tools

| Tool | What it does |
|---|---|
| `file` | Magic-byte file type detection |
| `strings` | ASCII + UTF-16LE strings with hex offsets; inline base64 decoding |
| `hexdump` | Hex + ASCII dump of first 512 bytes |
| `exif` | EXIF / XMP / PIL image metadata |
| `pngcheck` | PNG chunk validation; decodes tEXt, zTXt, iTXt; hex-dumps trailing data after IEND |
| `binwalk` | Embedded file signature scan; extracts ZIPs and gzip payloads |
| `lsb` | LSB channel distribution stats + 8-method text extraction (RGB/RGBA seq, per-channel, BGR, column-order) |
| `zsteg` | Multi-plane bit extraction — tests all channel combos × bit planes 0-3 × MSB/LSB-first; ranks by printability |
| `planes` | Saves all 24 bit-plane images (R/G/B × bits 0-7) to results dir for visual inspection |
| `stegdetect` | Statistical steganalysis: chi-square pair test (Westfeld & Pfitzmann) + simplified RS analysis |
| `entropy` | Shannon entropy per-file + sliding window ASCII heatmap; flags low-entropy pockets |
| `xor` | Single-byte XOR brute-force (all 256 keys); repeating-key detection via Hamming distance + per-position key solving |
| `audio` | WAV LSB extraction from audio samples; raw string scan on file bytes |
| `steghide` | Probe for steghide-embedded data (empty passphrase) |
| `foremost` | File carving — recovers files from raw data |
| **Run All** | Runs all of the above in sequence |

## Workflow

A typical CTF forensics challenge:

1. **`file`** — confirm what the file actually is
2. **`strings` + `hexdump`** — quick scan for obvious flags, readable metadata
3. **`exif`** — metadata often holds the flag outright
4. **`pngcheck`** — check PNG text chunks and trailing data (very common CTF technique)
5. **`binwalk`** — extract embedded files
6. **`stegdetect`** — confirm whether steganography is statistically present before spending time on it
7. **`lsb` + `zsteg`** — try all common LSB embedding schemes
8. **`planes`** — visual bit-plane inspection for hidden images/patterns
9. **`entropy`** — find unusual regions in the file
10. **`xor`** — try XOR decoding if data looks encoded
11. **`audio`** — if it's a WAV or audio-adjacent file
12. **`steghide` + `foremost`** — external carving tools

Brought to you by Coney Island Arcade.
