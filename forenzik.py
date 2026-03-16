#!/usr/bin/env python3

import base64
import gzip
import io
import math
import os
import re
import struct
import subprocess
import sys
import wave
import zipfile
import zlib
from pathlib import Path


def ensure_venv():
    """If not already running inside a venv, create one, install deps, and re-exec."""
    in_venv = sys.prefix != sys.base_prefix
    if in_venv:
        return

    venv_dir = Path(__file__).parent / ".venv"
    pip = venv_dir / "bin" / "pip"
    python = venv_dir / "bin" / "python"
    req = Path(__file__).parent / "requirements.txt"

    if not venv_dir.exists():
        print("Setting up virtual environment...")
        subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
        print("Done.\n")

    subprocess.run([str(pip), "install", "-r", str(req), "-q"], check=True)
    os.execv(str(python), [str(python)] + sys.argv)


ensure_venv()

import shutil
from datetime import datetime

import click
import exifread
from PIL import Image

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

console = Console()

BANNER_FILE = Path(__file__).parent / "banner.txt"
FLAG_RE = re.compile(r'[A-Za-z0-9_]{2,10}\{[^\x00-\x1f\x7f-\xff{}\n<>|~]{1,100}\}')
B64_RE  = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

PNG_COLOR_TYPES = {0: "Grayscale", 2: "RGB", 3: "Indexed", 4: "Grayscale+Alpha", 6: "RGBA"}


def _get_pixels(img: Image.Image) -> list[tuple]:
    """Return pixel data as a list of per-pixel tuples without using the
    deprecated Image.getdata(). Uses tobytes() + zip chunking instead."""
    n = len(img.mode)
    raw = img.tobytes()
    return list(zip(*[iter(raw)] * n))

MAGIC_SIGS = [
    (b'\xff\xd8\xff',           "JPEG image data"),
    (b'\x89PNG\r\n\x1a\n',     "PNG image data"),
    (b'GIF87a',                 "GIF image data, version 87a"),
    (b'GIF89a',                 "GIF image data, version 89a"),
    (b'BM',                     "BMP image data"),
    (b'II\x2a\x00',            "TIFF image data (little-endian)"),
    (b'MM\x00\x2a',            "TIFF image data (big-endian)"),
    (b'RIFF',                   "RIFF container (WAV/AVI)"),
    (b'%PDF',                   "PDF document"),
    (b'PK\x03\x04',            "ZIP archive"),
    (b'PK\x05\x06',            "ZIP archive (empty)"),
    (b'Rar!\x1a\x07\x00',      "RAR archive v4"),
    (b'Rar!\x1a\x07\x01\x00',  "RAR archive v5"),
    (b'7z\xbc\xaf\x27\x1c',   "7-Zip archive"),
    (b'\x1f\x8b',              "gzip compressed data"),
    (b'BZh',                   "bzip2 compressed data"),
    (b'\xfd7zXZ\x00',         "XZ compressed data"),
    (b'\x7fELF',               "ELF executable"),
    (b'MZ',                    "PE/DOS executable"),
    (b'\xca\xfe\xba\xbe',     "Mach-O fat binary"),
    (b'\xcf\xfa\xed\xfe',     "Mach-O 64-bit binary"),
    (b'OggS',                  "Ogg container"),
    (b'ID3',                   "MP3 audio (ID3 tag)"),
    (b'\xff\xfb',              "MP3 audio"),
    (b'fLaC',                  "FLAC audio"),
    (b'<!DOCTYPE',             "HTML document"),
    (b'<html',                 "HTML document"),
    (b'<?xml',                 "XML document"),
    (b'SQLite format 3\x00',   "SQLite database"),
    (b'#!',                    "Script"),
]

SCAN_SIGS = [
    (b'\x89PNG\r\n\x1a\n', "PNG image",            False),
    (b'\xff\xd8\xff',       "JPEG image",           False),
    (b'GIF87a',             "GIF image (87a)",      False),
    (b'GIF89a',             "GIF image (89a)",      False),
    (b'BM',                 "BMP image",            False),
    (b'PK\x03\x04',        "ZIP archive",           True),
    (b'PK\x05\x06',        "ZIP archive (empty)",  False),
    (b'Rar!\x1a\x07\x00',  "RAR archive v4",       False),
    (b'Rar!\x1a\x07\x01',  "RAR archive v5",       False),
    (b'7z\xbc\xaf\x27\x1c',"7-Zip archive",        False),
    (b'\x1f\x8b',          "gzip compressed data",  True),
    (b'BZh',               "bzip2 compressed data", False),
    (b'\xfd7zXZ\x00',      "XZ compressed data",   False),
    (b'%PDF',              "PDF document",           False),
    (b'\x7fELF',           "ELF executable",        False),
    (b'MZ',                "PE/DOS executable",     False),
    (b'RIFF',              "RIFF container",        False),
    (b'OggS',              "Ogg container",         False),
    (b'ID3',               "MP3 (ID3)",             False),
    (b'fLaC',              "FLAC audio",            False),
    (b'SQLite format 3\x00',"SQLite database",      False),
]

EXT_TOOLS = {
    "steghide": {"cmd": "steghide", "desc": "Detect steghide embedding (empty passphrase)",
                 "hint": "sudo apt install steghide"},
    "foremost": {"cmd": "foremost",  "desc": "File carving — recover embedded files",
                 "hint": "sudo apt install foremost"},
}

TOOL_DESCS = {
    "file":       "Identify file type via magic bytes",
    "strings":    "Extract ASCII + wide strings, inline base64 decode",
    "hexdump":    "Hex + ASCII dump of first 512 bytes",
    "exif":       "Dump EXIF / XMP / PIL metadata",
    "pngcheck":   "Validate PNG chunks, decode tEXt/zTXt/iTXt, trailing data",
    "binwalk":    "Scan + extract embedded files",
    "lsb":        "LSB channel stats + 8-method text extraction",
    "zsteg":      "Multi-plane bit extraction across channels/bits/order",
    "planes":     "Save all 24 bit-plane images to results dir",
    "stegdetect": "Chi-square + RS statistical steganalysis",
    "entropy":    "Shannon entropy + sliding window heatmap",
    "xor":        "Single-byte XOR brute-force + repeating-key detection",
    "audio":      "WAV/audio LSB extraction + raw string scan",
    **{k: v["desc"] for k, v in EXT_TOOLS.items()},
}

MENU_OPTIONS = [
    "file", "strings", "hexdump", "exif", "pngcheck",
    "binwalk", "lsb", "zsteg", "planes", "stegdetect", "entropy", "xor", "audio",
    "steghide", "foremost",
    "Run All", "Exit",
]

ALL_TOOLS = [t for t in MENU_OPTIONS if t not in ("Run All", "Exit")]


# ---------------------------------------------------------------------------
# Pure-Python tool implementations
# ---------------------------------------------------------------------------

def py_file(image_file: Path) -> str:
    data = image_file.read_bytes()
    header = data[:32]
    size = image_file.stat().st_size
    for magic, desc in MAGIC_SIGS:
        if header[:len(magic)] == magic:
            return f"{image_file.name}: {desc}  ({size:,} bytes)"
    try:
        data[:512].decode("utf-8")
        return f"{image_file.name}: UTF-8 text  ({size:,} bytes)"
    except UnicodeDecodeError:
        pass
    return f"{image_file.name}: data (unknown format, {size:,} bytes)"


def py_strings(image_file: Path, min_len: int = 7) -> str:
    data = image_file.read_bytes()
    sections = []

    # --- ASCII strings ---
    ascii_results = []
    current: list[str] = []
    start = 0
    for i, byte in enumerate(data):
        if 0x20 <= byte <= 0x7E:
            if not current:
                start = i
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                ascii_results.append((start, "".join(current)))
            current = []
    if len(current) >= min_len:
        ascii_results.append((start, "".join(current)))

    sections.append(f"=== ASCII strings ({len(ascii_results)} found) ===")
    for offset, s in ascii_results:
        decoded_notes = []
        for m in B64_RE.finditer(s):
            match = m.group()
            try:
                # Pad to multiple of 4 if needed
                padding = (4 - len(match) % 4) % 4
                decoded = base64.b64decode(match + "=" * padding).decode("utf-8", errors="replace")
                printable = sum(1 for c in decoded if 32 <= ord(c) <= 126)
                if printable / max(len(decoded), 1) > 0.7:
                    decoded_notes.append(f"b64→{repr(decoded[:80])}")
            except Exception:
                pass
        note = f"  [{'; '.join(decoded_notes)}]" if decoded_notes else ""
        sections.append(f"{offset:08x}  {s}{note}")

    # --- Wide strings (UTF-16LE) ---
    wide_results = []
    i = 0
    while i < len(data) - 1:
        if 0x20 <= data[i] <= 0x7E and data[i + 1] == 0x00:
            j = i
            chars = []
            while j + 1 < len(data) and 0x20 <= data[j] <= 0x7E and data[j + 1] == 0x00:
                chars.append(chr(data[j]))
                j += 2
            if len(chars) >= min_len:
                wide_results.append((i, "".join(chars)))
            i = j
            continue
        i += 1

    if wide_results:
        sections.append(f"\n=== Wide strings / UTF-16LE ({len(wide_results)} found) ===")
        for offset, s in wide_results:
            sections.append(f"{offset:08x}  {s}")

    return "\n".join(sections) if sections else "No strings found."


def py_hexdump(image_file: Path, limit: int = 512) -> str:
    data = image_file.read_bytes()
    total = len(data)
    data = data[:limit]
    lines = [f"Hexdump of {image_file.name}  (showing {len(data)}/{total:,} bytes)\n"]
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part  = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<48s}  |{ascii_part}|")
    return "\n".join(lines)


def py_exif(image_file: Path) -> str:
    sections = []

    # exifread
    try:
        with open(image_file, "rb") as f:
            tags = exifread.process_file(f, details=True)
        if tags:
            sections.append("=== EXIF (exifread) ===")
            sections.extend(f"{tag:40s} {value}" for tag, value in sorted(tags.items()))
        else:
            sections.append("=== EXIF (exifread) ===\nNo EXIF data found.")
    except Exception as e:
        sections.append(f"=== EXIF (exifread) ===\nError: {type(e).__name__}: {e}")

    # PIL metadata + image properties
    try:
        img = Image.open(image_file)
        info = img.info
        sections.append("\n=== PIL image properties ===")
        sections.append(f"  Mode:   {img.mode}")
        sections.append(f"  Size:   {img.width}x{img.height}")
        sections.append(f"  Format: {img.format}")
        if hasattr(img, "n_frames"):
            sections.append(f"  Frames: {img.n_frames}")
        if info:
            sections.append("\n=== PIL image info / embedded metadata ===")
            for k, v in sorted(info.items()):
                if isinstance(v, bytes):
                    try:
                        v_str = v.decode("utf-8", errors="replace")
                    except Exception:
                        v_str = v.hex()
                    sections.append(f"  {k}: {v_str[:400]}")
                else:
                    sections.append(f"  {k}: {str(v)[:400]}")
    except Exception as e:
        sections.append(f"\n=== PIL metadata ===\nError: {type(e).__name__}: {e}")

    return "\n".join(sections)


def py_pngcheck(image_file: Path) -> str:
    PNG_SIG = b'\x89PNG\r\n\x1a\n'
    data = image_file.read_bytes()
    lines = [f"File: {image_file.name}  ({len(data):,} bytes)"]

    if not data.startswith(PNG_SIG):
        return f"{image_file.name}: not a PNG file (wrong signature)"

    lines.append("PNG signature: OK")
    offset = 8
    chunk_num = 0
    idat_count = 0
    idat_bytes = 0
    found_iend = False

    while offset < len(data):
        if offset + 8 > len(data):
            lines.append(f"  [ERROR] Truncated chunk header at offset {offset:#x}")
            break

        length = struct.unpack(">I", data[offset:offset + 4])[0]
        chunk_type_raw = data[offset + 4:offset + 8]
        chunk_type = chunk_type_raw.decode("ascii", errors="replace")
        chunk_data = data[offset + 8: offset + 8 + length]
        end = offset + 8 + length

        if end + 4 > len(data):
            lines.append(f"  [ERROR] Chunk {chunk_type} extends past end of file")
            break

        crc_stored   = struct.unpack(">I", data[end:end + 4])[0]
        crc_computed = zlib.crc32(chunk_type_raw + chunk_data) & 0xFFFFFFFF
        crc_str = ("CRC OK" if crc_stored == crc_computed
                   else f"CRC FAIL (stored=0x{crc_stored:08x} computed=0x{crc_computed:08x})")

        lines.append(f"  [{chunk_num:>3}] {chunk_type}  length={length}  "
                     f"offset={offset:#010x}  {crc_str}")

        if chunk_type == "IHDR" and len(chunk_data) >= 13:
            w, h, bd, ct, comp, filt, inter = struct.unpack(">IIBBBBB", chunk_data[:13])
            lines.append(f"         Width={w}  Height={h}  BitDepth={bd}  "
                         f"ColorType={PNG_COLOR_TYPES.get(ct, ct)}  "
                         f"Interlace={'Adam7' if inter else 'None'}")

        elif chunk_type == "PLTE":
            n_entries = length // 3
            lines.append(f"         Palette: {n_entries} color entries")

        elif chunk_type == "IDAT":
            idat_count += 1
            idat_bytes += length

        elif chunk_type == "tEXt" and chunk_data:
            parts = chunk_data.split(b"\x00", 1)
            if len(parts) == 2:
                key = parts[0].decode("latin-1", errors="replace")
                val = parts[1].decode("latin-1", errors="replace")
                lines.append(f"         Text: [{key}] = {val}")

        elif chunk_type == "zTXt" and chunk_data:
            parts = chunk_data.split(b"\x00", 2)
            if len(parts) >= 3:
                key = parts[0].decode("latin-1", errors="replace")
                try:
                    val = zlib.decompress(parts[2]).decode("latin-1", errors="replace")
                    lines.append(f"         CompressedText: [{key}] = {val}")
                except zlib.error as e:
                    lines.append(f"         CompressedText: [{key}] (zlib error: {e})")
                except Exception as e:
                    lines.append(f"         CompressedText: [{key}] ({type(e).__name__}: {e})")

        elif chunk_type == "iTXt" and chunk_data:
            try:
                null_pos = chunk_data.index(b'\x00')
                keyword   = chunk_data[:null_pos].decode("utf-8", errors="replace")
                comp_flag = chunk_data[null_pos + 1] if null_pos + 1 < len(chunk_data) else 0
                rest      = chunk_data[null_pos + 3:]     # skip comp_flag + comp_method bytes
                lang_end  = rest.find(b'\x00')
                if lang_end >= 0:
                    rest = rest[lang_end + 1:]
                    tk_end = rest.find(b'\x00')
                    if tk_end >= 0:
                        rest = rest[tk_end + 1:]
                if comp_flag:
                    try:
                        text = zlib.decompress(rest).decode("utf-8", errors="replace")
                    except zlib.error as e:
                        text = f"(zlib error: {e})"
                    except Exception as e:
                        text = f"({type(e).__name__}: {e})"
                else:
                    text = rest.decode("utf-8", errors="replace")
                lines.append(f"         InternationalText: [{keyword}] = {text[:500]}")
            except Exception as e:
                lines.append(f"         InternationalText: {length} bytes ({type(e).__name__}: {e})")

        chunk_num += 1
        offset = end + 4

        if chunk_type == "IEND":
            found_iend = True
            trailing = len(data) - offset
            if trailing > 0:
                lines.append(f"  [WARNING] {trailing} bytes of trailing data after IEND")
                trail = data[offset:offset + min(trailing, 256)]
                lines.append(f"  Trailing data hex dump (first {len(trail)} bytes):")
                for ti in range(0, len(trail), 16):
                    ch = trail[ti:ti + 16]
                    hp = " ".join(f"{b:02x}" for b in ch)
                    ap = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in ch)
                    lines.append(f"    {ti:04x}  {hp:<48s}  |{ap}|")
            break

    if not found_iend:
        lines.append("  [WARNING] No IEND chunk found — file may be truncated or corrupted")

    if idat_count > 0:
        lines.append(f"\nIDAT summary: {idat_count} chunk(s), {idat_bytes:,} compressed bytes total")

    return "\n".join(lines)


def py_binwalk(image_file: Path, results_dir: Path) -> str:
    data = image_file.read_bytes()
    findings = []

    for i in range(len(data)):
        for magic, desc, extractable in SCAN_SIGS:
            if data[i:i + len(magic)] == magic:
                findings.append((i, desc, extractable, magic))
                break

    if not findings:
        return "No embedded signatures found."

    lines = [f"Scanning {image_file.name}  ({len(data):,} bytes)\n"]
    extracted = []

    for offset, desc, extractable, magic in findings:
        lines.append(f"  {offset:#010x}  {desc}")
        # offset > 0 guard: skip offset 0 since that is the file itself, not an embedded payload
        if extractable and offset > 0:
            chunk = data[offset:]
            out_name = f"extracted_{offset:#010x}"
            try:
                if magic == b'PK\x03\x04':
                    with zipfile.ZipFile(io.BytesIO(chunk)) as zf:
                        out_dir = results_dir / (out_name + "_zip")
                        zf.extractall(out_dir)
                        extracted.append(str(out_dir))
                elif magic == b'\x1f\x8b':
                    out_file = results_dir / (out_name + ".gz.out")
                    with gzip.open(io.BytesIO(chunk)) as gz:
                        out_file.write_bytes(gz.read())
                    extracted.append(str(out_file))
            except zipfile.BadZipFile as e:
                lines.append(f"             [ZIP extraction failed: {e}]")
            except gzip.BadGzipFile as e:
                lines.append(f"             [GZIP extraction failed: {e}]")
            except Exception as e:
                lines.append(f"             [extraction failed: {type(e).__name__}: {e}]")

    if extracted:
        lines.append("\nExtracted:")
        for path in extracted:
            lines.append(f"  {path}")

    return "\n".join(lines)


def py_lsb(image_file: Path) -> str:
    """LSB steganography analysis: channel stats + 8-method text extraction."""
    try:
        img = Image.open(image_file)
        original_mode = img.mode
        img = img.convert("RGBA")
    except Exception as e:
        return f"Could not open image: {type(e).__name__}: {e}"

    width, height = img.size
    pixels = _get_pixels(img)
    total = len(pixels)
    lines = [f"Image: {image_file.name}  {width}x{height}  original_mode={original_mode}  pixels={total}"]

    channels: dict[str, list[int]] = {"R": [], "G": [], "B": [], "A": []}
    for r, g, b, a in pixels:
        channels["R"].append(r & 1)
        channels["G"].append(g & 1)
        channels["B"].append(b & 1)
        channels["A"].append(a & 1)

    lines.append("\nLSB distribution (ratio near 0.5 = suspicious):")
    for ch, lsbs in channels.items():
        ones  = sum(lsbs)
        ratio = ones / total if total else 0
        flag  = "  <-- suspicious" if abs(ratio - 0.5) < 0.02 else ""
        lines.append(f"  {ch}: {ones}/{total} ones  ratio={ratio:.4f}{flag}")

    if original_mode in ("RGB", "L", "P"):
        lines.append("  Note: Alpha is synthetic (image had no alpha channel); alpha LSB not meaningful")

    def pack_bits_msb(bits: list[int]) -> bytes:
        out = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte = sum(bits[i + j] << (7 - j) for j in range(8))
            out.append(byte)
        return bytes(out)

    def score(data: bytes, label: str) -> str:
        if not data:
            return f"  {label}: (no data)"
        n = min(500, len(data))
        printable = sum(1 for b in data[:n] if 32 <= b <= 126)
        ratio = printable / n
        text  = data[:500].decode("latin-1", errors="replace")
        flags = FLAG_RE.findall(text)
        if flags:
            return f"  {label}: *** FLAGS: {flags} ***\n    {repr(text[:200])}"
        clean = "".join(c if 32 <= ord(c) <= 126 else "" for c in text[:200])
        if ratio > 0.70:
            return f"  {label}: printable={ratio:.0%}  {repr(clean[:200])}"
        if ratio > 0.40:
            return f"  {label}: printable={ratio:.0%}  (partial — {repr(clean[:100])})"
        return f"  {label}: printable={ratio:.0%}  (mostly binary)"

    lines.append("\nLSB text extraction attempts:")

    # Method 1: RGB sequential (most common CTF embedding method)
    rgb_bits: list[int] = []
    for r, g, b, a in pixels:
        rgb_bits.extend([r & 1, g & 1, b & 1])
    lines.append(score(pack_bits_msb(rgb_bits), "RGB sequential"))

    # Method 2: RGBA sequential
    rgba_bits: list[int] = []
    for r, g, b, a in pixels:
        rgba_bits.extend([r & 1, g & 1, b & 1, a & 1])
    lines.append(score(pack_bits_msb(rgba_bits), "RGBA sequential"))

    # Methods 3-6: individual channels
    for ch in ("R", "G", "B", "A"):
        lines.append(score(pack_bits_msb(channels[ch]), f"{ch} channel only"))

    # Method 7: BGR channel order (some tools use this)
    bgr_bits: list[int] = []
    for r, g, b, a in pixels:
        bgr_bits.extend([b & 1, g & 1, r & 1])
    lines.append(score(pack_bits_msb(bgr_bits), "BGR sequential"))

    # Method 8: column-order scan (row-major assumed by default; column-major sometimes used)
    col_pixels = [pixels[y * width + x] for x in range(width) for y in range(height)]
    col_bits: list[int] = []
    for r, g, b, a in col_pixels:
        col_bits.extend([r & 1, g & 1, b & 1])
    lines.append(score(pack_bits_msb(col_bits), "RGB column-order"))

    return "\n".join(lines)


def py_zsteg(image_file: Path) -> str:
    """Multi-plane bit extraction: tries all channel combos × bit depths × bit ordering."""
    try:
        img = Image.open(image_file)
        if img.mode == "P":
            img = img.convert("RGB")
        elif img.mode not in ("RGB", "RGBA", "L"):
            img = img.convert("RGBA")
    except Exception as e:
        return f"Could not open image: {type(e).__name__}: {e}"

    pixels  = _get_pixels(img)
    mode    = img.mode
    width, height = img.size
    lines   = [f"Image: {image_file.name}  {width}x{height}  mode={mode}"]

    def extract(pixels, ch_indices: list[int], bit: int, lsb_first: bool) -> bytes:
        bits: list[int] = []
        for px in pixels:
            px_t = px if isinstance(px, tuple) else (px,)
            for ci in ch_indices:
                val = px_t[ci] if ci < len(px_t) else 0
                bits.append((val >> bit) & 1)
        out = bytearray()
        for i in range(0, len(bits) - 7, 8):
            b = bits[i:i + 8]
            byte = sum(b[j] << j for j in range(8)) if lsb_first else sum(b[j] << (7 - j) for j in range(8))
            out.append(byte)
        return bytes(out)

    def analyze(data: bytes) -> tuple[float, list[str]]:
        if not data:
            return 0.0, []
        n         = min(500, len(data))
        printable = sum(1 for b in data[:n] if 32 <= b <= 126)
        ratio     = printable / n
        text      = data[:500].decode("latin-1", errors="replace")
        flags     = FLAG_RE.findall(text)
        return ratio + 5.0 * len(flags), flags

    ch_idx = {c: i for i, c in enumerate(mode)}

    combos: list[tuple[list[int], str]] = []
    for c in mode:
        combos.append(([ch_idx[c]], c))
    for a, b in [("R", "G"), ("R", "B"), ("G", "B")]:
        if a in ch_idx and b in ch_idx:
            combos.append(([ch_idx[a], ch_idx[b]], f"{a}{b}"))
    if all(c in ch_idx for c in "RGB"):
        combos.append(([ch_idx["R"], ch_idx["G"], ch_idx["B"]], "RGB"))
    if all(c in ch_idx for c in "RGBA"):
        combos.append(([ch_idx["R"], ch_idx["G"], ch_idx["B"], ch_idx["A"]], "RGBA"))

    candidates = []
    total_tested = 0
    for bit in range(4):
        for ch_list, ch_name in combos:
            for lsb_first in (False, True):
                total_tested += 1
                try:
                    data  = extract(pixels, ch_list, bit, lsb_first)
                    score, flags = analyze(data)
                    if score > 0.35 or flags:
                        order = "lsb-first" if lsb_first else "msb-first"
                        text  = data[:300].decode("latin-1", errors="replace")
                        candidates.append((score, bit, ch_name, order, text, flags))
                except Exception:
                    pass

    candidates.sort(reverse=True)
    lines.append(f"Tested {total_tested} combinations (channels × bit-planes × bit-order)\n")

    if not candidates:
        lines.append("No promising bit-plane data found.")
        return "\n".join(lines)

    lines.append("Top candidates (sorted by printability score):")
    shown = 0
    for score, bit, ch_name, order, text, flags in candidates:
        if shown >= 20 and not flags:
            continue
        flag_note = f"  *** FLAGS: {flags} ***" if flags else ""
        clean = "".join(c if 32 <= ord(c) <= 126 else " " for c in text[:200]).strip()
        lines.append(f"\n  bit={bit}  channels={ch_name}  order={order}  score={score:.2f}{flag_note}")
        lines.append(f"  {repr(clean[:160])}")
        shown += 1
        if shown >= 30:
            break

    return "\n".join(lines)


def py_planes(image_file: Path, results_dir: Path) -> str:
    """Save all bit-plane images (R/G/B × bits 0-7) to results directory."""
    try:
        img = Image.open(image_file).convert("RGB")
    except Exception as e:
        return f"Could not open image: {type(e).__name__}: {e}"

    width, height = img.size
    pixels = _get_pixels(img)
    lines  = [f"Bit-plane extraction: {image_file.name}  {width}x{height}"]

    saved = []
    for ch_idx, ch_name in enumerate("RGB"):
        for bit in range(8):
            plane_data = [255 if ((px[ch_idx] >> bit) & 1) else 0 for px in pixels]
            plane_img  = Image.new("L", (width, height))
            plane_img.putdata(plane_data)
            out_path = results_dir / f"bitplane_{ch_name}_bit{bit}.png"
            plane_img.save(out_path)
            saved.append(out_path.name)

    lines.append(f"Saved {len(saved)} images to: {results_dir}")
    lines.append("Naming: bitplane_<channel>_bit<n>.png  (bit0=LSB, bit7=MSB)")
    lines.append("\nFiles:")
    for name in saved:
        lines.append(f"  {name}")
    return "\n".join(lines)


def _chi2_sf(chi_sq: float, df: int) -> float:
    """Chi-squared survival function approximation via Wilson-Hilferty."""
    if df <= 0 or chi_sq < 0:
        return 1.0
    x = chi_sq / df
    if x <= 0:
        return 1.0
    z = (x ** (1 / 3) - (1 - 2 / (9 * df))) / math.sqrt(2 / (9 * df))
    return 0.5 * math.erfc(z / math.sqrt(2))


def py_stegdetect(image_file: Path) -> str:
    """Statistical steganalysis: chi-square (Westfeld/Pfitzmann) + simplified RS analysis."""
    try:
        img = Image.open(image_file).convert("RGB")
    except Exception as e:
        return f"Could not open image: {type(e).__name__}: {e}"

    pixels = _get_pixels(img)
    width, height = img.size
    lines = [
        f"Statistical Steganalysis: {image_file.name}  {width}x{height}\n",
        "Chi-square attack (Westfeld & Pfitzmann 1999):",
        "  After LSB embedding, value pairs (2k, 2k+1) equalize in frequency.",
        "  High p-value = pairs are equalized = SUSPICIOUS.",
        "  Low p-value  = natural variation present = likely clean.\n",
    ]

    verdicts = []
    for ch_name, ci in [("R", 0), ("G", 1), ("B", 2)]:
        freq = [0] * 256
        for px in pixels:
            freq[px[ci]] += 1

        chi_sq = 0.0
        df     = 0
        for k in range(128):
            f0 = freq[2 * k]
            f1 = freq[2 * k + 1]
            expected = (f0 + f1) / 2
            if expected > 0:
                chi_sq += (f0 - expected) ** 2 / expected
                chi_sq += (f1 - expected) ** 2 / expected
                df += 1

        p = _chi2_sf(chi_sq, df)
        if p > 0.95:
            verdict = "*** SUSPICIOUS ***"
            verdicts.append(f"{ch_name} chi2: SUSPICIOUS (p={p:.3f})")
        elif p > 0.50:
            verdict = "UNCERTAIN"
            verdicts.append(f"{ch_name} chi2: uncertain (p={p:.3f})")
        else:
            verdict = "likely clean"
        lines.append(f"  Channel {ch_name}: chi2={chi_sq:.2f}  df={df}  p={p:.4f}  => {verdict}")

    # Simplified RS analysis on R channel
    lines.append("\nRS Analysis (simplified — R channel, groups of 4):")
    lines.append("  Compares group smoothness with/without LSB flip.")
    lines.append("  |d| near 0 = Rm ≈ R-1 and Sm ≈ S-1 = SUSPICIOUS.\n")
    try:
        r_vals  = [px[0] for px in pixels]
        groups  = [r_vals[i:i + 4] for i in range(0, len(r_vals) - 3, 4)][:10000]

        def smooth(g: list[int]) -> int:
            return sum(abs(g[i] - g[i - 1]) for i in range(1, len(g)))

        Rm = Sm = R1 = S1 = 0
        for g in groups:
            orig      = smooth(g)
            flipped   = smooth([v ^ 1 for v in g])   # mask +1
            neg_flip  = smooth([v ^ 2 for v in g])   # approximate mask -1
            if orig < flipped: Rm += 1
            elif orig > flipped: Sm += 1
            if orig < neg_flip: R1 += 1
            elif orig > neg_flip: S1 += 1

        n  = len(groups)
        if n == 0:
            lines.append("  Image too small for RS analysis (need at least 4 pixels).")
            raise ValueError("insufficient pixels")
        rm = Rm / n; sm = Sm / n; r1 = R1 / n; s1 = S1 / n
        d  = (rm - r1) + (sm - s1)
        lines.append(f"  Rm={rm:.4f}  Sm={sm:.4f}  R-1={r1:.4f}  S-1={s1:.4f}")
        lines.append(f"  d = (Rm - R-1) + (Sm - S-1) = {d:.4f}")
        if abs(d) < 0.02:
            lines.append("  => |d| near 0: *** SUSPICIOUS *** — possible LSB embedding")
            verdicts.append(f"RS: SUSPICIOUS (d={d:.4f})")
        else:
            lines.append("  => |d| significant: likely clean")
    except Exception as e:
        lines.append(f"  RS analysis error: {type(e).__name__}: {e}")

    lines.append("")
    if verdicts:
        lines.append(f"[!] Summary: {'; '.join(verdicts)}")
    else:
        lines.append("[+] No steganography indicators found by statistical tests.")

    return "\n".join(lines)


def py_entropy(image_file: Path) -> str:
    """Shannon entropy analysis with sliding window ASCII heatmap."""
    data = image_file.read_bytes()
    size = len(data)

    def shannon(chunk: bytes) -> float:
        if not chunk:
            return 0.0
        freq: dict[int, int] = {}
        for b in chunk:
            freq[b] = freq.get(b, 0) + 1
        n = len(chunk)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    overall = shannon(data)
    lines   = [f"Entropy analysis: {image_file.name}  ({size:,} bytes)"]
    lines.append(f"Overall entropy: {overall:.4f} bits/byte  (max=8.0)\n")

    if   overall > 7.8: lines.append("  Very high entropy — likely compressed, encrypted, or random")
    elif overall > 7.0: lines.append("  High entropy — compressed or encoded content")
    elif overall > 5.0: lines.append("  Medium entropy — typical binary/image data")
    else:               lines.append("  Low entropy — may contain plaintext or structured data")

    window = max(256, size // 32)
    step   = max(64, window // 4)
    wins   = [(i, shannon(data[i:i + window])) for i in range(0, size - window, step)]

    if len(wins) < 2:
        return "\n".join(lines)

    e_vals    = [e for _, e in wins]
    min_e, max_e = min(e_vals), max(e_vals)
    lines.append(f"\nSliding window ({window} bytes, step {step}):")
    lines.append(f"  min={min_e:.4f}  max={max_e:.4f}  range={max_e - min_e:.4f}\n")
    lines.append("  Offset       Entropy  Chart (0=low, full=high)")

    bar_width = 30
    for offset, e in wins:
        bar  = int((e / 8.0) * bar_width)
        bar_s = "█" * bar + "░" * (bar_width - bar)
        note  = " <-- LOW ENTROPY" if e < 5.0 else (" <-- HIGH" if e > 7.8 else "")
        lines.append(f"  {offset:08x}  {e:.4f}  {bar_s}{note}")

    # Highlight anomalous low-entropy regions (possible plaintext pockets)
    if max_e - min_e > 1.0:
        threshold = min_e + 0.4 * (max_e - min_e)
        anomalies = [(o, e) for o, e in wins if e < threshold]
        if anomalies:
            lines.append(f"\n  Low-entropy regions (possible plaintext / structured data):")
            for offset, e in anomalies[:10]:
                snippet = data[offset:offset + 32]
                ascii_s = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in snippet)
                lines.append(f"    {offset:#010x}  entropy={e:.4f}  |{ascii_s}|")

    return "\n".join(lines)


def _hamming_dist(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def py_xor(image_file: Path) -> str:
    """Single-byte XOR brute-force + repeating-key (Vigenere-style) detection."""
    data   = image_file.read_bytes()
    sample = data[:4000]
    lines  = [f"XOR analysis: {image_file.name}  ({len(data):,} bytes, analyzing first {len(sample)})"]

    # Single-byte
    results = []
    for key in range(256):
        xored     = bytes(b ^ key for b in sample)
        printable = sum(1 for b in xored if 32 <= b <= 126 or b in (9, 10, 13))
        ratio     = printable / len(xored)
        text      = xored.decode("latin-1", errors="replace")
        flags     = FLAG_RE.findall(text)
        score     = ratio + 5.0 * len(flags)
        results.append((score, key, ratio, text, flags))

    results.sort(reverse=True)
    lines.append("\nTop single-byte XOR candidates:")
    for score, key, ratio, text, flags in results[:10]:
        flag_note = f"  *** FLAGS: {flags} ***" if flags else ""
        clean = "".join(c if 32 <= ord(c) <= 126 else "." for c in text[:120])
        lines.append(f"\n  key=0x{key:02x} ({key:3d})  printable={ratio:.0%}{flag_note}")
        lines.append(f"  {repr(clean[:120])}")

    # Repeating-key: find likely key lengths via normalized Hamming distance
    lines.append("\n--- Repeating-key XOR (Vigenere-style) ---")
    lines.append("Finding key length via normalized Hamming distance (lower = more likely):")

    kl_scores: list[tuple[float, int]] = []
    for kl in range(2, 33):
        if kl * 4 > len(sample):
            break
        dists = []
        for i in range(min(6, len(sample) // kl - 1)):
            a = sample[i * kl:(i + 1) * kl]
            b = sample[(i + 1) * kl:(i + 2) * kl]
            if len(a) == len(b) == kl:
                dists.append(_hamming_dist(a, b) / kl)
        if dists:
            kl_scores.append((sum(dists) / len(dists), kl))

    kl_scores.sort()
    top_kls = [kl for _, kl in kl_scores[:6]]
    for norm_dist, kl in kl_scores[:6]:
        lines.append(f"  keylen={kl:2d}  normalized_hamming={norm_dist:.4f}")

    # Solve for each top key length
    def solve_repeating(data: bytes, keylen: int) -> tuple[bytes, float]:
        key = bytearray()
        for i in range(keylen):
            chunk     = data[i::keylen]
            best_sc   = -1
            best_byte = 0
            for candidate in range(256):
                dec = bytes(b ^ candidate for b in chunk)
                sc  = sum(1 for b in dec if 32 <= b <= 126 or b in (9, 10, 13))
                sc += 10 * len(FLAG_RE.findall(dec.decode("latin-1", errors="replace")))
                if sc > best_sc:
                    best_sc   = sc
                    best_byte = candidate
            key.append(best_byte)
        decrypted = bytes(data[i] ^ key[i % keylen] for i in range(len(data)))
        printable = sum(1 for b in decrypted if 32 <= b <= 126 or b in (9, 10, 13))
        return bytes(key), printable / len(decrypted)

    lines.append("\nRepeating-key decryption attempts:")
    for kl in top_kls:
        try:
            key, ratio = solve_repeating(sample, kl)
            decrypted  = bytes(sample[i] ^ key[i % kl] for i in range(len(sample)))
            text       = decrypted.decode("latin-1", errors="replace")
            flags      = FLAG_RE.findall(text)
            flag_note  = f"  *** FLAGS: {flags} ***" if flags else ""
            clean      = "".join(c if 32 <= ord(c) <= 126 else "." for c in text[:120])
            lines.append(f"\n  keylen={kl}  key={key.hex()}  printable={ratio:.0%}{flag_note}")
            lines.append(f"  {repr(clean[:120])}")
        except Exception as e:
            lines.append(f"  keylen={kl}: error — {type(e).__name__}: {e}")

    return "\n".join(lines)


def py_audio(image_file: Path) -> str:
    """Audio steganography analysis: WAV LSB extraction + raw string scan."""
    data = image_file.read_bytes()
    lines = [f"Audio analysis: {image_file.name}  ({len(data):,} bytes)"]

    is_wav = data[:4] == b"RIFF" and data[8:12] == b"WAVE"
    samples = None

    if is_wav:
        try:
            with wave.open(str(image_file), "rb") as wav:
                nchannels  = wav.getnchannels()
                sampwidth  = wav.getsampwidth()
                framerate  = wav.getframerate()
                nframes    = wav.getnframes()
                raw_frames = wav.readframes(nframes)
            duration = nframes / framerate if framerate else 0
            lines.append(f"WAV: channels={nchannels}  sample_width={sampwidth}B  "
                         f"rate={framerate}Hz  frames={nframes}  duration={duration:.2f}s")
            lines.append(f"Raw audio data: {len(raw_frames):,} bytes\n")

            if sampwidth == 2:
                fmt     = f"<{len(raw_frames) // 2}h"
                aligned = raw_frames[:len(raw_frames) - len(raw_frames) % 2]
                samples = list(struct.unpack(fmt, aligned))
            elif sampwidth == 1:
                samples = list(raw_frames)
            else:
                lines.append(f"Sample width {sampwidth} — falling back to raw byte LSB")
                samples = list(raw_frames)
        except wave.Error as e:
            lines.append(f"WAV parse error: {e}  — falling back to raw byte analysis")
        except Exception as e:
            lines.append(f"WAV open error: {type(e).__name__}: {e}  — falling back to raw byte analysis")
    else:
        lines.append("Not a WAV file — performing raw byte LSB analysis")
        samples = list(data)

    if samples:
        # LSB extraction (msb-first bit packing)
        lsbs = [int(s) & 1 for s in samples]
        raw_bytes = bytearray()
        for i in range(0, len(lsbs) - 7, 8):
            byte = sum(lsbs[i + j] << (7 - j) for j in range(8))
            raw_bytes.append(byte)

        text      = raw_bytes[:500].decode("latin-1", errors="replace")
        printable = sum(1 for c in text if 32 <= ord(c) <= 126)
        ratio     = printable / min(500, len(text)) if text else 0
        lines.append(f"LSB extraction ({len(lsbs)} samples → {len(raw_bytes)} bytes):")
        lines.append(f"  Printable ratio: {ratio:.0%}")
        flags = FLAG_RE.findall(text)
        if flags:
            lines.append(f"  *** FLAGS FOUND: {flags} ***")
        clean = "".join(c if 32 <= ord(c) <= 126 else "." for c in text[:300])
        lines.append(f"  First 300 chars: {repr(clean)}")

    # Raw string extraction from audio bytes (catches cleartext in file structure)
    raw_strings: list[tuple[int, str]] = []
    current: list[str] = []
    start = 0
    for i, byte in enumerate(data):
        if 0x20 <= byte <= 0x7E:
            if not current:
                start = i
            current.append(chr(byte))
        else:
            if len(current) >= 8:
                raw_strings.append((start, "".join(current)))
            current = []
    if len(current) >= 8:
        raw_strings.append((start, "".join(current)))

    if raw_strings:
        lines.append(f"\nRaw strings in file ({len(raw_strings)} found, showing up to 40):")
        for offset, s in raw_strings[:40]:
            f_note = f"  *** FLAG: {FLAG_RE.findall(s)} ***" if FLAG_RE.search(s) else ""
            lines.append(f"  {offset:08x}  {s[:120]}{f_note}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# External tool runner
# ---------------------------------------------------------------------------

def run_ext_tool(name: str, image_file: Path, results_dir: Path) -> str | None:
    tool = EXT_TOOLS[name]
    if not shutil.which(tool["cmd"]):
        console.print(f"[yellow]{name} not installed.[/yellow]  [dim]{tool['hint']}[/dim]")
        return None

    if name == "steghide":
        cmd = ["steghide", "info", "-p", "", str(image_file)]
    elif name == "foremost":
        out = str(results_dir / "foremost_output")
        cmd = ["foremost", "-i", str(image_file), "-o", out]
    else:
        cmd = [tool["cmd"], str(image_file)]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return (result.stdout + result.stderr).strip() or None
    except subprocess.TimeoutExpired:
        console.print(f"[red]{name} timed out after 120s.[/red]")
        return None
    except FileNotFoundError as e:
        console.print(f"[red]{name} not found: {e}[/red]")
        return None
    except Exception as e:
        console.print(f"[red]{name} error: {type(e).__name__}: {e}[/red]")
        return None


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def highlight_flags(text: str) -> Text:
    result = Text()
    last = 0
    for m in FLAG_RE.finditer(text):
        result.append(text[last:m.start()])
        result.append(m.group(), style="bold green")
        last = m.end()
    result.append(text[last:])
    return result


def display_and_save(name: str, output: str, results_dir: Path):
    out_file = results_dir / f"{name}_output.txt"
    out_file.write_text(output)

    console.print(Rule(f"[bold magenta]{name}[/bold magenta]", style="magenta"))

    if len(output.splitlines()) <= 30:
        console.print(highlight_flags(output))
    else:
        with console.pager(styles=True):
            console.print(f"[bold magenta]─── {name} ───[/bold magenta]")
            console.print(highlight_flags(output))

    console.print(f"[dim]Saved → {out_file}[/dim]")

    flags = FLAG_RE.findall(output)
    # Secondary filter: require ≥60% of chars to be alphanumeric/underscore/hyphen.
    # Eliminates XOR garbage that matches the pattern but is mostly symbols.
    def _confident(f: str) -> bool:
        normal = sum(1 for c in f if c.isalnum() or c in "_-! ")
        return normal / max(len(f), 1) >= 0.60
    flags = [f for f in flags if _confident(f)]
    if flags:
        console.print(Panel(
            "\n".join(f"[bold green]{f}[/bold green]" for f in flags),
            title="[bold green] Possible Flags [/bold green]",
            border_style="green",
        ))


# ---------------------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------------------

def run_tool(name: str, image_file: Path, results_dir: Path):
    console.print(f"\n[bold magenta]Running {name}...[/bold magenta]")
    output = None
    try:
        if   name == "file":       output = py_file(image_file)
        elif name == "strings":    output = py_strings(image_file)
        elif name == "hexdump":    output = py_hexdump(image_file)
        elif name == "exif":       output = py_exif(image_file)
        elif name == "pngcheck":   output = py_pngcheck(image_file)
        elif name == "binwalk":    output = py_binwalk(image_file, results_dir)
        elif name == "lsb":        output = py_lsb(image_file)
        elif name == "zsteg":      output = py_zsteg(image_file)
        elif name == "planes":     output = py_planes(image_file, results_dir)
        elif name == "stegdetect": output = py_stegdetect(image_file)
        elif name == "entropy":    output = py_entropy(image_file)
        elif name == "xor":        output = py_xor(image_file)
        elif name == "audio":      output = py_audio(image_file)
        else:                      output = run_ext_tool(name, image_file, results_dir)
    except Exception as e:
        console.print(f"[red]{name} error: {type(e).__name__}: {e}[/red]")
        return

    if not output:
        console.print(f"[dim]No output from {name}.[/dim]")
        return

    display_and_save(name, output, results_dir)


def run_all(image_file: Path, results_dir: Path):
    for name in ALL_TOOLS:
        run_tool(name, image_file, results_dir)
    console.print(Panel(
        f"[green]All tools complete.[/green]\nResults saved in: [bold]{results_dir}[/bold]",
        border_style="magenta",
    ))


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

def print_banner():
    if BANNER_FILE.exists():
        console.print(f"[bold magenta]{BANNER_FILE.read_text().rstrip()}[/bold magenta]")
    else:
        console.print("[bold magenta]FORENZIK[/bold magenta]")
    console.print("[white]Brought to you by Coney Island Arcade[/white]\n")


def show_status():
    missing = [n for n in EXT_TOOLS if not shutil.which(EXT_TOOLS[n]["cmd"])]
    if missing:
        console.print(
            "[dim]Optional tools not installed: "
            + ", ".join(f"[yellow]{t}[/yellow]" for t in missing)
            + "[/dim]\n"
        )


def pick_file_interactive() -> Path | None:
    while True:
        cwd   = Path.cwd()
        files = sorted(f for f in cwd.iterdir() if f.is_file())
        width = max(40, min(console.width, 84))

        table = Table(show_header=False, box=None, padding=(0, 2), width=width - 4)
        table.add_column("i",    style="bold cyan", justify="right", no_wrap=True)
        table.add_column("name", style="white")

        for i, f in enumerate(files, 1):
            table.add_row(str(i), f.name)
        table.add_row("0", "[dim]Enter path manually[/dim]")
        table.add_row("q", "[dim]Quit[/dim]")

        console.print(Panel(table, title="[bold]Select a file[/bold]",
                            border_style="magenta", width=width))
        choice = Prompt.ask("Choice")

        if choice.lower() in ("q", "quit", "exit"):
            return None

        if choice == "0":
            p_str = Prompt.ask("Path")
            p = Path(p_str)
            if p.is_file():
                return p
            console.print(f"[red]File not found: {p_str} — try again.[/red]")
            continue

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(files):
                return files[idx]
        except ValueError:
            pass

        console.print("[red]Invalid selection — try again.[/red]")


def show_menu() -> str:
    width = max(40, min(console.width, 84))
    table = Table(show_header=False, box=None, padding=(0, 2), width=width - 4)
    table.add_column("i",    style="bold cyan", justify="right", no_wrap=True)
    table.add_column("tool", style="white",     no_wrap=True)
    table.add_column("desc", style="dim")

    for i, opt in enumerate(MENU_OPTIONS, 1):
        available = opt not in EXT_TOOLS or shutil.which(EXT_TOOLS[opt]["cmd"])
        label = opt if available else f"[dim]{opt}[/dim]"
        table.add_row(str(i), label, TOOL_DESCS.get(opt, ""))

    console.print(Panel(table, title="[bold]CTF Forensics + Steganography Toolkit[/bold]",
                        border_style="magenta", width=width))
    choice = Prompt.ask("Select an option")

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(MENU_OPTIONS):
            return MENU_OPTIONS[idx]
    except ValueError:
        pass
    return ""


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("file", required=False, type=click.Path(dir_okay=False))
@click.option("--tool", "-t",
              multiple=True,
              type=click.Choice(ALL_TOOLS, case_sensitive=False),
              help="Run a specific tool. Repeatable.")
@click.option("--all", "-a", "run_all_flag",
              is_flag=True,
              help="Run all tools non-interactively and exit.")
@click.option("--output", "-o",
              type=click.Path(),
              default=None,
              help="Output directory (default: forenzik_results_<timestamp> in cwd).")
def main(file, tool, run_all_flag, output):
    """
    forenzik — CTF forensics + steganography toolkit.

    Pass FILE directly to skip the file picker.
    Use --all to run everything non-interactively.
    Use --tool/-t to run one or more specific tools.

    Examples:\n
      python3 forenzik.py image.png --all\n
      python3 forenzik.py image.png -t exif -t lsb -t zsteg\n
      python3 forenzik.py image.png -t pngcheck\n
      python3 forenzik.py
    """
    print_banner()
    show_status()

    if file:
        image_file = Path(file)
        if not image_file.is_file():
            console.print(f"[red]File not found: {file}[/red]")
            raise SystemExit(1)
    else:
        image_file = pick_file_interactive()
        if not image_file:
            console.print("[red]No valid file selected. Exiting.[/red]")
            raise SystemExit(1)

    console.print(f"\n[bold green]Target:[/bold green] {image_file}\n")

    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_dir = Path(output) if output else Path.cwd() / f"forenzik_results_{timestamp}"
    results_dir.mkdir(parents=True, exist_ok=True)

    if run_all_flag:
        run_all(image_file, results_dir)
        return

    if tool:
        for t in tool:
            run_tool(t, image_file, results_dir)
        return

    while True:
        selection = show_menu()
        if not selection:
            console.print("[red]Invalid option — try again.[/red]")
            continue
        if selection == "Run All":
            run_all(image_file, results_dir)
        elif selection == "Exit":
            console.print("\n[bold magenta]Thank you for hacking with CIA![/bold magenta]\n")
            break
        else:
            run_tool(selection, image_file, results_dir)


if __name__ == "__main__":
    main()
