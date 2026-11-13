"""
Remote ZIP & RAR Inspector & Virtual File Explorer
Self-contained Flask application for inspecting, exploring, previewing, and
streaming individual files from remote ZIP and RAR archives without downloading the entire package.
"""
import os
import re
import math
import time
import json
import zlib
import queue
import shutil
import struct
import zipfile
import tempfile
import threading
import subprocess
import mimetypes
import urllib.parse
from flask import Flask, render_template_string, request, Response, stream_with_context, jsonify
import requests
from remotezip import RemoteZip, RemoteFetcher
import fnmatch
from concurrent.futures import ThreadPoolExecutor, as_completed
# Optional Deflate64 decompression support
try:
    import zipfile_deflate64
except ImportError:
    pass

# ======================================================================
# 1. APPLY MONKEY-PATCH FOR ZSTANDARD (METHOD 93) COMPRESSION (ZIP)
# ======================================================================
ZIP_ZSTANDARD = 93
try:
    import zstandard

    class ZstdDecompressorWrapper:
        def __init__(self, zstd_dict=None):
            self._dctx = zstandard.ZstdDecompressor(dict_data=zstd_dict)
            self._dobj = self._dctx.decompressobj()

        def decompress(self, data, *args, **kwargs):
            return self._dobj.decompress(data)

        def flush(self):
            return getattr(self._dobj, 'flush', lambda: b'')()

        @property
        def eof(self):
            return getattr(self._dobj, 'eof', False)

        @property
        def unused_data(self):
            return getattr(self._dobj, 'unused_data', b'')

        @property
        def unconsumed_tail(self):
            return getattr(self._dobj, 'unconsumed_tail', b'')

    _orig_check_compression = getattr(zipfile, '_check_compression', None)
    if _orig_check_compression:
        def my_check_compression(compression):
            if compression == ZIP_ZSTANDARD:
                return
            _orig_check_compression(compression)
        zipfile._check_compression = my_check_compression

    _orig_get_decompressor = getattr(zipfile, '_get_decompressor', None)
    if _orig_get_decompressor:
        def my_get_decompressor(compress_type):
            if compress_type == ZIP_ZSTANDARD:
                return ZstdDecompressorWrapper()
            return _orig_get_decompressor(compress_type)
        zipfile._get_decompressor = my_get_decompressor
except ImportError:
    pass


# ======================================================================
# 2. DEFINITIONS, SIGNATURES & UTILITY HELPERS
# ======================================================================
RAR4_SIG = b"Rar!\x1a\x07\x00"
RAR5_SIG = b"Rar!\x1a\x07\x01\x00"

RAR_MAX_ENTRIES = 500000
RAR_QO_MAX_BYTES = 512 * 1024 * 1024        # refuse absurd Quick Open sizes
RAR_EXTRACT_MAX_BYTES = 75 * 1024 * 1024    # how far into a RAR we will fetch to unpack one entry
RAR_EXTRACT_TIMEOUT = 60                    # seconds for the external extractor
STORED_LABEL = "Stored (No compression)"

EXT_CATEGORIES = {
    'image': {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico', '.bmp', '.avif', '.tiff'},
    'audio': {'.mp3', '.wav', '.ogg', '.m4a', '.flac', '.aac', '.opus'},
    'code': {'.py', '.js', '.ts', '.html', '.css', '.json', '.yaml', '.yml', '.xml', '.sh',
             '.bat', '.ps1', '.c', '.cpp', '.h', '.hpp', '.rs', '.go', '.java', '.php',
             '.rb', '.sql', '.toml', '.ini', '.cfg', '.conf', '.env', '.vue', '.jsx', '.tsx', '.lua',
             '.reg', '.inf'},
    'doc': {'.txt', '.md', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.csv', '.log', '.rtf',
            '.nfo', '.diz', '.url'},
    'archive': {'.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar', '.iso', '.zst'}
}

DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 RemoteInspector/2.0'
}

NETWORK_TIMEOUT = (10, 30)

# Reusable keep-alive HTTP session pool (LIFO keeps the warmest TLS socket first)
_SESSION_POOL = queue.LifoQueue(maxsize=16)
_RESOLVED_URL_CACHE = {}
_PREVIEW_CACHE = {}
_PREVIEW_CACHE_LOCK = threading.Lock()

from contextlib import contextmanager

@contextmanager
def borrow_session():
    try:
        s = _SESSION_POOL.get_nowait()
    except queue.Empty:
        s = requests.Session()
        s.headers.update(DEFAULT_HEADERS)
    try:
        yield s
        try:
            _SESSION_POOL.put_nowait(s)
        except queue.Full:
            s.close()
    except Exception:
        s.close()
        raise


def resolve_download_url(url: str) -> str:
    if not url:
        return url
    if url in _RESOLVED_URL_CACHE:
        return _RESOLVED_URL_CACHE[url]
    if "dlproxy" in url.lower() or "/download/" in url.lower():
        return url
    if "github.com" in url.lower() or "ankergames" in url.lower():
        headers = {
            "User-Agent": DEFAULT_HEADERS["User-Agent"],
            "Accept": "*/*"
        }
        try:
            with borrow_session() as s:
                with s.get(url, headers=headers, stream=True, allow_redirects=True, timeout=12) as response:
                    direct_url = response.url
                    if direct_url and direct_url != url:
                        _RESOLVED_URL_CACHE[url] = direct_url
                        return direct_url
        except Exception as e:
            print(f"Error resolving redirect URL: {e}")
    return url


def to_dos_time(dt):
    if not dt:
        return 0, 0
    year, month, day, hour, minute, second = dt[:6]
    if year < 1980:
        year = 1980
    dos_date = ((year - 1980) << 9) | (month << 5) | day
    dos_time = (hour << 11) | (minute << 5) | (second // 2)
    return dos_time, dos_date


def parse_date_str(s):
    """'YYYY-MM-DD HH:MM:SS' -> tuple usable by to_dos_time (falls back to 1980-01-01)."""
    try:
        d, t = s.split(' ')
        y, mo, da = (int(x) for x in d.split('-'))
        h, mi, se = (int(x) for x in t.split(':'))
        return (y, max(1, mo), max(1, da), h, mi, se)
    except Exception:
        return (1980, 1, 1, 0, 0, 0)


def infer_category(ext):
    ext_lower = ext.lower()
    for cat, exts in EXT_CATEGORIES.items():
        if ext_lower in exts:
            return cat
    return 'binary'


def format_size(size_bytes):
    if size_bytes <= 0:
        return "0 B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB")
    i = min(len(size_name) - 1, int(math.floor(math.log(size_bytes, 1024))))
    if i == 0:
        return f"{size_bytes} B"
    p = math.pow(1024, i)
    return f"{round(size_bytes / p, 2)} {size_name[i]}"


def get_compress_method_name(method_id):
    mapping = {
        0: "Stored (No compression)",
        1: "Shrunk",
        6: "Imploded",
        8: "Deflated",
        9: "Deflate64",
        12: "BZIP2",
        14: "LZMA",
        93: "Zstandard"
    }
    return mapping.get(method_id, f"Unknown ({method_id})")


def generate_hex_dump(data_bytes):
    lines = []
    for i in range(0, len(data_bytes), 16):
        chunk = data_bytes[i:i+16]
        offset = f"{i:08X}"
        hex_bytes = " ".join(f"{b:02X}" for b in chunk)
        hex_padding = " " * ((16 - len(chunk)) * 3)
        ascii_chars = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append({
            "offset": offset,
            "hex": hex_bytes + hex_padding,
            "ascii": ascii_chars
        })
    return lines


# ======================================================================
# 3. HIGH-PERFORMANCE IN-MEMORY CACHE & SCAN JOB REGISTRY
# ======================================================================
ZIP_CACHE = {}
ZIP_CACHE_LOCK = threading.Lock()
MAX_CACHE_ENTRIES = 6

RAR_SCANS = {}            # scan_id -> {'stop': threading.Event, 'url': str}
RAR_SCANS_LOCK = threading.Lock()


# ======================================================================
# 4. REMOTE RANGE READER & RAR ENGINE (PARSER, QUICK OPEN, SCANNER)
# ======================================================================
class ScanStopped(Exception):
    """Raised inside a scan when the user pressed Stop (or the browser went away)."""


class RangeReader:
    """Random-access reader over HTTP Range requests with read-ahead caching.
    Stop-aware: the stop event is checked before every request and between network chunks."""

    def __init__(self, url, window=256 * 1024, timeout=NETWORK_TIMEOUT, stop=None):
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        self.url = url
        self.window = window
        self.timeout = timeout
        self.stop = stop or threading.Event()
        self.requests_count = 0
        self.bytes_read = 0
        self.buf = b""
        self.buf_off = 0
        self.size = 0
        self.limit = None
        self._hits = 0

    def check_stop(self):
        if self.stop.is_set():
            raise ScanStopped()

    def probe(self):
        self.check_stop()
        r = self.session.get(
            self.url,
            headers={"Range": "bytes=0-16383", "Accept-Encoding": "identity"},
            stream=True,
            timeout=self.timeout
        )
        try:
            if r.status_code != 206:
                raise IOError(f"Server answered HTTP {r.status_code} (expected 206 Partial Content)")
            tail = r.headers.get("Content-Range", "").rsplit("/", 1)[-1]
            if not tail.isdigit():
                raise IOError(f"Missing total file size in Content-Range header: {r.headers.get('Content-Range')}")
            self.requests_count += 1
            self.size = int(tail)
            self.url = r.url
            data = b"".join(r.iter_content(16384))
            self.bytes_read += len(data)
            self.buf = data
            self.buf_off = 0
            return self.size
        finally:
            r.close()

    def _get(self, offset, length):
        last_err = None
        for attempt in range(3):
            self.check_stop()
            try:
                r = self.session.get(
                    self.url,
                    timeout=self.timeout,
                    stream=True,
                    headers={"Range": f"bytes={offset}-{offset + length - 1}", "Accept-Encoding": "identity"}
                )
                try:
                    self.requests_count += 1
                    if r.status_code != 206:
                        raise OSError(f"HTTP {r.status_code} (expected 206)")
                    parts = []
                    for chunk in r.iter_content(64 * 1024):
                        self.check_stop()          # abandon a slow-but-flowing download quickly
                        parts.append(chunk)
                    data = b"".join(parts)
                finally:
                    r.close()
                if len(data) != length:
                    raise OSError(f"Short read: got {len(data)} of {length} bytes")
                self.bytes_read += length
                return data
            except ScanStopped:
                raise
            except Exception as e:
                last_err = e
                if self.stop.wait(0.4 * (attempt + 1)):
                    raise ScanStopped()
        raise OSError(f"Range request failed at offset {offset}: {last_err}")

    def read(self, offset, n):
        cap = min(self.size, self.limit) if self.limit else self.size
        n = min(n, cap - offset)
        if n <= 0:
            return b""
        end = offset + n
        if self.buf_off <= offset and end <= self.buf_off + len(self.buf):
            self._hits += 1
            if not self.limit and self._hits >= 6:
                self.window = min(1024 * 1024, self.window * 2)  # dense small files -> scale up to 1 MB
                self._hits = 0
            return self.buf[offset - self.buf_off:end - self.buf_off]
        if not self.limit and self.buf and self._hits == 0:
            self.window = max(64 * 1024, self.window // 2)      # sparse big jumps -> shrink down to 64 KB
        self._hits = 0
        fetch = min(max(n, self.window), cap - offset)
        self.buf = self._get(offset, fetch)
        self.buf_off = offset
        return self.buf[:n]


def vint(buf, pos):
    result = shift = 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("bad vint")
    raise ValueError("vint truncated")


class Progress:
    """Throttled progress events for the SSE stream."""

    def __init__(self, rd, emit):
        self.rd, self.emit, self.last = rd, emit, 0.0

    def tick(self, offset, count, current="", percent=None, force=False):
        now = time.time()
        if not force and now - self.last < 0.12:
            return
        self.last = now
        total = self.rd.size
        pct = percent if percent is not None else round(offset / max(1, total) * 100, 1)
        self.emit({
            "type": "progress",
            "percent": min(100.0, max(0.0, pct)),
            "offset": min(offset, total),
            "offset_str": format_size(min(offset, total)),
            "total_size": total,
            "total_size_str": format_size(total),
            "count": count,
            "requests": self.rd.requests_count,
            "bytes_read": self.rd.bytes_read,
            "bytes_read_str": format_size(self.rd.bytes_read),
            "current_file": current,
        })


# ---------------------------- RAR5 headers ----------------------------
def rar5_parse(blk):
    """Parse one RAR5 header. `blk` starts at the CRC32 field and must hold the whole header."""
    hsize, p = vint(blk, 4)
    total = p + hsize
    if hsize == 0 or total > len(blk):
        raise ValueError("truncated header")
    htype, pos = vint(blk, p)
    hflags, pos = vint(blk, pos)
    extra = data_size = 0
    if hflags & 0x1:
        extra, pos = vint(blk, pos)
    if hflags & 0x2:
        data_size, pos = vint(blk, pos)
    stored_crc = struct.unpack_from("<I", blk, 0)[0]
    return {"blk": blk, "total": total, "htype": htype, "hflags": hflags,
            "extra": extra, "data_size": data_size, "pos": pos,
            "crc_ok": (zlib.crc32(blk[4:total]) & 0xFFFFFFFF) == stored_crc}


def rar5_header_at(rd, off):
    head = rd.read(off, 16)
    if len(head) < 8:
        return None
    hsize, p = vint(head, 4)
    if hsize == 0 or hsize > 2 * 1024 * 1024:
        raise ValueError(f"implausible header size {hsize}")
    blk = rd.read(off, p + hsize)
    if len(blk) < p + hsize:
        raise ValueError("archive truncated inside a header")
    return rar5_parse(blk)


def rar5_extra_records(h):
    """Yield (record_type, blk, body_pos, record_end) for the header's extra area (the LAST bytes of a header)."""
    blk, total = h['blk'], h['total']
    epos = total - h['extra']
    while h['extra'] and epos < total:
        rsize, q = vint(blk, epos)
        rtype, r = vint(blk, q)
        yield rtype, blk, r, q + rsize
        epos = q + rsize


def rar5_file_fields(h):
    """Fields shared by file headers (type 2) and service headers (type 3)."""
    blk, pos = h['blk'], h['pos']
    fflags, pos = vint(blk, pos)
    size, pos = vint(blk, pos)
    _attr, pos = vint(blk, pos)
    mtime_str, crc = "N/A", None
    if fflags & 0x2:
        mt = struct.unpack_from("<I", blk, pos)[0]
        pos += 4
        try:
            mtime_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(mt))
        except (OverflowError, OSError, ValueError):
            pass
    if fflags & 0x4:
        crc = struct.unpack_from("<I", blk, pos)[0]
        pos += 4
    comp, pos = vint(blk, pos)
    _host, pos = vint(blk, pos)
    nlen, pos = vint(blk, pos)
    name = blk[pos:pos + nlen].decode("utf-8", "replace").replace("\\", "/")
    enc = any(rtype == 1 for rtype, _b, _p, _e in rar5_extra_records(h))
    return {
        "name": name, "size": size, "packed": h['data_size'],
        "method": (comp >> 7) & 0x7, "dir": bool(fflags & 0x1),
        "solid": bool(comp & 0x40), "enc": enc,
        "prev": bool(h['hflags'] & 0x4), "next": bool(h['hflags'] & 0x8),
        "crc": crc, "date": mtime_str,
    }


def rar5_main_info(h, info):
    aflags, _ = vint(h['blk'], h['pos'])
    info["volume"] = bool(aflags & 0x1)
    info["solid"] = bool(aflags & 0x4)


def detect_rar5_quick_open(data):
    """Return the absolute file offset of the Quick Open service header, or None.
    The locator lives in the main header's EXTRA AREA, which is the LAST `extra` bytes of the header."""
    if not data.startswith(RAR5_SIG) or len(data) < 24:
        return None
    try:
        hsize, p = vint(data, 12)               # 8-byte signature + 4-byte CRC
        total = p + hsize                       # absolute end of the main header
        htype, pos = vint(data, p)
        if htype != 1 or total > len(data):
            return None
        hflags, pos = vint(data, pos)
        extra = 0
        if hflags & 0x1:
            extra, pos = vint(data, pos)
        if hflags & 0x2:
            _, pos = vint(data, pos)
        epos = total - extra
        while extra and epos < total:
            rsize, q = vint(data, epos)
            rtype, r = vint(data, q)
            if rtype == 1:                      # locator record
                lflags, r = vint(data, r)
                if lflags & 0x1:                # quick open offset present
                    raw_off, r = vint(data, r)
                    if raw_off:
                        return 8 + raw_off      # relative to the start of the main header
            epos = q + rsize
    except Exception:
        pass
    return None


def rar5_walk(rd, start, end, info, entries, prog):
    """Walk RAR5 headers from `start` until position >= `end` (or the end-of-archive header).
    Returns the final position; sets info['walk_failed'] on a parse problem."""
    off = start
    while off < end and len(entries) < RAR_MAX_ENTRIES:
        rd.check_stop()
        try:
            h = rar5_header_at(rd, off)
        except (IndexError, struct.error, ValueError) as e:
            info["notes"].append(f"Header parse error at offset {off}: {e}")
            info["walk_failed"] = True
            break
        if h is None:
            info["walk_failed"] = True
            break
        if not h['crc_ok']:
            info["bad_crc"] = info.get("bad_crc", 0) + 1
        data_off, t = off + h['total'], h['htype']
        if t == 4:                                            # archive encryption header
            info["enc_headers"] = True
            info["walk_failed"] = True
            break
        if t == 1:
            rar5_main_info(h, info)
        elif t == 2:
            try:
                f = rar5_file_fields(h)
            except (IndexError, struct.error, ValueError) as e:
                info["notes"].append(f"File header parse error at offset {off}: {e}")
                info["walk_failed"] = True
                break
            f["off"], f["hpos"] = data_off, off
            entries.append(f)
            prog.tick(off, len(entries), f["name"])
        elif t == 5:                                          # end of archive
            return max(end, off)
        off = data_off + h['data_size']
    prog.tick(off, len(entries), force=False)
    return off


def rar4_walk(rd, info, entries, prog):
    off = len(RAR4_SIG)
    while off + 7 <= rd.size and len(entries) < RAR_MAX_ENTRIES:
        rd.check_stop()
        try:
            base = rd.read(off, 7)
            if len(base) < 7:
                break
            _crc, htype, hflags, hsize = struct.unpack("<HBHH", base)
            if hsize < 7:
                info["notes"].append(f"Bad header size at offset {off}; stopped there.")
                break
            blk = rd.read(off, hsize)
            if len(blk) < hsize:
                info["notes"].append("Archive truncated inside a header.")
                break
            add = struct.unpack_from("<I", blk, 7)[0] if hflags & 0x8000 else 0
            data_off = off + hsize

            if htype == 0x73:                                 # main header
                info["volume"] = bool(hflags & 0x1)
                info["solid"] = bool(hflags & 0x8)
                if hflags & 0x80:
                    info["enc_headers"] = True
                    break
            elif htype == 0x74:                               # file header
                (pack, unp, _host, crc32, ftime, _ver, method, nsz,
                 _attr) = struct.unpack_from("<IIBIIBBHI", blk, 7)
                pos = 32
                if hflags & 0x100:                            # 64-bit sizes
                    hp, hu = struct.unpack_from("<II", blk, pos)
                    pack |= hp << 32
                    unp |= hu << 32
                    pos += 8
                add = pack
                name = decode_rar4_name(blk[pos:pos + nsz])
                dt_str = (f"{((ftime >> 25) & 0x7F) + 1980:04d}-{(ftime >> 21) & 0x0F:02d}-{(ftime >> 16) & 0x1F:02d} "
                          f"{(ftime >> 11) & 0x1F:02d}:{(ftime >> 5) & 0x3F:02d}:{(ftime & 0x1F) * 2:02d}")
                entries.append({
                    "name": name, "size": unp, "packed": pack,
                    "method": max(0, method - 0x30),
                    "dir": (hflags & 0xE0) == 0xE0, "solid": bool(hflags & 0x10),
                    "enc": bool(hflags & 0x4), "prev": bool(hflags & 0x1),
                    "next": bool(hflags & 0x2), "crc": crc32, "date": dt_str,
                    "off": data_off, "hpos": off
                })
                prog.tick(off, len(entries), name)
            elif htype == 0x7B:                               # end of archive
                break
            off = data_off + add
        except (IndexError, struct.error) as e:
            info["notes"].append(f"Header parse error at offset {off}: {e}")
            break


def decode_rar4_name(raw):
    raw = raw.split(b"\0")[0]
    try:
        return raw.decode("utf-8").replace("\\", "/")
    except UnicodeDecodeError:
        return raw.decode("cp437", "replace").replace("\\", "/")


# ---------------------------- RAR5 Quick Open ----------------------------
def _qo_records(data, qo_offset, extra_vints, limit=None):
    """Split the QO data area into (header_position, header_copy) pairs.
    Record = CRC32, size vint, flags vint, offset vint, [extra_vints x vint], header copy.
    The offset counts BACK from the QO header to the original header."""
    out, pos, bad_crc = [], 0, 0
    while pos + 5 <= len(data) and (limit is None or len(out) < limit):
        stored = struct.unpack_from("<I", data, pos)[0]
        size, p = vint(data, pos + 4)
        if size == 0 or p + size > len(data):
            break
        if (zlib.crc32(data[pos + 4:p + size]) & 0xFFFFFFFF) != stored:
            bad_crc += 1
        _flags, q = vint(data, p)
        rel, q = vint(data, q)
        for _ in range(extra_vints):
            _, q = vint(data, q)
        out.append((qo_offset - rel, data[q:p + size]))
        pos = p + size
    return out, bad_crc


def _qo_header_ok(hdr, strict=False):
    """A cached copy must be exactly one whole header. `strict` (layout detection) also demands a file/service type."""
    try:
        h = rar5_parse(hdr)
        return h['total'] == len(hdr) and (not strict or h['htype'] in (2, 3))
    except Exception:
        return False


class _BufReader:
    """In-memory slice reader for a pre-fetched [base, base + len(buf)) gap group."""
    def __init__(self, base, buf, stop):
        self.base, self.buf, self.stop = base, buf, stop

    def check_stop(self):
        if self.stop.is_set():
            raise ScanStopped()

    def read(self, offset, n):
        rel = offset - self.base
        return b"" if rel < 0 or rel >= len(self.buf) else self.buf[rel:rel + n]


def rar5_quick_open_scan(rd, qo_offset, info, entries, prog):
    """Fill `entries` from the Quick Open cache, then walk ONLY the byte ranges the cache doesn't cover.
    Returns True on success. On any doubt it returns False and the caller does a full header walk."""
    notes = info["notes"]

    def fail(msg):
        notes.append(msg + " Falling back to a full header walk.")
        return False

    try:
        main = rar5_header_at(rd, 8)
        if not main or main['htype'] != 1:
            return fail("Main archive header not readable.")
        rar5_main_info(main, info)
        main_end = 8 + main['total'] + main['data_size']
        if not (main_end <= qo_offset < rd.size):
            return fail("Quick Open offset points outside the archive.")
        qo = rar5_header_at(rd, qo_offset)
        if not qo or qo['htype'] != 3:
            return fail("Quick Open offset did not land on a service header.")
        qf = rar5_file_fields(qo)
        if qf['name'] != "QO" or qf['method'] != 0 or qf['enc']:
            return fail("Quick Open record is compressed, encrypted or unrecognised.")
        data_off, data_size = qo_offset + qo['total'], qo['data_size']
        qo_end = data_off + data_size
        if data_size <= 0 or data_size > RAR_QO_MAX_BYTES or qo_end > rd.size:
            return fail("Quick Open size is implausible.")

        chunks, got = [], 0
        while got < data_size:
            n = min(1 << 20, data_size - got)
            piece = rd.read(data_off + got, n)
            if len(piece) != n:
                return fail("Quick Open data was cut short.")
            chunks.append(piece)
            got += n
            prog.tick(got, 0, f"Downloading Quick Open index ({format_size(got)} / {format_size(data_size)})",
                      percent=5 + 70 * got / data_size, force=True)
        data = b"".join(chunks)

        # The record layout is not formally documented: accept whichever variant yields a valid header copy.
        extra_vints = None
        for ev in (0, 1):
            try:
                recs, _ = _qo_records(data, qo_offset, ev, limit=1)
            except (IndexError, ValueError):
                continue
            if recs and 8 < recs[0][0] < qo_offset and _qo_header_ok(recs[0][1], strict=True):
                extra_vints = ev
                break
        if extra_vints is None:
            return fail("Quick Open records did not decode to valid headers.")
        cached, rec_bad_crc = _qo_records(data, qo_offset, extra_vints)
        if not cached:
            return fail("Quick Open record was empty.")

        spans, cached_entries, hdr_bad_crc = [(8, main_end), (qo_offset, qo_end)], [], 0
        for hpos, hdr in cached:
            if not (8 < hpos < qo_offset) or not _qo_header_ok(hdr):
                return fail("Quick Open holds a record that is not a header.")
            h = rar5_parse(hdr)
            if h['htype'] == 1:                 # main header copy: already covered by its own span
                continue
            hdr_bad_crc += 0 if h['crc_ok'] else 1
            spans.append((hpos, hpos + h['total'] + h['data_size']))
            if h['htype'] == 2:
                f = rar5_file_fields(h)
                f["off"], f["hpos"] = hpos + h['total'], hpos
                cached_entries.append(f)
        if not cached_entries:
            return fail("Quick Open held no file headers.")

        # Validate against the REAL archive bytes (first + last cached header).
        ordered = sorted(cached, key=lambda t: t[0])
        for hpos, hdr in (ordered[0], ordered[-1]):
            live = rd.read(hpos, min(len(hdr), 32))
            if live != hdr[:len(live)]:
                return fail("Quick Open cache did not match the archive bytes.")

        # Walk every gap the cache does not cover, so the listing is complete by construction.
        spans.sort()
        for i in range(1, len(spans)):
            if spans[i][0] < spans[i - 1][1]:
                return fail("Quick Open headers overlap.")
        entries.extend(cached_entries)

        # Collect all uncached gaps (including the tail after the last span)
        gaps = [(spans[i - 1][1], spans[i][0]) for i in range(1, len(spans)) if spans[i][0] > spans[i - 1][1]]
        if spans[-1][1] < rd.size:
            gaps.append((spans[-1][1], rd.size))

        if gaps:
            # Coalesce nearby small gaps (<= 32 KB apart, <= 256 KB total span) into single range reads
            groups = []
            for a, b in gaps:
                if (groups and groups[-1][-1][1] + 32 * 1024 >= a
                        and b - groups[-1][0][0] <= 256 * 1024):
                    groups[-1].append((a, b))
                else:
                    groups.append([(a, b)])

            noop_prog = type("NoopProg", (), {"tick": lambda *a, **kw: None})()
            total_gap_bytes = sum(b - a for a, b in gaps)
            done_bytes = 0
            lock = threading.Lock()
            workers = min(10, len(groups))
            rpool = queue.Queue()
            readers = []
            for _ in range(workers):
                wrd = RangeReader(rd.url, window=128 * 1024, timeout=rd.timeout, stop=rd.stop)
                wrd.size = rd.size
                readers.append(wrd)
                rpool.put(wrd)

            def walk_group(grp):
                wrd = rpool.get()
                req0, bytes0 = wrd.requests_count, wrd.bytes_read
                local_entries, local_info = [], {"notes": []}
                try:
                    g_start, g_end = grp[0][0], grp[-1][1]
                    if g_end - g_start <= 256 * 1024:
                        buf = wrd._get(g_start, g_end - g_start)
                        brd = _BufReader(g_start, buf, rd.stop)
                        for a, b in grp:
                            pos = rar5_walk(brd, a, b, local_info, local_entries, noop_prog)
                            if local_info.get("walk_failed") or pos != b:
                                return None, local_info, a
                    else:
                        for a, b in grp:
                            wrd.limit = b
                            pos = rar5_walk(wrd, a, b, local_info, local_entries, noop_prog)
                            wrd.limit = None
                            if local_info.get("walk_failed") or pos != b:
                                return None, local_info, a
                    return local_entries, local_info, None
                finally:
                    with lock:
                        rd.requests_count += wrd.requests_count - req0
                        rd.bytes_read += wrd.bytes_read - bytes0
                    rpool.put(wrd)

            try:
                with ThreadPoolExecutor(max_workers=workers) as ex:
                    futs = {ex.submit(walk_group, g): sum(b - a for a, b in g) for g in groups}
                    for fut in as_completed(futs):
                        rd.check_stop()
                        res_entries, linfo, bad_off = fut.result()
                        if res_entries is None:
                            for f in futs:
                                f.cancel()
                            if linfo.get("enc_headers"):
                                info["enc_headers"] = True
                            del entries[:]
                            return fail(f"Could not walk an uncached gap at offset {bad_off}.")
                        entries.extend(res_entries)
                        info["bad_crc"] = info.get("bad_crc", 0) + linfo.get("bad_crc", 0)
                        info["notes"].extend(linfo["notes"])
                        if "volume" in linfo:
                            info["volume"] = linfo["volume"]
                        if "solid" in linfo:
                            info["solid"] = linfo["solid"]
                        done_bytes += futs[fut]
                        pct = 75 + 24 * (done_bytes / max(1, total_gap_bytes))
                        prog.tick(done_bytes, len(entries),
                                  res_entries[-1]["name"] if res_entries else "",
                                  percent=pct)
            finally:
                for r in readers:
                    r.session.close()

        entries.sort(key=lambda e: e["hpos"])
        notes.append(f"Listing built from the Quick Open index: {len(cached_entries)} cached entries, "
                     f"{len(entries) - len(cached_entries)} found in {len(gaps)} uncached gap(s), "
                     f"{rd.requests_count} requests.")
        if rec_bad_crc or hdr_bad_crc:
            notes.append(f"CRC mismatches: {rec_bad_crc} index record(s), {hdr_bad_crc} header(s).")
        return True
    except ScanStopped:
        raise
    except (IndexError, struct.error, ValueError) as e:
        del entries[:]
        return fail(f"Quick Open failed ({e}).")


def scan_rar(rd, info, entries, emit, use_quick_open=True):
    """Full RAR scan: Quick Open fast path for RAR5, otherwise a sequential header walk."""
    prog = Progress(rd, emit)
    if info["fmt"] == "RAR5":
        done = False
        if use_quick_open:
            qo_offset = detect_rar5_quick_open(rd.read(0, min(4096, rd.size)))
            if qo_offset:
                emit({"type": "qo_found", "offset": qo_offset})
                done = rar5_quick_open_scan(rd, qo_offset, info, entries, prog)
                info["quick_open"] = done
                if not done:
                    del entries[:]
                    info.pop("walk_failed", None)
                    emit({"type": "qo_failed"})
            else:
                info["notes"].append("No Quick Open record in this archive; walked every header instead.")
        else:
            info["notes"].append("Quick Open skipped on request; walked every header.")
        if not done:
            rar5_walk(rd, len(RAR5_SIG), rd.size, info, entries, prog)
    else:
        rar4_walk(rd, info, entries, prog)
    if info.get("bad_crc"):
        info["notes"].append(f"{info['bad_crc']} header(s) failed the CRC check (damaged archive or unusual headers).")
    if info.get("volume") or any(e["prev"] or e["next"] for e in entries):
        info["notes"].append("Multi-volume set: only entries starting in THIS part are listed; "
                             "entries split across volumes cannot be downloaded or previewed.")
    if info.get("solid") or any(e["solid"] for e in entries):
        info["notes"].append("Solid archive: listing works, but unpacking one file needs all earlier data.")


def populate_rar_cache(url, entries, info, is_partial=False):
    """Converts scanned RAR entries into the virtual filesystem tree and flat file list."""
    tree = {"": {"file_ids": [], "subfolders": set()}}
    flat_files = []
    total_uncomp_size = 0
    total_comp_size = 0

    def add_dirs(parts):
        for i, part in enumerate(parts):
            parent = "/".join(parts[:i])
            tree.setdefault(parent, {"file_ids": [], "subfolders": set()})["subfolders"].add(part)

    for entry in entries:
        parts = [p for p in entry['name'].replace('\\', '/').split('/') if p]
        if not parts:
            continue
        if entry['dir']:
            add_dirs(parts)
            continue

        filename_only = parts[-1]
        parent_path = "/".join(parts[:-1])
        add_dirs(parts[:-1])

        file_size = entry['size']
        comp_size = entry['packed']
        total_uncomp_size += file_size
        total_comp_size += comp_size

        ratio = 0
        if file_size > 0:
            ratio = max(0, round((1 - (comp_size / file_size)) * 100, 1))

        _, ext = os.path.splitext(filename_only)
        file_id = len(flat_files)
        crc = entry.get('crc')

        flat_files.append({
            'id': file_id,
            'name': "/".join(parts),
            'filename_only': filename_only,
            'folder_path': parent_path if parent_path else "/",
            'size': file_size,
            'size_str': format_size(file_size),
            'comp_size': comp_size,
            'comp_size_str': format_size(comp_size),
            'ratio': f"{ratio}%",
            'ratio_num': ratio,
            'crc32': f"0x{crc:08X}" if crc is not None else "n/a",
            'crc_int': crc,
            'encrypted': bool(entry.get('enc', False)),
            'method': STORED_LABEL if entry['method'] == 0 else f"RAR (m{entry['method']})",
            'stored': entry['method'] == 0,
            'date': entry.get('date', 'N/A'),
            'category': infer_category(ext),
            'archive_type': 'rar',
            'offset': entry.get('off', 0),
            'hpos': entry.get('hpos', 0),
            'solid': entry.get('solid', False),
            'prev': entry.get('prev', False),
            'next': entry.get('next', False),
        })
        tree.setdefault(parent_path, {"file_ids": [], "subfolders": set()})["file_ids"].append(file_id)

    overall_ratio = 0
    if total_uncomp_size > 0:
        overall_ratio = round((1 - (total_comp_size / total_uncomp_size)) * 100, 1)

    archive_stats = {
        'total_files': len(flat_files),
        'total_size': format_size(total_uncomp_size),
        'total_comp_size': format_size(total_comp_size),
        'total_ratio': f"{overall_ratio}%",
        'archive_format': info.get('fmt', 'RAR'),
        'solid': bool(info.get('solid', False)),
        'volume': bool(info.get('volume', False)),
        'quick_open': bool(info.get('quick_open', False)),
        'partial': is_partial,
        'notes': list(info.get('notes', [])),
    }

    with ZIP_CACHE_LOCK:
        if url not in ZIP_CACHE and len(ZIP_CACHE) >= MAX_CACHE_ENTRIES:
            oldest = min(ZIP_CACHE.keys(), key=lambda k: ZIP_CACHE[k]['timestamp'])
            ZIP_CACHE.pop(oldest, None)
        ZIP_CACHE[url] = {
            'tree': tree,
            'flat_files': flat_files,
            'archive_stats': archive_stats,
            'timestamp': time.time(),
            'archive_type': 'rar'
        }


def rar_scan_worker(url, scan_id, q, stop, use_quick_open):
    """Runs one scan on a background thread and talks to the SSE generator through a queue."""
    emit = q.put
    info = {"fmt": "RAR", "solid": False, "volume": False, "enc_headers": False,
            "quick_open": False, "notes": []}
    entries = []
    try:
        rd = RangeReader(url, stop=stop)
        total_size = rd.probe()
        magic = rd.read(0, 16)
        info["fmt"] = "RAR5" if magic.startswith(RAR5_SIG) else ("RAR4" if magic.startswith(RAR4_SIG) else "RAR")
        if info["fmt"] == "RAR":
            raise ValueError("Not a RAR archive (bad signature). Use the .rar / .part1.rar link, not a landing page.")
        emit({"type": "init", "fmt": info["fmt"], "size": total_size, "size_str": format_size(total_size)})

        try:
            scan_rar(rd, info, entries, emit, use_quick_open)
        except ScanStopped:
            pass
        stopped = stop.is_set()
        if stopped:
            info["notes"].append(f"Stopped by user: partial listing ({len(entries)} entries).")
        if info["enc_headers"]:
            raise ValueError("Headers are encrypted (-hp): names and sizes cannot be read without the password.")
        if not entries:
            raise ValueError("No entries were found" + (" before the scan was stopped." if stopped else "."))

        populate_rar_cache(url, entries, info, is_partial=stopped)
        if not stopped:
            Progress(rd, emit).tick(rd.size, len(entries), "Done", percent=100.0, force=True)
        emit({"type": "stopped" if stopped else "complete", "count": len(entries)})
    except ScanStopped:
        emit({"type": "error", "message": "Scan stopped before any entries were read."})
    except Exception as e:
        print(f"[rar-scan] {type(e).__name__}: {e}")
        emit({"type": "error", "message": str(e)})
    finally:
        q.put(None)


# ---------------------------- RAR entry helpers ----------------------------
def rar_entry_blocker(f_obj):
    """Reason an entry's DATA can't be read from this single URL, or None."""
    if f_obj.get('encrypted'):
        return "File is password protected"
    if f_obj.get('prev') or f_obj.get('next'):
        return "This entry is split across RAR volumes; its data is not contiguous in this one file."
    return None


_EXTRACTOR_CACHE = {}


def find_rar_extractor():
    """Returns (kind, path) for an external tool that can read RAR, or None. Override with RAR_EXTRACTOR env var."""
    if 'tool' in _EXTRACTOR_CACHE:
        return _EXTRACTOR_CACHE['tool']
    candidates = [os.environ.get("RAR_EXTRACTOR", "")]
    candidates += [shutil.which(n) or "" for n in ("7zz", "7z", "unrar")]
    candidates += [r"C:\Program Files\7-Zip\7z.exe", r"C:\Program Files (x86)\7-Zip\7z.exe",
                   r"C:\Program Files\WinRAR\UnRAR.exe"]
    tool = None
    for c in candidates:
        if c and os.path.exists(c):
            tool = ("unrar" if "unrar" in os.path.basename(c).lower() else "7z", c)
            break
    _EXTRACTOR_CACHE['tool'] = tool
    return tool


def _rar_slice_wrappers(fmt, is_solid):
    """Build minimal valid RAR5/RAR4 archive head and tail around a sliced solid block."""
    if fmt == "RAR5":
        mb = bytes([1, 0, 4 if is_solid else 0])
        mh = struct.pack('<I', zlib.crc32(bytes([len(mb)]) + mb) & 0xFFFFFFFF) + bytes([len(mb)]) + mb
        eb = bytes([5, 0, 0])
        eh = struct.pack('<I', zlib.crc32(bytes([len(eb)]) + eb) & 0xFFFFFFFF) + bytes([len(eb)]) + eb
        return RAR5_SIG + mh, eh
    if fmt == "RAR4":
        mb = struct.pack('<BHHHI', 0x73, 0x0008 if is_solid else 0, 13, 0, 0)
        mh = struct.pack('<H', zlib.crc32(mb) & 0xFFFF) + mb
        eb = struct.pack('<BHH', 0x7B, 0x4000, 7)
        eh = struct.pack('<H', zlib.crc32(eb) & 0xFFFF) + eb
        return RAR4_SIG + mh, eh
    return b"", b""


def _find_slice_start(url, f_obj):
    """Find the header offset where this entry's compression block begins."""
    if not f_obj.get('solid'):
        return f_obj.get('hpos', 0), False
    with ZIP_CACHE_LOCK:
        cached = ZIP_CACHE.get(url)
        files = list(cached['flat_files']) if cached else []
    for i in range(f_obj['id'], -1, -1):
        cand = files[i]
        if cand.get('prev') or cand.get('next') or cand.get('encrypted'):
            break
        if not cand.get('stored') and not cand.get('solid'):
            return cand.get('hpos', 0), True
    return 0, True


def extract_rar_entry_bytes(url, f_obj, filename):
    """Fetch only the solid block containing this entry, unpack it, and verify CRC32."""
    block = rar_entry_blocker(f_obj)
    if block:
        raise RuntimeError(block)
    tool = find_rar_extractor()
    if not tool:
        raise RuntimeError("No RAR-capable extractor found. Install 7zz/7z (with RAR5 support) or unrar, "
                           "or set the RAR_EXTRACTOR environment variable.")

    with ZIP_CACHE_LOCK:
        fmt = (ZIP_CACHE.get(url) or {}).get('archive_stats', {}).get('archive_format', 'RAR5')

    slice_start, is_solid_blk = _find_slice_start(url, f_obj)
    use_wrapper = slice_start > 64
    fetch_start = slice_start if use_wrapper else 0
    target_end = f_obj['offset'] + f_obj['comp_size'] + 8192
    span = target_end - fetch_start

    if span > RAR_EXTRACT_MAX_BYTES:
        raise ValueError(
            f"Entry sits {format_size(span)} deep inside a solid block "
            f"(offset: {format_size(f_obj['offset'])}, unpack limit: {format_size(RAR_EXTRACT_MAX_BYTES)})."
        )

    headers = dict(DEFAULT_HEADERS, Range=f"bytes={fetch_start}-{target_end}")
    headers["Accept-Encoding"] = "identity"
    tmp_path = None
    try:
        head_wrap, tail_wrap = _rar_slice_wrappers(fmt, is_solid_blk) if use_wrapper else (b"", b"")
        with tempfile.NamedTemporaryFile(suffix=".rar", delete=False) as tmp:
            tmp_path = tmp.name
            if head_wrap:
                tmp.write(head_wrap)
            with requests.get(url, headers=headers, stream=True, timeout=(10, 45)) as r:
                if r.status_code not in (200, 206):
                    raise IOError(f"HTTP {r.status_code} fetching archive slice")
                written = 0
                for chunk in r.iter_content(256 * 1024):
                    tmp.write(chunk)
                    written += len(chunk)
                    if written > span:
                        break
            if tail_wrap:
                tmp.write(tail_wrap)

        kind, path = tool
        target = filename.replace('/', os.sep)
        if kind == "7z":
            cmd = [path, "x", "-so", "-y", "-bd", "-p-", tmp_path, target]
        else:
            cmd = [path, "p", "-inul", "-y", "-p-", tmp_path, target]
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=RAR_EXTRACT_TIMEOUT)
        data = proc.stdout
        if not data and f_obj['size'] > 0:
            raise RuntimeError(proc.stderr.decode('utf-8', errors='ignore').strip() or "Extraction produced no data")

        exp = f_obj.get('crc_int')
        if exp is not None:
            if (zlib.crc32(data) & 0xFFFFFFFF) != exp:
                raise RuntimeError("Extracted bytes failed the CRC32 check (truncated or damaged solid stream).")
        elif len(data) != f_obj['size']:
            raise RuntimeError("Extracted size does not match the header size, and the entry has no CRC to verify.")
        return data
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


# ======================================================================
# 5. FLASK APP & HTML CLIENT INTERFACE
# ======================================================================
app = Flask(__name__)

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Remote ZIP & RAR Inspector & Explorer</title>
    <!-- Tailwind CSS CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- Prism.js for Syntax Highlighting -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css" rel="stylesheet" />
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/plugins/autoloader/prism-autoloader.min.js"></script>
    <!-- Marked.js for Markdown Preview -->
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #94a3b8; }
        .no-scrollbar::-webkit-scrollbar { display: none; }
        .no-scrollbar { -ms-overflow-style: none; scrollbar-width: none; }
        .checkerboard {
            background-color: #ffffff;
            background-image: linear-gradient(45deg, #f1f5f9 25%, transparent 25%), 
                              linear-gradient(-45deg, #f1f5f9 25%, transparent 25%), 
                              linear-gradient(45deg, transparent 75%, #f1f5f9 75%), 
                              linear-gradient(-45deg, transparent 75%, #f1f5f9 75%);
            background-size: 16px 16px;
            background-position: 0 0, 0 8px, 8px -8px, -8px 0px;
        }
    </style>
</head>
<body class="bg-slate-50 text-slate-800 min-h-screen flex flex-col justify-between antialiased selection:bg-indigo-500 selection:text-white">

    <!-- Top Navigation Header -->
    <header class="bg-white border-b border-slate-200/80 sticky top-0 z-30 shadow-sm backdrop-blur-md bg-white/90">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
            <div class="flex items-center gap-3">
                <div id="statsHeader" class="hidden md:flex items-center gap-4 text-xs font-semibold text-slate-600 bg-slate-100/80 px-3.5 py-1.5 rounded-xl border border-slate-200/60">
                    <span id="statFormatBadge" class="px-2 py-0.5 rounded-md text-[10px] uppercase font-bold bg-indigo-100 text-indigo-700">ZIP</span>
                    <span>Total: <strong id="statTotalFiles" class="text-slate-900">0</strong> files</span>
                    <span class="text-slate-300">|</span>
                    <span>Size: <strong id="statTotalSize" class="text-slate-900">0 B</strong></span>
                    <span class="text-slate-300">|</span>
                    <span>Comp: <strong id="statCompressedSize" class="text-slate-900">0 B</strong></span>
                    <span class="text-slate-300">|</span>
                    <span class="text-emerald-600">Saved: <strong id="statRatio">0%</strong></span>
                </div>
                <!-- USER GUIDE BUTTON -->
                <button onclick="openGuideModal()" type="button"
                        title="User & Link Guide"
                        aria-label="User & Link Guide"
                        class="inline-flex items-center justify-center gap-1.5 p-2 sm:px-3.5 sm:py-1.5 rounded-xl bg-indigo-50 border border-indigo-200/90 text-indigo-700 hover:bg-indigo-600 hover:text-white font-semibold text-xs transition shadow-sm cursor-pointer shrink-0">
                    <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M12 6.042A8.967 8.967 0 006 3.75c-1.052 0-2.062.18-3 .512v14.25A8.987 8.987 0 016 18c2.305 0 4.408.867 6 2.292m0-14.25a8.966 8.966 0 016-2.292c1.052 0 2.062.18 3 .512v14.25A8.987 8.987 0 0018 18a8.967 8.967 0 00-6 2.292m0-14.25v14.25" />
                    </svg>
                    <span class="hidden sm:inline">User &amp; Link Guide</span>
                </button>
            </div>
        </div>
    </header>

    <main class="flex-grow py-8 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto w-full">
        
        <!-- URL Input Card -->
        <div class="bg-white rounded-2xl border border-slate-200 shadow-sm p-5 sm:p-6 mb-6">
            <form onsubmit="handleFormSubmit(event); return false;" class="space-y-3">
                <div class="flex items-center justify-between">
                    <label for="urlInput" class="block text-xs font-bold uppercase tracking-wider text-slate-500">Source Archive URL (HTTP / HTTPS · ZIP &amp; RAR)</label>
                    <span class="text-[11px] font-semibold text-indigo-600 bg-indigo-50 border border-indigo-100 px-2 py-0.5 rounded-md">ZIP &amp; RAR Range Engine</span>
                </div>
                <div class="flex flex-col sm:flex-row gap-3">
                    <div class="relative flex-grow">
                        <div class="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                            <svg class="h-5 w-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244m6.561-2.02l-1.584-1.584"></path>
                            </svg>
                        </div>
                        <input type="text" id="urlInput" name="url"
                               class="block w-full pl-10 pr-4 py-2.5 bg-slate-50/50 border border-slate-300 rounded-xl focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 text-sm text-slate-800 placeholder-slate-400 transition" 
                               placeholder="https://example.com/archive.zip or .rar" value="{{ url or '' }}" required>
                    </div>
                    <button type="submit"
                            class="inline-flex items-center justify-center px-5 py-2.5 border border-transparent text-sm font-semibold rounded-xl text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition shadow-sm shrink-0 cursor-pointer">
                        Inspect Archive
                    </button>
                </div>
            </form>
        </div>

        <!-- Alert Container -->
        <div id="errorContainer" class="hidden p-4 bg-red-50 border border-red-200 text-red-700 rounded-2xl flex items-start gap-3 mb-6 shadow-sm">
            <svg class="w-5 h-5 shrink-0 text-red-500 mt-0.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z"></path>
            </svg>
            <div>
                <h3 class="font-bold text-sm text-red-800">Inspection Failed</h3>
                <p id="errorText" class="text-xs mt-0.5"></p>
            </div>
        </div>

        <!-- Loading Skeleton (Default ZIP fast inspection) -->
        <div id="loadingContainer" class="hidden bg-white rounded-2xl border border-slate-200 shadow-sm p-12 text-center mb-6">
            <div class="inline-flex items-center justify-center p-3 bg-indigo-50 text-indigo-600 rounded-full mb-3">
                <svg class="animate-spin h-7 w-7 text-indigo-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
            </div>
            <h3 class="text-base font-bold text-slate-900">Inspecting Remote Archive...</h3>
            <p class="text-xs text-slate-500 mt-1">Issuing HTTP Range Requests to read Central Directory headers.</p>
        </div>

        <!-- ======================================================== -->
        <!-- ⚡ EXPERIMENTAL RAR PROGRESS BAR & STOP CONTROL BOX       -->
        <!-- ======================================================== -->
        <div id="rarProgressContainer" class="hidden bg-white rounded-2xl border border-amber-200/80 shadow-md p-6 mb-6">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4 pb-3 border-b border-slate-100">
                <div class="flex items-center gap-2.5">
                    <span class="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-amber-100 text-amber-900 font-bold text-xs">
                        <span class="animate-ping w-2 h-2 rounded-full bg-amber-600 inline-block mr-1"></span>
                        RAR Mode (Experimental)
                    </span>
                    <span id="rarFmtBadge" class="px-2 py-0.5 rounded-md text-xs font-bold bg-slate-100 text-slate-700">RAR5</span>
                    <span id="rarQoBadge" class="hidden px-2 py-0.5 rounded-md text-xs font-bold bg-emerald-100 text-emerald-800">⚡ Quick Open Detected</span>
                </div>
                <div class="flex items-center gap-2">
                    <button id="rarStopBtn" onclick="stopRarScan()" type="button" 
                            class="inline-flex items-center gap-1.5 px-3.5 py-1.5 bg-rose-50 hover:bg-rose-600 text-rose-700 hover:text-white border border-rose-200 rounded-xl font-bold text-xs transition shadow-sm cursor-pointer">
                        <svg class="w-3.5 h-3.5 shrink-0" fill="currentColor" viewBox="0 0 24 24">
                            <rect x="6" y="6" width="12" height="12" rx="2"></rect>
                        </svg>
                        <span>Stop &amp; View Partial</span>
                    </button>
                </div>
            </div>

            <!-- Progress Bar Strip -->
            <div class="space-y-1.5 mb-4">
                <div class="flex justify-between text-xs font-semibold">
                    <span class="text-slate-600">Archive Traversal Progress</span>
                    <span id="rarProgressPercent" class="text-indigo-600 font-bold">0.0%</span>
                </div>
                <div class="w-full bg-slate-100 rounded-full h-3.5 overflow-hidden shadow-inner border border-slate-200">
                    <div id="rarProgressBar" class="bg-indigo-600 h-3.5 rounded-full transition-all duration-200 relative overflow-hidden" style="width: 0%">
                        <div class="absolute inset-0 bg-white/20 animate-pulse"></div>
                    </div>
                </div>
            </div>

            <!-- Real-Time Metrics Strip -->
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div class="p-2.5 bg-slate-50 border border-slate-100 rounded-xl">
                    <span class="text-slate-400 font-semibold block text-[11px]">Indexed Files</span>
                    <strong id="rarStatFiles" class="text-slate-900 text-sm">0 files</strong>
                </div>
                <div class="p-2.5 bg-slate-50 border border-slate-100 rounded-xl">
                    <span class="text-slate-400 font-semibold block text-[11px]">Range Requests</span>
                    <strong id="rarStatRequests" class="text-slate-900 text-sm">0 requests</strong>
                </div>
                <div class="p-2.5 bg-slate-50 border border-slate-100 rounded-xl">
                    <span class="text-slate-400 font-semibold block text-[11px]">Network Fetched</span>
                    <strong id="rarStatBytes" class="text-slate-900 text-sm">0 B</strong>
                </div>
                <div class="p-2.5 bg-slate-50 border border-slate-100 rounded-xl">
                    <span class="text-slate-400 font-semibold block text-[11px]">Archive Scanned</span>
                    <strong id="rarStatOffset" class="text-slate-900 text-sm">0 B / 0 B</strong>
                </div>
            </div>

            <div class="mt-3 text-[11px] text-slate-500 truncate font-mono flex items-center gap-1.5">
                <span class="font-sans font-semibold text-slate-400 shrink-0">Scanning:</span>
                <span id="rarStatCurrentFile" class="truncate">Connecting to remote host...</span>
            </div>
        </div>

        <!-- File Explorer Workspace -->
        <div id="workspaceContainer" class="hidden bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden flex flex-col">
            
            <!-- Partial Scan Notification Banner -->
            <div id="partialBanner" class="hidden px-5 py-2.5 bg-amber-50 border-b border-amber-200 text-amber-900 text-xs flex items-center justify-between gap-3">
                <div class="flex items-center gap-2">
                    <svg class="w-4 h-4 text-amber-600 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"></path>
                    </svg>
                    <span><strong>Partial Scan:</strong> Displaying files discovered before scanning was stopped.</span>
                </div>
                <button onclick="rescanRar(false)" type="button" class="px-2.5 py-1 bg-amber-200/80 hover:bg-amber-300 text-amber-900 font-bold rounded-lg transition text-[11px] cursor-pointer shrink-0">
                    Rescan Full Archive
                </button>
            </div>

            <!-- RAR Scan Notes Banner -->
            <div id="rarNotesBanner" class="hidden px-5 py-2.5 bg-sky-50 border-b border-sky-200 text-sky-900 text-xs flex items-start justify-between gap-3">
                <ul id="rarNotesList" class="list-disc pl-4 space-y-0.5"></ul>
                <button id="rarVerifyBtn" onclick="rescanRar(true)" type="button" class="hidden px-2.5 py-1 bg-sky-200/80 hover:bg-sky-300 text-sky-900 font-bold rounded-lg transition text-[11px] cursor-pointer shrink-0">
                    Verify with full scan
                </button>
            </div>

            <!-- Explorer Toolbar -->
            <div class="p-4 sm:p-5 border-b border-slate-200 bg-slate-50/50 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                
                <!-- Search Box + Scope Toggle -->
                <div class="flex items-center gap-2 max-w-lg w-full">
                    <div class="relative flex-grow">
                        <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                            <svg class="h-4 w-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                            </svg>
                        </div>
                        <input type="text" id="searchInput" oninput="onSearchInput()"
                               class="block w-full pl-9 pr-4 py-2 bg-white border border-slate-200 rounded-xl text-xs sm:text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition placeholder-slate-400"
                               placeholder="Filter files globally or use wildcards (*.json)...">
                    </div>
                    <select id="scopeSelect" onchange="onScopeChange()" 
                            class="bg-white border border-slate-200 text-xs font-semibold rounded-xl px-3 py-2 text-slate-700 focus:outline-none focus:border-indigo-500 shrink-0">
                        <option value="current">Current Folder</option>
                        <option value="global">Entire Archive</option>
                    </select>
                </div>

                <!-- Category Filter Chips -->
                <div class="flex items-center gap-1.5 overflow-x-auto no-scrollbar py-0.5">
                    <button onclick="setCategory('all')" class="cat-chip px-3 py-1.5 text-xs font-semibold rounded-lg bg-indigo-600 text-white shadow-sm transition" data-cat="all">All</button>
                    <button onclick="setCategory('code')" class="cat-chip px-3 py-1.5 text-xs font-semibold rounded-lg bg-white border border-slate-200 text-slate-600 hover:bg-slate-50 transition" data-cat="code">Code</button>
                    <button onclick="setCategory('image')" class="cat-chip px-3 py-1.5 text-xs font-semibold rounded-lg bg-white border border-slate-200 text-slate-600 hover:bg-slate-50 transition" data-cat="image">Images</button>
                    <button onclick="setCategory('audio')" class="cat-chip px-3 py-1.5 text-xs font-semibold rounded-lg bg-white border border-slate-200 text-slate-600 hover:bg-slate-50 transition" data-cat="audio">Audio</button>
                    <button onclick="setCategory('doc')" class="cat-chip px-3 py-1.5 text-xs font-semibold rounded-lg bg-white border border-slate-200 text-slate-600 hover:bg-slate-50 transition" data-cat="doc">Docs</button>
                    <button onclick="setCategory('archive')" class="cat-chip px-3 py-1.5 text-xs font-semibold rounded-lg bg-white border border-slate-200 text-slate-600 hover:bg-slate-50 transition" data-cat="archive">Archives</button>
                    <button onclick="setCategory('large')" class="cat-chip px-3 py-1.5 text-xs font-semibold rounded-lg bg-white border border-slate-200 text-slate-600 hover:bg-slate-50 transition" data-cat="large">&gt;10MB</button>
                </div>
            </div>

            <!-- Breadcrumbs Navigation Bar -->
            <div class="px-4 sm:px-5 py-2.5 bg-white border-b border-slate-200 flex items-center justify-between text-xs font-semibold text-slate-600 overflow-x-auto no-scrollbar">
                <div class="flex items-center gap-1.5 whitespace-nowrap">
                    <span onclick="navigateTo('')" class="text-indigo-600 hover:text-indigo-800 cursor-pointer transition flex items-center gap-1">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12l8.954-8.955c.44-.439 1.152-.439 1.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25"></path>
                        </svg>
                        Root
                    </span>
                    <div id="breadcrumbTrail" class="inline-flex items-center gap-1.5"></div>
                </div>
                <div class="flex items-center gap-2 shrink-0">
                    <span class="text-slate-400">Page size:</span>
                    <select id="pageSizeSelect" onchange="onPageSizeChange()" class="bg-slate-50 border border-slate-200 text-xs rounded-lg px-2 py-1 text-slate-700 focus:outline-none">
                        <option value="25">25</option>
                        <option value="50" selected>50</option>
                        <option value="100">100</option>
                        <option value="200">200</option>
                    </select>
                </div>
            </div>

            <!-- Table View -->
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse text-xs sm:text-sm">
                    <thead>
                        <tr class="bg-slate-50/80 border-b border-slate-200 text-slate-600 font-semibold select-none text-xs">
                            <th class="py-3 px-4 w-10 text-center">
                                <input type="checkbox" id="selectAllCheckbox" onchange="toggleSelectAll(this)" 
                                       class="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500">
                            </th>
                            <th onclick="toggleSort('name')" class="py-3 px-4 cursor-pointer hover:text-indigo-600 transition">
                                <div class="flex items-center gap-1.5">Name <span id="sort_icon_name" class="text-slate-400">↕</span></div>
                            </th>
                            <th onclick="toggleSort('size')" class="py-3 px-4 cursor-pointer hover:text-indigo-600 transition w-28">
                                <div class="flex items-center gap-1.5">Size <span id="sort_icon_size" class="text-slate-400">↕</span></div>
                            </th>
                            <th onclick="toggleSort('comp_size')" class="py-3 px-4 cursor-pointer hover:text-indigo-600 transition w-28 hidden md:table-cell">
                                <div class="flex items-center gap-1.5">Comp <span id="sort_icon_comp_size" class="text-slate-400">↕</span></div>
                            </th>
                            <th onclick="toggleSort('ratio')" class="py-3 px-4 cursor-pointer hover:text-indigo-600 transition w-20 hidden sm:table-cell">
                                <div class="flex items-center gap-1.5">Ratio <span id="sort_icon_ratio" class="text-slate-400">↕</span></div>
                            </th>
                            <th onclick="toggleSort('date')" class="py-3 px-4 cursor-pointer hover:text-indigo-600 transition w-36 hidden lg:table-cell">
                                <div class="flex items-center gap-1.5">Modified <span id="sort_icon_date" class="text-slate-400">↕</span></div>
                            </th>
                            <th class="py-3 px-4 text-right w-28">Actions</th>
                        </tr>
                    </thead>
                    <tbody id="tableBody" class="divide-y divide-slate-100"></tbody>
                </table>
            </div>

            <!-- Empty State -->
            <div id="emptyState" class="hidden py-12 text-center text-slate-400">
                <svg class="w-10 h-10 mx-auto mb-2 text-slate-300" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M2.25 13.5h3.86a2.25 2.25 0 012.012 1.244l.256.512a2.25 2.25 0 002.013 1.244h3.218a2.25 2.25 0 002.013-1.244l.256-.512a2.25 2.25 0 012.013-1.244h3.859m-19.5.375v6.75a2.25 2.25 0 002.25 2.25h15a2.25 2.25 0 002.25-2.25v-6.75m-19.5 0A2.25 2.25 0 014.5 12h15a2.25 2.25 0 012.25 2.25"></path>
                </svg>
                <p class="text-sm font-semibold">No matching files found</p>
                <p class="text-xs text-slate-400 mt-0.5">Try changing search scope or clearing category filters.</p>
            </div>

            <!-- Pagination Footer -->
            <div class="px-4 sm:px-5 py-3.5 bg-slate-50/80 border-t border-slate-200 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs">
                <span id="paginationInfo" class="font-medium text-slate-500">Showing 0 of 0 items</span>
                <div class="flex items-center gap-1.5" id="paginationButtons"></div>
            </div>

        </div>
    </main>

    <!-- Floating Batch Actions Toolbar -->
    <div id="batchToolbar" class="fixed bottom-6 left-1/2 transform -translate-x-1/2 bg-slate-900 text-white px-5 py-3 rounded-2xl shadow-2xl z-40 flex items-center gap-3 sm:gap-4 hidden transition-all duration-300 border border-slate-700">
        <span class="text-xs font-semibold whitespace-nowrap"><strong id="selectedCount" class="text-indigo-400">0</strong> selected</span>
        <div class="h-4 w-px bg-slate-700 shrink-0"></div>
        
        <button id="batchDownloadZipBtn" onclick="downloadSelectedZip()" class="text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 px-3 py-1.5 rounded-xl transition flex items-center gap-1.5 shadow-sm whitespace-nowrap cursor-pointer">
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3"></path>
            </svg>
            <span>Download (.zip)</span>
        </button>

        <button onclick="openBatchModal('curl')" class="text-xs font-semibold hover:text-indigo-300 transition">cURL</button>
        <button onclick="openBatchModal('powershell')" class="text-xs font-semibold hover:text-indigo-300 transition">PowerShell</button>
        <button onclick="openBatchModal('wget')" class="text-xs font-semibold hover:text-indigo-300 transition">Wget</button>
        <button onclick="openBatchModal('links')" class="text-xs font-semibold hover:text-indigo-300 transition">Link</button>
        <div class="h-4 w-px bg-slate-700 shrink-0"></div>
        <button onclick="clearSelection()" class="text-xs text-slate-400 hover:text-white transition cursor-pointer">Deselect</button>
    </div>

    <!-- Universal Inspector Modal -->
    <div id="inspectorModal" onclick="closeModal()" class="fixed inset-0 bg-slate-900/50 backdrop-blur-sm z-50 flex items-center justify-center p-3 sm:p-4 hidden opacity-0 transition-opacity duration-200">
        <div onclick="event.stopPropagation()" class="bg-white rounded-2xl max-w-4xl w-full border border-slate-200 shadow-2xl overflow-hidden flex flex-col max-h-[90vh] transform scale-95 transition-all duration-200">
            
            <!-- Modal Header -->
            <div class="px-6 py-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
                <div class="min-w-0 flex-grow pr-4">
                    <h3 id="modalFilename" class="font-bold text-slate-900 text-base truncate">File Details</h3>
                    <p id="modalPath" class="text-xs text-slate-400 truncate font-mono mt-0.5"></p>
                </div>
                <button onclick="closeModal()" class="text-slate-400 hover:text-slate-600 transition p-1">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"></path>
                    </svg>
                </button>
            </div>

            <!-- Modal Tab Navigation -->
            <div class="flex items-center border-b border-slate-200 px-6 gap-6 text-xs font-bold text-slate-500 bg-white">
                <button onclick="switchTab('preview')" id="tabBtnPreview" class="py-3 border-b-2 border-indigo-600 text-indigo-600 transition">Preview</button>
                <button onclick="switchTab('metadata')" id="tabBtnMetadata" class="py-3 border-b-2 border-transparent hover:text-slate-900 transition">Metadata</button>
                <button onclick="switchTab('hex')" id="tabBtnHex" class="py-3 border-b-2 border-transparent hover:text-slate-900 transition">Hex View</button>
            </div>

            <!-- Modal Body Panes -->
            <div class="p-6 overflow-y-auto flex-grow">
                
                <!-- Pane 1: Preview -->
                <div id="panePreview" class="space-y-4">
                    <iframe id="pdfPreviewTag" class="hidden w-full h-[650px] rounded-xl border border-slate-200"></iframe>

                    <!-- CSV Table Preview -->
                    <div id="csvPreviewBox" class="hidden max-h-96 overflow-auto border border-slate-200 rounded-xl">
                        <table id="csvTable" class="w-full text-left text-xs border-collapse"></table>
                    </div>

                    <div id="previewLoader" class="py-12 text-center text-slate-400 hidden">
                        <svg class="animate-spin h-6 w-6 text-indigo-600 mx-auto mb-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        <p class="text-xs">Streaming byte chunk...</p>
                    </div>

                    <!-- Image Preview Container -->
                    <div id="imagePreviewBox" class="hidden text-center">
                        <div class="inline-block checkerboard border border-slate-200 rounded-xl p-2 max-w-full overflow-hidden shadow-inner">
                            <img id="imagePreviewTag" src="" alt="Preview" class="max-h-96 max-w-full rounded-lg object-contain mx-auto">
                        </div>
                    </div>

                    <!-- Audio Preview Container -->
                    <div id="audioPreviewBox" class="hidden text-center py-6 bg-slate-900 rounded-2xl">
                        <audio id="audioPreviewTag" controls class="w-3/4 mx-auto"></audio>
                    </div>

                    <!-- Code / Text Viewer -->
                    <div id="codePreviewBox" class="hidden relative">
                        <div class="flex items-center justify-between pb-2">
                            <span id="codeLangBadge" class="text-xs font-bold uppercase text-slate-400">Code</span>
                            <div class="flex items-center gap-2">
                                <button id="mdToggleBtn" onclick="toggleMarkdown()" class="hidden text-xs font-semibold text-indigo-600 hover:text-indigo-800 transition">View Formatted</button>
                                <button onclick="copyCode()" class="text-xs font-semibold text-indigo-600 hover:text-indigo-800 transition">Copy</button>
                            </div>
                        </div>
                        <pre class="rounded-xl max-h-96 overflow-auto text-xs font-mono !bg-slate-900 !p-4"><code id="codeBlock" class="language-plaintext"></code></pre>
                        <div id="markdownRendered" class="hidden max-h-96 overflow-auto p-4 bg-slate-50 border border-slate-200 rounded-xl prose prose-sm max-w-none"></div>
                    </div>

                    <!-- Unsupported / RAR Compressed Banner -->
                    <div id="unsupportedPreviewBox" class="hidden py-8 text-center bg-slate-50 border border-dashed border-slate-200 rounded-xl">
                        <p id="unsupportedTitle" class="text-xs text-slate-500 font-semibold">Inline preview is not supported for this file type.</p>
                        <p id="unsupportedSub" class="text-xs text-slate-400 mt-1">Use the <strong>Hex View</strong> tab to inspect binary bytes, or download the file.</p>
                    </div>
                </div>

                <!-- Pane 2: Metadata & Integrity -->
                <div id="paneMetadata" class="hidden space-y-3 text-xs">
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <div class="p-3 bg-slate-50 border border-slate-100 rounded-xl">
                            <span class="text-slate-400 font-semibold block">Uncompressed Size</span>
                            <span id="metaSize" class="text-slate-900 font-bold text-sm"></span>
                        </div>
                        <div class="p-3 bg-slate-50 border border-slate-100 rounded-xl">
                            <span class="text-slate-400 font-semibold block">Compressed Size</span>
                            <span id="metaCompSize" class="text-slate-900 font-bold text-sm"></span>
                        </div>
                        <div class="p-3 bg-slate-50 border border-slate-100 rounded-xl">
                            <span class="text-slate-400 font-semibold block">Compression Ratio</span>
                            <span id="metaRatio" class="text-emerald-600 font-bold text-sm"></span>
                        </div>
                        <div class="p-3 bg-slate-50 border border-slate-100 rounded-xl">
                            <span class="text-slate-400 font-semibold block">Compression Method</span>
                            <span id="metaMethod" class="text-slate-900 font-bold text-sm"></span>
                        </div>
                        <div class="p-3 bg-slate-50 border border-slate-100 rounded-xl">
                            <span class="text-slate-400 font-semibold block">CRC32 Checksum</span>
                            <span id="metaCRC" class="font-mono text-slate-900 font-bold text-sm select-all"></span>
                        </div>
                        <div class="p-3 bg-slate-50 border border-slate-100 rounded-xl">
                            <span class="text-slate-400 font-semibold block">Encryption</span>
                            <span id="metaEncrypted" class="font-bold text-sm"></span>
                        </div>
                    </div>
                    <div class="p-3 bg-slate-50 border border-slate-100 rounded-xl">
                        <span class="text-slate-400 font-semibold block">Last Modified</span>
                        <span id="metaDate" class="text-slate-900 font-semibold"></span>
                    </div>
                </div>

                <!-- Pane 3: Hex View -->
                <div id="paneHex" class="hidden">
                    <div id="hexLoader" class="py-8 text-center text-slate-400 hidden">
                        <p class="text-xs">Generating 16-byte hex dump...</p>
                    </div>
                    <pre id="hexContainer" class="font-mono text-[11px] bg-slate-900 text-slate-200 p-4 rounded-xl max-h-96 overflow-auto leading-relaxed select-all whitespace-pre"></pre>
                </div>

            </div>

            <!-- Modal Footer -->
            <div class="px-6 py-3.5 border-t border-slate-100 bg-slate-50/50 flex items-center justify-between gap-3">
                <button onclick="copyDirectLink()" class="text-xs font-semibold text-slate-600 hover:text-slate-900 transition flex items-center gap-1">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244m6.561-2.02l-1.584-1.584"></path>
                    </svg>
                    <span>Copy Direct Link</span>
                </button>
                <div class="flex items-center gap-2">
                    <button onclick="closeModal()" class="px-4 py-2 border border-slate-200 text-xs font-semibold rounded-xl text-slate-700 hover:bg-slate-50 transition">Dismiss</button>
                    <a id="modalDownloadBtn" href="#" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded-xl transition flex items-center gap-1.5 shadow-sm">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3"></path>
                        </svg>
                        <span>Download</span>
                    </a>
                </div>
            </div>

        </div>
    </div>

    <!-- Batch Export Script Modal -->
    <div id="batchModal" onclick="closeBatchModal()" class="fixed inset-0 bg-slate-900/50 backdrop-blur-sm z-50 flex items-center justify-center p-4 hidden opacity-0 transition-opacity duration-200">
        <div onclick="event.stopPropagation()" class="bg-white rounded-2xl max-w-2xl w-full border border-slate-200 shadow-2xl p-6 relative">
            <h3 id="batchModalTitle" class="font-bold text-slate-900 text-base mb-1">Batch Script Export</h3>
            <p class="text-xs text-slate-400 mb-3">Copy this automated script to download all selected files sequentially.</p>
            <textarea id="batchScriptArea" readonly class="w-full h-56 font-mono text-xs p-3.5 bg-slate-900 text-slate-200 rounded-xl focus:outline-none select-all"></textarea>
            <div class="mt-4 flex justify-end gap-2">
                <button onclick="closeBatchModal()" class="px-4 py-2 border border-slate-200 text-xs font-semibold rounded-xl text-slate-700 hover:bg-slate-50 transition">Close</button>
                <button onclick="copyBatchScript()" id="batchCopyBtn" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded-xl transition">Copy Script</button>
            </div>
        </div>
    </div>

    <!-- USER MANUAL & LINK RULES MODAL -->
    <div id="guideModal" onclick="closeGuideModal()" class="fixed inset-0 bg-slate-900/60 backdrop-blur-sm z-50 flex items-center justify-center p-2 sm:p-6 hidden opacity-0 transition-opacity duration-200">
        <div onclick="event.stopPropagation()" class="bg-white rounded-2xl max-w-5xl w-full border border-slate-200 shadow-2xl overflow-hidden flex flex-col max-h-[94vh] sm:max-h-[90vh] transform scale-95 transition-all duration-200">
            
            <div class="px-4 sm:px-6 py-3 sm:py-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/70">
                <div class="flex items-center gap-2.5 sm:gap-3 min-w-0 pr-2">
                    <div class="p-1.5 sm:p-2 bg-indigo-600 text-white rounded-xl shadow-xs shrink-0">
                        <svg class="w-4 h-4 sm:w-5 sm:h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M12 6.042A8.967 8.967 0 006 3.75c-1.052 0-2.062.18-3 .512v14.25A8.987 8.987 0 016 18c2.305 0 4.408.867 6 2.292m0-14.25a8.966 8.966 0 016-2.292c1.052 0 2.062.18 3 .512v14.25A8.987 8.987 0 0018 18a8.967 8.967 0 00-6 2.292m0-14.25v14.25" />
                        </svg>
                    </div>
                    <div class="min-w-0">
                        <h3 class="font-bold text-slate-900 text-sm sm:text-base leading-tight truncate">Inspector Manual &amp; Link Rules</h3>
                        <p class="text-[11px] sm:text-xs text-slate-400 truncate">ZIP &amp; RAR HTTP Range Request inspection engine</p>
                    </div>
                </div>
                <button onclick="closeGuideModal()" class="text-slate-400 hover:text-slate-700 transition p-1.5 rounded-lg hover:bg-slate-100 shrink-0 cursor-pointer">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                </button>
            </div>

            <!-- Tabs -->
            <div class="flex items-center border-b border-slate-200 px-3 sm:px-6 gap-1 sm:gap-2 text-xs overflow-x-auto no-scrollbar bg-white shrink-0">
                <button onclick="switchGuideTab('linkRules')" id="guideNavBtn_linkRules" class="guide-tab-btn px-3 sm:px-4 py-2.5 sm:py-3 border-b-2 border-indigo-600 text-indigo-600 font-bold whitespace-nowrap transition cursor-pointer">
                    🔗 Link Rules
                </button>
                <button onclick="switchGuideTab('rarMode')" id="guideNavBtn_rarMode" class="guide-tab-btn px-3 sm:px-4 py-2.5 sm:py-3 border-b-2 border-transparent text-slate-500 hover:text-slate-800 font-medium whitespace-nowrap transition cursor-pointer">
                    🧪 RAR Engine Guide
                </button>
                <button onclick="switchGuideTab('copying')" id="guideNavBtn_copying" class="guide-tab-btn px-3 sm:px-4 py-2.5 sm:py-3 border-b-2 border-transparent text-slate-500 hover:text-slate-800 font-medium whitespace-nowrap transition cursor-pointer">
                    📋 Copying &amp; Sharing
                </button>
                <button onclick="switchGuideTab('troubleshooting')" id="guideNavBtn_troubleshooting" class="guide-tab-btn px-3 sm:px-4 py-2.5 sm:py-3 border-b-2 border-transparent text-slate-500 hover:text-slate-800 font-medium whitespace-nowrap transition cursor-pointer">
                    ⚙️ Errors &amp; FAQ
                </button>
            </div>

            <div class="p-3.5 sm:p-6 overflow-y-auto flex-grow text-xs leading-relaxed text-slate-600 space-y-3.5 sm:space-y-4">
                
                <!-- TAB 1: Link Rules -->
                <div id="guidePanel_linkRules" class="space-y-3 sm:space-y-4">
                    <div class="p-3.5 sm:p-4 bg-indigo-50/80 border border-indigo-100 rounded-xl">
                        <h4 class="font-bold text-indigo-950 text-xs sm:text-sm mb-1">Direct Range-Capable Binary URLs</h4>
                        <p class="text-indigo-900/80 text-[11px] sm:text-xs">This engine uses HTTP Range Requests (<code class="bg-indigo-100 px-1 py-0.5 rounded font-mono">206 Partial Content</code>) to slice archive indices. Your link must point directly to the binary package without login walls or web landing pages.</p>
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-3 sm:gap-4">
                        <div class="p-3.5 sm:p-4 bg-emerald-50/60 border border-emerald-200 rounded-xl space-y-2">
                            <div class="flex items-center gap-1.5 text-emerald-800 font-bold text-xs sm:text-sm">
                                <span>✔</span> Supported
                            </div>
                            <ul class="space-y-1.5 text-emerald-950/80 text-[11px] sm:text-xs">
                                <li>Direct binary ZIP links (<code class="bg-emerald-100 px-1 rounded font-mono">.zip</code>) from CDNs, Nginx, Apache, S3, or Backblaze B2.</li>
                                <li><strong>Direct RAR archives (<code class="bg-emerald-100 px-1 rounded font-mono">.rar</code>, <code class="bg-emerald-100 px-1 rounded font-mono">.part1.rar</code>)</strong>: RAR4 and RAR5 formats inspected via range jumps.</li>
                                <li>GitHub Releases asset direct download links.</li>
                                <li>Servers supporting byte ranges (returning <code class="bg-emerald-100 px-1 rounded font-mono">HTTP 206</code>).</li>
                            </ul>
                        </div>

                        <div class="p-3.5 sm:p-4 bg-rose-50/60 border border-rose-200 rounded-xl space-y-2">
                            <div class="flex items-center gap-1.5 text-rose-800 font-bold text-xs sm:text-sm">
                                <span>✖</span> Unsupported
                            </div>
                            <ul class="space-y-1.5 text-rose-950/80 text-[11px] sm:text-xs">
                                <li>Download landing pages (MediaFire, Google Drive web preview, Mega).</li>
                                <li>7z and ISO formats (unless extracted/re-archived).</li>
                                <li>Encrypted header archives (<code class="bg-rose-100 px-1 rounded font-mono">-hp</code>) without credentials.</li>
                            </ul>
                        </div>
                    </div>
                </div>

                <!-- TAB 2: RAR Engine Guide -->
                <div id="guidePanel_rarMode" class="space-y-3 sm:space-y-4 hidden">
                    <div class="p-3.5 bg-amber-50/70 border border-amber-200 rounded-xl space-y-1.5">
                        <h4 class="font-bold text-amber-950 text-xs sm:text-sm">How RAR Remote Inspection Works</h4>
                        <p class="text-amber-900/80 text-[11px] sm:text-xs">Unlike ZIP (which centralizes all filenames at the very end of the file), standard RAR archives scatter file headers throughout the archive. Our engine uses two specialized techniques:</p>
                        <ol class="list-decimal pl-4 space-y-1 text-amber-950/90 text-[11px] sm:text-xs">
                            <li><strong>⚡ Quick Open Locator (RAR5):</strong> Checks for a pre-indexed Quick Open service record. If found, it reads the cached index, verifies it against the real archive bytes, and walks only the byte ranges the index does not cover, so the listing is complete. Anything doubtful falls back to a full walk.</li>
                            <li><strong>🎯 Sequential Header Hopping:</strong> For archives without Quick Open, it reads each header and range-jumps over packed bytes. The <strong>Live Progress Bar</strong> keeps you informed, and you can click <strong>Stop &amp; View Partial</strong> at any time.</li>
                        </ol>
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px] sm:text-xs">
                        <div class="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                            <span class="font-bold text-slate-900 block">Stored (Method 0) Entries</span>
                            <p class="text-slate-600">Files stored without compression can be downloaded, previewed, or streamed directly, with a CRC32 check. Entries split across volumes or password protected cannot.</p>
                        </div>
                        <div class="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                            <span class="font-bold text-slate-900 block">Compressed &amp; Solid Entries</span>
                            <p class="text-slate-600">Can be previewed (not downloaded) when a RAR-capable tool (7zz, 7z or unrar) is installed on the server. Output is only shown if it matches the CRC32 from the header. The <strong>Hex View</strong> tab shows raw packed bytes.</p>
                        </div>
                    </div>
                </div>

                <!-- TAB 3: Copying & Sharing -->
                <div id="guidePanel_copying" class="space-y-3 sm:space-y-4 hidden">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div class="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                            <span class="font-bold text-slate-900 block">Direct File Links</span>
                            <p class="text-slate-600 text-[11px]">Click "Inspect" on any file and use "Copy Direct Link" to stream single files into browsers, curl, or download managers (IDM).</p>
                        </div>
                        <div class="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                            <span class="font-bold text-slate-900 block">Batch Script Export</span>
                            <p class="text-slate-600 text-[11px]">Select multiple files and use the cURL, PowerShell, or Wget buttons to download files automatically.</p>
                        </div>
                    </div>
                </div>

                <!-- TAB 4: Troubleshooting -->
                <div id="guidePanel_troubleshooting" class="space-y-3 sm:space-y-4 hidden">
                    <div class="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1 text-[11px] sm:text-xs text-slate-600">
                        <h4 class="font-bold text-slate-900 text-xs sm:text-sm">Common Diagnoses</h4>
                        <ul class="space-y-1.5 mt-2">
                            <li><code class="bg-white px-1 border rounded text-rose-700 font-bold font-mono">Range requests not supported (HTTP 200 / 416)</code> → Server does not support slicing byte segments.</li>
                            <li><code class="bg-white px-1 border rounded text-rose-700 font-bold font-mono">Encrypted headers (-hp)</code> → The archive encrypts filenames and cannot be listed without credentials.</li>
                            <li><code class="bg-white px-1 border rounded text-rose-700 font-bold font-mono">Failed the CRC32 check</code> → The solid stream was truncated or the archive is damaged; the preview is withheld rather than shown wrong.</li>
                        </ul>
                    </div>
                </div>

            </div>

            <div class="px-4 sm:px-6 py-2.5 sm:py-3 border-t border-slate-100 bg-slate-50/70 flex items-center justify-between gap-2 shrink-0">
                <span class="hidden sm:inline text-[11px] text-slate-400">Tip: Press <kbd class="px-1.5 py-0.5 bg-white border rounded shadow-xs font-mono">ESC</kbd> to close dialogs</span>
                <button onclick="closeGuideModal()" class="w-full sm:w-auto px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded-xl transition shadow-sm cursor-pointer text-center">
                    Got it!
                </button>
            </div>

        </div>
    </div>

    <footer class="py-6 border-t border-slate-200 bg-white">
        <div class="max-w-7xl mx-auto px-4 text-center text-xs text-slate-400">
            Powered by Python, RemoteZip, RangeReader &amp; Flask.
        </div>
    </footer>

    <!-- Frontend Core Engine -->
    <script>
    const INITIAL_URL = {{ url | tojson }};
    
    const state = {
        url: INITIAL_URL || "",
        path: "",
        q: "",
        scope: "current",
        cat: "all",
        sort: "name",
        order: "asc",
        page: 1,
        limit: 50,
        selectedFiles: new Map(),
        activeFile: null,
        markdownFormatted: false,
        rawTextContent: "",
        archiveFormat: "ZIP",
        isRar: false,
        scanId: null,
        rarFinished: false,
        skipQo: false
    };

    let currentRenderedFiles = [];
    let searchDebounce = null;
    let isHashUpdating = false;
    let rarEventSource = null;

    window.addEventListener('DOMContentLoaded', () => {
        parseHashState();
        if (state.url) {
            document.getElementById('urlInput').value = state.url;
            fetchExplorerData();
        }
    });

    window.addEventListener('hashchange', () => {
        if (!isHashUpdating) {
            parseHashState();
            fetchExplorerData();
        }
    });

    function parseHashState() {
        if (!window.location.hash) return;
        const params = new URLSearchParams(window.location.hash.substring(1));
        if (params.has('url')) state.url = params.get('url');
        if (params.has('path')) state.path = params.get('path');
        if (params.has('sort')) state.sort = params.get('sort');
        if (params.has('order')) state.order = params.get('order');
        if (params.has('page')) state.page = parseInt(params.get('page')) || 1;
        if (params.has('limit')) state.limit = parseInt(params.get('limit')) || 50;
        if (params.has('cat')) state.cat = params.get('cat');
        if (params.has('q')) state.q = params.get('q');
        if (params.has('scope')) state.scope = params.get('scope');

        if (state.url) document.getElementById('urlInput').value = state.url;
        document.getElementById('searchInput').value = state.q;
        document.getElementById('scopeSelect').value = state.scope;
        document.getElementById('pageSizeSelect').value = state.limit;
        updateCategoryPills();
    }

    function syncHashState() {
        isHashUpdating = true;
        const params = new URLSearchParams();
        if (state.url) params.set('url', state.url);
        if (state.path) params.set('path', state.path);
        if (state.sort !== 'name') params.set('sort', state.sort);
        if (state.order !== 'asc') params.set('order', state.order);
        if (state.page > 1) params.set('page', state.page);
        if (state.limit !== 50) params.set('limit', state.limit);
        if (state.cat !== 'all') params.set('cat', state.cat);
        if (state.q) params.set('q', state.q);
        if (state.scope !== 'current') params.set('scope', state.scope);

        window.location.hash = params.toString();
        setTimeout(() => { isHashUpdating = false; }, 50);
    }

    function showError(message) {
        document.getElementById('errorText').textContent = message;
        document.getElementById('errorContainer').classList.remove('hidden');
    }

    function handleFormSubmit(e) {
        if (e) e.preventDefault();
        let url = document.getElementById('urlInput').value.trim();
        if (!url) return;

        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
            document.getElementById('urlInput').value = url;
        }

        state.url = url;
        state.path = "";
        state.q = "";
        state.page = 1;
        state.selectedFiles.clear();
        updateBatchToolbar();
        syncHashState();
        fetchExplorerData();
    }

    async function fetchExplorerData() {
        if (!state.url) return;

        const loading = document.getElementById('loadingContainer');
        const workspace = document.getElementById('workspaceContainer');
        const errorBox = document.getElementById('errorContainer');
        const errorText = document.getElementById('errorText');
        const rarContainer = document.getElementById('rarProgressContainer');

        const isInitial = workspace.classList.contains('hidden');
        if (isInitial && rarContainer.classList.contains('hidden')) {
            loading.classList.remove('hidden');
        }
        errorBox.classList.add('hidden');

        try {
            const queryParams = new URLSearchParams({
                url: state.url,
                path: state.path,
                q: state.q,
                scope: state.scope,
                cat: state.cat,
                sort: state.sort,
                order: state.order,
                page: state.page,
                limit: state.limit
            });

            const res = await fetch(`/api/list?${queryParams.toString()}`, { cache: 'no-store' });
            let data = {};
            const contentType = res.headers.get("content-type") || "";

            if (contentType.includes("application/json")) {
                data = await res.json();
            } else {
                const errorHtml = await res.text();
                throw new Error(`Server returned status ${res.status}: Remote server blocked or invalid archive.`);
            }

            if (!res.ok) throw new Error(data.error || "Failed to inspect archive.");

            // ⚡ RAR ARCHIVE DETECTED AND NEEDS STREAM SCANNING
            if (data.is_rar) {
                if (data.resolved_url && data.resolved_url !== state.url) {
                    state.url = data.resolved_url;
                    document.getElementById('urlInput').value = data.resolved_url;
                    syncHashState();
                }
                loading.classList.add('hidden');
                workspace.classList.add('hidden');
                startRarScan(data);
                return;
            }

            // Resolved redirect link
            if (data.resolved_url && data.resolved_url !== state.url) {
                state.url = data.resolved_url;
                document.getElementById('urlInput').value = data.resolved_url;
                syncHashState();
            }

            loading.classList.add('hidden');
            rarContainer.classList.add('hidden');
            workspace.classList.remove('hidden');

            state.archiveFormat = data.archive_stats ? (data.archive_stats.archive_format || 'ZIP') : 'ZIP';
            state.isRar = state.archiveFormat.includes('RAR');

            // Format Badge in header
            const fmtBadge = document.getElementById('statFormatBadge');
            fmtBadge.textContent = state.archiveFormat;
            fmtBadge.className = state.isRar 
                ? "px-2 py-0.5 rounded-md text-[10px] uppercase font-bold bg-amber-100 text-amber-800"
                : "px-2 py-0.5 rounded-md text-[10px] uppercase font-bold bg-indigo-100 text-indigo-700";

            if (data.archive_stats) {
                document.getElementById('statsHeader').classList.remove('hidden');
                document.getElementById('statTotalFiles').textContent = data.archive_stats.total_files.toLocaleString();
                document.getElementById('statTotalSize').textContent = data.archive_stats.total_size;
                document.getElementById('statCompressedSize').textContent = data.archive_stats.total_comp_size;
                document.getElementById('statRatio').textContent = data.archive_stats.total_ratio;

                // Show partial notice if stopped
                const partialBanner = document.getElementById('partialBanner');
                if (data.archive_stats.partial) {
                    partialBanner.classList.remove('hidden');
                } else {
                    partialBanner.classList.add('hidden');
                }
            }
            renderRarNotes(data.archive_stats);

            renderBreadcrumbs();
            renderTable(data);
            renderPagination(data);
            updateSortIcons();

        } catch (err) {
            loading.classList.add('hidden');
            rarContainer.classList.add('hidden');
            if (isInitial) workspace.classList.add('hidden');
            errorText.textContent = err.message;
            errorBox.classList.remove('hidden');
        }
    }

    function renderRarNotes(stats) {
        const box = document.getElementById('rarNotesBanner');
        const list = document.getElementById('rarNotesList');
        const verifyBtn = document.getElementById('rarVerifyBtn');
        const notes = (stats && stats.notes) || [];
        if (!state.isRar || notes.length === 0) {
            box.classList.add('hidden');
            return;
        }
        list.innerHTML = notes.map(n => `<li>${escapeHtml(n)}</li>`).join('');
        verifyBtn.classList.toggle('hidden', !(stats.quick_open && !stats.partial));
        box.classList.remove('hidden');
    }

    // ==========================================
    // ⚡ RAR STREAM SCANNING CONTROLLERS
    // ==========================================
    function startRarScan(initData) {
        document.getElementById('loadingContainer').classList.add('hidden');
        document.getElementById('workspaceContainer').classList.add('hidden');
        document.getElementById('errorContainer').classList.add('hidden');

        const rarBox = document.getElementById('rarProgressContainer');
        rarBox.classList.remove('hidden');

        document.getElementById('rarProgressBar').style.width = '0%';
        document.getElementById('rarProgressPercent').textContent = '0.0%';
        document.getElementById('rarFmtBadge').textContent = initData.archive_format || 'RAR';
        document.getElementById('rarQoBadge').classList.add('hidden');
        document.getElementById('rarStatFiles').textContent = '0 files';
        document.getElementById('rarStatRequests').textContent = '1 request';
        document.getElementById('rarStatBytes').textContent = '0 B';
        document.getElementById('rarStatOffset').textContent = `0 B / ${initData.file_size_str || ''}`;
        document.getElementById('rarStatCurrentFile').textContent = 'Connecting via HTTP Range Requests...';

        const stopBtn = document.getElementById('rarStopBtn');
        stopBtn.disabled = false;
        stopBtn.classList.remove('opacity-50', 'cursor-not-allowed');
        stopBtn.innerHTML = `
            <svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 24 24">
                <rect x="6" y="6" width="12" height="12" rx="2"></rect>
            </svg>
            <span>Stop &amp; View Partial</span>
        `;

        if (rarEventSource) {
            rarEventSource.close();
        }

        // Each scan gets its own id, so Stop only ever affects THIS scan (even with two tabs on one link).
        state.scanId = (window.crypto && crypto.randomUUID)
            ? crypto.randomUUID()
            : (Date.now().toString(36) + Math.random().toString(36).slice(2));
        state.rarFinished = false;
        const qo = state.skipQo ? '0' : '1';
        state.skipQo = false;

        const streamUrl = `/api/rar/scan_stream?url=${encodeURIComponent(state.url)}&scan_id=${encodeURIComponent(state.scanId)}&qo=${qo}`;
        rarEventSource = new EventSource(streamUrl);

        rarEventSource.onmessage = (e) => {
            try {
                const msg = JSON.parse(e.data);
                handleRarStreamEvent(msg);
            } catch (err) {
                console.error("SSE parse error:", err, e.data);
            }
        };

        rarEventSource.onerror = () => {
            if (rarEventSource) {
                rarEventSource.close();
                rarEventSource = null;
            }
            if (!state.rarFinished) {
                state.rarFinished = true;
                document.getElementById('rarProgressContainer').classList.add('hidden');
                showError('Lost the connection to the scan stream before it finished. Press "Inspect Archive" to retry.');
            }
        };
    }

    function handleRarStreamEvent(msg) {
        if (msg.type === 'init') {
            document.getElementById('rarFmtBadge').textContent = msg.fmt;
            document.getElementById('rarStatOffset').textContent = `0 B / ${msg.size_str}`;
        } else if (msg.type === 'qo_found') {
            document.getElementById('rarQoBadge').classList.remove('hidden');
        } else if (msg.type === 'qo_failed') {
            document.getElementById('rarQoBadge').classList.add('hidden');
            document.getElementById('rarStatCurrentFile').textContent = 'Quick Open index not usable, walking every header instead...';
        } else if (msg.type === 'progress') {
            const pct = Math.max(0, Math.min(100, msg.percent));
            document.getElementById('rarProgressBar').style.width = `${pct}%`;
            document.getElementById('rarProgressPercent').textContent = `${pct.toFixed(1)}%`;
            document.getElementById('rarStatFiles').textContent = `${msg.count.toLocaleString()} files`;
            document.getElementById('rarStatRequests').textContent = `${msg.requests} requests`;
            document.getElementById('rarStatBytes').textContent = msg.bytes_read_str;
            document.getElementById('rarStatOffset').textContent = `${msg.offset_str} / ${msg.total_size_str}`;
            if (msg.current_file) {
                document.getElementById('rarStatCurrentFile').textContent = msg.current_file;
            }
        } else if (msg.type === 'complete' || msg.type === 'stopped') {
            state.rarFinished = true;
            if (rarEventSource) {
                rarEventSource.close();
                rarEventSource = null;
            }
            document.getElementById('rarStatCurrentFile').textContent = 'Building file explorer view...';
            setTimeout(() => fetchExplorerData(), 50);
        } else if (msg.type === 'error') {
            state.rarFinished = true;
            if (rarEventSource) {
                rarEventSource.close();
                rarEventSource = null;
            }
            document.getElementById('rarProgressContainer').classList.add('hidden');
            showError(msg.message);
        }
    }

    async function stopRarScan() {
        const stopBtn = document.getElementById('rarStopBtn');
        stopBtn.disabled = true;
        stopBtn.classList.add('opacity-50', 'cursor-not-allowed');
        stopBtn.innerHTML = `
            <svg class="animate-spin w-3.5 h-3.5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <span>Stopping...</span>
        `;
        try {
            await fetch(`/api/rar/stop?scan_id=${encodeURIComponent(state.scanId || '')}`, { method: 'POST' });
        } catch (e) {
            console.error("Stop error:", e);
        }
    }

    // skipQuickOpen = true  ->  ignore the Quick Open index and walk every header (used to verify it)
    async function rescanRar(skipQuickOpen) {
        try {
            state.skipQo = !!skipQuickOpen;
            await fetch(`/api/rar/rescan?url=${encodeURIComponent(state.url)}`, { method: 'POST' });
            fetchExplorerData();
        } catch (e) {
            console.error("Rescan clear error:", e);
        }
    }

    function copyFolderLink(folderPath, event) {
        if (event) event.stopPropagation();
        const link = window.location.origin + `/download_folder?url=${encodeURIComponent(state.url)}&folder=${encodeURIComponent(folderPath)}`;
        copyToClipboard(link, () => alert("Direct folder download link copied to clipboard!"));
    }

    function escapeHtml(text) {
        if (!text) return '';
        return String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    }

    function renderBreadcrumbs() {
        const trail = document.getElementById('breadcrumbTrail');
        trail.innerHTML = '';
        if (!state.path) return;

        const parts = state.path.split('/');
        let accum = "";
        const fragment = document.createDocumentFragment();

        parts.forEach((part, index) => {
            accum += (index === 0 ? "" : "/") + part;
            const target = accum;

            const sep = document.createElement('span');
            sep.className = "text-slate-300";
            sep.textContent = "/";
            fragment.appendChild(sep);

            const link = document.createElement('span');
            link.className = "hover:text-indigo-600 cursor-pointer transition max-w-[140px] truncate";
            link.textContent = part;
            link.onclick = () => navigateTo(target);
            fragment.appendChild(link);
        });

        trail.appendChild(fragment);
    }

    function getCategoryIcon(cat, encrypted) {
        if (encrypted) {
            return `<svg class="w-4 h-4 text-amber-500 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z"></path></svg>`;
        }
        switch(cat) {
            case 'code':
                return `<svg class="w-4 h-4 text-sky-500 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5"></path></svg>`;
            case 'image':
                return `<svg class="w-4 h-4 text-emerald-500 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M2.25 15.75l5.159-5.159a2.25 2.25 0 013.182 0l5.159 5.159m-1.5-1.5l1.409-1.409a2.25 2.25 0 013.182 0l2.909 2.909m-18 3.75h16.5a1.5 1.5 0 001.5-1.5V6a1.5 1.5 0 00-1.5-1.5H3.75A1.5 1.5 0 002.25 6v12a1.5 1.5 0 001.5 1.5zm10.5-11.25h.008v.008h-.008V8.25zm.375 0a.375.375 0 11-.75 0 .375.375 0 01.75 0z"></path></svg>`;
            case 'audio':
                return `<svg class="w-4 h-4 text-purple-500 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 9l10.5-3m0 6.553v3.75a2.25 2.25 0 01-1.632 2.163l-1.32.377a1.875 1.875 0 01-2.298-1.815V15.75m5.25-6.553l-5.25 1.5m0 0v5.25"></path></svg>`;
            case 'doc':
                return `<svg class="w-4 h-4 text-indigo-500 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z"></path></svg>`;
            case 'archive':
                return `<svg class="w-4 h-4 text-rose-500 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M20.25 7.5l-.625 10.632a2.25 2.25 0 01-2.247 2.118H6.622a2.25 2.25 0 01-2.247-2.118L3.75 7.5"></path></svg>`;
            default:
                return `<svg class="w-4 h-4 text-slate-400 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z"></path></svg>`;
        }
    }

    // A RAR entry whose bytes can't be read from this single URL (compressed, split, or encrypted)
    function rarNoDownload(file) {
        return file.archive_type === 'rar' && (!file.stored || file.prev || file.next || file.encrypted);
    }

    function renderTable(data) {
        const tbody = document.getElementById('tableBody');
        const empty = document.getElementById('emptyState');
        tbody.innerHTML = '';

        const subfolders = data.subfolders || [];
        const files = data.files || [];
        currentRenderedFiles = files;

        if (subfolders.length === 0 && files.length === 0) {
            empty.classList.remove('hidden');
            return;
        }
        empty.classList.add('hidden');

        const fragment = document.createDocumentFragment();

        if (state.path && !state.q) {
            const tr = document.createElement('tr');
            tr.className = "hover:bg-slate-50/60 transition duration-150 cursor-pointer text-indigo-600 font-semibold";
            tr.onclick = goUp;
            tr.innerHTML = `
                <td class="py-2.5 px-4 text-center"></td>
                <td class="py-2.5 px-4 flex items-center gap-2" colspan="6">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M9 15L3 9m0 0l6-6M3 9h12a6 6 0 010 12h-3"></path>
                    </svg>
                    <span>.. (Go Up)</span>
                </td>
            `;
            fragment.appendChild(tr);
        }

        subfolders.forEach(folder => {
            const tr = document.createElement('tr');
            tr.className = "hover:bg-slate-50/60 transition duration-150 cursor-pointer";
            tr.onclick = () => navigateTo(folder.path);
            tr.innerHTML = `
                <td class="py-2.5 px-4 text-center"></td>
                <td class="py-2.5 px-4 font-semibold text-slate-800 flex items-center gap-2">
                    <svg class="w-4 h-4 text-amber-500 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.381c-.597 0-1.17-.237-1.597-.664z"></path>
                    </svg>
                    <span class="truncate">${escapeHtml(folder.name)}</span>
                    <span class="text-[10px] font-normal px-2 py-0.5 bg-slate-100 text-slate-500 rounded-full">${folder.total_files} items · ${folder.total_size}</span>
                </td>
                <td class="py-2.5 px-4 text-slate-400 font-mono text-xs">${folder.total_size}</td>
                <td class="py-2.5 px-4 text-slate-400 font-mono text-xs hidden md:table-cell">-</td>
                <td class="py-2.5 px-4 text-slate-400 text-xs hidden sm:table-cell">-</td>
                <td class="py-2.5 px-4 text-slate-400 text-xs hidden lg:table-cell">-</td>
                <td class="py-2.5 px-4 text-right whitespace-nowrap">
                    <div class="flex items-center justify-end gap-1.5">
                        <button onclick="copyFolderLink('${escapeHtml(folder.path)}', event)" 
                                class="p-1 bg-slate-100 hover:bg-slate-200 text-slate-600 rounded-lg transition" 
                                title="Copy Direct External Link">
                            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244m6.561-2.02l-1.584-1.584"></path>
                            </svg>
                        </button>
                        <a href="/download_folder?url=${encodeURIComponent(state.url)}&folder=${encodeURIComponent(folder.path)}" 
                           onclick="event.stopPropagation()" 
                           class="p-1 bg-slate-100 hover:bg-indigo-600 hover:text-white text-slate-600 rounded-lg transition" 
                           title="Download Folder (.zip)">
                            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3"></path>
                            </svg>
                        </a>
                        <span class="text-xs font-semibold text-indigo-600 hover:text-indigo-800 ml-1">Open &rarr;</span>
                    </div>
                </td>
            `;
            fragment.appendChild(tr);
        });

        files.forEach((file, index) => {
            const isChecked = state.selectedFiles.has(file.name);
            const noData = rarNoDownload(file);
            const tr = document.createElement('tr');
            tr.className = "hover:bg-slate-50/60 transition duration-150 group";
            tr.innerHTML = `
                <td class="py-2.5 px-4 text-center">
                    <input type="checkbox" onchange="toggleFileSelectionByIndex(this, ${index})" 
                           ${isChecked ? 'checked' : ''} ${noData ? 'disabled' : ''}
                           class="file-checkbox rounded border-slate-300 text-indigo-600 focus:ring-indigo-500 ${noData ? 'opacity-30' : ''}">
                </td>
                <td class="py-2.5 px-4">
                    <div class="flex items-center gap-2 min-w-0">
                        ${getCategoryIcon(file.category, file.encrypted)}
                        <span onclick="openInspectorByIndex(${index})" 
                              class="font-semibold text-slate-900 hover:text-indigo-600 hover:underline cursor-pointer truncate" 
                              title="${escapeHtml(file.name)}">
                            ${escapeHtml(file.filename_only)}
                        </span>
                        ${state.q ? `<span class="text-[10px] text-slate-400 font-mono truncate max-w-xs">(${escapeHtml(file.folder_path)})</span>` : ''}
                    </div>
                </td>
                <td class="py-2.5 px-4 font-mono text-slate-700 text-xs">${file.size_str}</td>
                <td class="py-2.5 px-4 font-mono text-slate-500 text-xs hidden md:table-cell">${file.comp_size_str}</td>
                <td class="py-2.5 px-4 text-xs font-semibold text-emerald-600 hidden sm:table-cell">${file.ratio}</td>
                <td class="py-2.5 px-4 text-slate-500 text-xs hidden lg:table-cell">${file.date}</td>
                <td class="py-2.5 px-4 text-right whitespace-nowrap">
                    <div class="flex items-center justify-end gap-1.5">
                        <button onclick="openInspectorByIndex(${index})" 
                                class="px-2 py-1 bg-slate-100 hover:bg-indigo-50 hover:text-indigo-600 text-slate-700 text-xs font-semibold rounded-lg transition" title="Inspect">
                            Inspect
                        </button>
                        <a href="/download?url=${encodeURIComponent(state.url)}&filename=${encodeURIComponent(file.name)}" 
                           ${noData ? 'aria-disabled="true" tabindex="-1"' : ''}
                           class="p-1 bg-slate-100 hover:bg-indigo-600 hover:text-white text-slate-600 rounded-lg transition ${noData ? 'opacity-30 pointer-events-none' : ''}" title="${noData ? 'Not downloadable from a RAR (compressed, split or encrypted)' : 'Download'}">
                            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3"></path>
                            </svg>
                        </a>
                    </div>
                </td>
            `;
            fragment.appendChild(tr);
        });

        tbody.appendChild(fragment);
        updateSelectAllState();
    }

    function renderPagination(data) {
        const info = document.getElementById('paginationInfo');
        const container = document.getElementById('paginationButtons');
        container.innerHTML = '';

        const total = data.total_files || 0;
        const page = data.page || 1;
        const totalPages = data.total_pages || 1;
        const start = total === 0 ? 0 : (page - 1) * state.limit + 1;
        const end = Math.min(page * state.limit, total);

        info.textContent = `Showing ${start.toLocaleString()} - ${end.toLocaleString()} of ${total.toLocaleString()} items`;

        if (totalPages <= 1) return;

        const fragment = document.createDocumentFragment();

        const prevBtn = document.createElement('button');
        prevBtn.className = `px-2.5 py-1 rounded-lg border border-slate-200 text-xs font-semibold ${page > 1 ? 'hover:bg-slate-50 text-slate-700' : 'text-slate-300 cursor-not-allowed'}`;
        prevBtn.textContent = "Prev";
        prevBtn.disabled = page <= 1;
        prevBtn.onclick = () => { if (page > 1) { state.page--; syncHashState(); fetchExplorerData(); } };
        fragment.appendChild(prevBtn);

        const nextBtn = document.createElement('button');
        nextBtn.className = `px-2.5 py-1 rounded-lg border border-slate-200 text-xs font-semibold ${page < totalPages ? 'hover:bg-slate-50 text-slate-700' : 'text-slate-300 cursor-not-allowed'}`;
        nextBtn.textContent = "Next";
        nextBtn.disabled = page >= totalPages;
        nextBtn.onclick = () => { if (page < totalPages) { state.page++; syncHashState(); fetchExplorerData(); } };
        fragment.appendChild(nextBtn);

        container.appendChild(fragment);
    }

    function navigateTo(path) {
        state.path = path;
        state.q = "";
        state.page = 1;
        document.getElementById('searchInput').value = "";
        syncHashState();
        fetchExplorerData();
    }

    function goUp() {
        if (!state.path) return;
        const parts = state.path.split('/');
        parts.pop();
        navigateTo(parts.join('/'));
    }

    function onSearchInput() {
        clearTimeout(searchDebounce);
        searchDebounce = setTimeout(() => {
            state.q = document.getElementById('searchInput').value.trim();
            state.page = 1;
            syncHashState();
            fetchExplorerData();
        }, 250);
    }

    function onScopeChange() {
        state.scope = document.getElementById('scopeSelect').value;
        state.page = 1;
        syncHashState();
        fetchExplorerData();
    }

    function onPageSizeChange() {
        state.limit = parseInt(document.getElementById('pageSizeSelect').value) || 50;
        state.page = 1;
        syncHashState();
        fetchExplorerData();
    }

    function setCategory(cat) {
        state.cat = cat;
        state.page = 1;
        updateCategoryPills();
        syncHashState();
        fetchExplorerData();
    }

    function updateCategoryPills() {
        document.querySelectorAll('.cat-chip').forEach(btn => {
            if (btn.getAttribute('data-cat') === state.cat) {
                btn.className = "cat-chip px-3 py-1.5 text-xs font-semibold rounded-lg bg-indigo-600 text-white shadow-sm transition";
            } else {
                btn.className = "cat-chip px-3 py-1.5 text-xs font-semibold rounded-lg bg-white border border-slate-200 text-slate-600 hover:bg-slate-50 transition";
            }
        });
    }

    function toggleSort(col) {
        if (state.sort === col) {
            state.order = state.order === 'asc' ? 'desc' : 'asc';
        } else {
            state.sort = col;
            state.order = 'asc';
        }
        syncHashState();
        fetchExplorerData();
    }

    function updateSortIcons() {
        ['name', 'size', 'comp_size', 'ratio', 'date'].forEach(col => {
            const el = document.getElementById(`sort_icon_${col}`);
            if (!el) return;
            if (state.sort === col) {
                el.textContent = state.order === 'asc' ? '▲' : '▼';
                el.className = "text-indigo-600";
            } else {
                el.textContent = '↕';
                el.className = "text-slate-400";
            }
        });
    }

    function toggleFileSelectionByIndex(checkbox, index) {
        const file = currentRenderedFiles[index];
        if (!file) return;
        if (checkbox.checked) {
            state.selectedFiles.set(file.name, file);
        } else {
            state.selectedFiles.delete(file.name);
        }
        updateBatchToolbar();
        updateSelectAllState();
    }

    function toggleSelectAll(masterCheckbox) {
        const checkboxes = document.querySelectorAll('.file-checkbox');
        checkboxes.forEach(cb => {
            if (cb.disabled) return;
            cb.checked = masterCheckbox.checked;
            cb.dispatchEvent(new Event('change'));
        });
    }

    function updateSelectAllState() {
        const master = document.getElementById('selectAllCheckbox');
        const checkboxes = Array.from(document.querySelectorAll('.file-checkbox')).filter(cb => !cb.disabled);
        if (checkboxes.length === 0) {
            master.checked = false;
            return;
        }
        master.checked = checkboxes.every(cb => cb.checked);
    }

    function updateBatchToolbar() {
        const bar = document.getElementById('batchToolbar');
        const count = document.getElementById('selectedCount');
        count.textContent = state.selectedFiles.size;
        if (state.selectedFiles.size > 0) {
            bar.classList.remove('hidden');
        } else {
            bar.classList.add('hidden');
        }
    }

    function clearSelection() {
        state.selectedFiles.clear();
        document.querySelectorAll('.file-checkbox').forEach(cb => cb.checked = false);
        document.getElementById('selectAllCheckbox').checked = false;
        updateBatchToolbar();
    }

    function getBatchDownloadUrl() {
        const fileNames = Array.from(state.selectedFiles.values()).map(f => f.name);
        return window.location.origin + `/download_batch?url=${encodeURIComponent(state.url)}&files=${encodeURIComponent(fileNames.join(','))}`;
    }

    function downloadSelectedZip() {
        if (state.selectedFiles.size === 0) return;
        window.location.href = getBatchDownloadUrl();
    }

    function openBatchModal(type) {
        const modal = document.getElementById('batchModal');
        const title = document.getElementById('batchModalTitle');
        const area = document.getElementById('batchScriptArea');
        const count = state.selectedFiles.size;
        const singleUrl = getBatchDownloadUrl();

        if (type === 'curl') {
            title.textContent = `Single cURL Command (${count} files)`;
            area.value = `curl -L -o "selected_files.zip" "${singleUrl}"`;
        } else if (type === 'powershell') {
            title.textContent = `Single PowerShell Command (${count} files)`;
            area.value = `Invoke-WebRequest -Uri "${singleUrl}" -OutFile "selected_files.zip"`;
        } else if (type === 'wget') {
            title.textContent = `Single Wget Command (${count} files)`;
            area.value = `wget -O "selected_files.zip" "${singleUrl}"`;
        } else {
            title.textContent = `Single Direct Download Link (${count} files as .zip)`;
            area.value = singleUrl;
        }

        modal.classList.remove('hidden');
        void modal.offsetWidth;
        modal.classList.remove('opacity-0');
    }

    function closeBatchModal() {
        const modal = document.getElementById('batchModal');
        modal.classList.add('opacity-0');
        setTimeout(() => modal.classList.add('hidden'), 200);
    }

    function copyBatchScript() {
        const area = document.getElementById('batchScriptArea');
        copyToClipboard(area.value, () => {
            const btn = document.getElementById('batchCopyBtn');
            const orig = btn.textContent;
            btn.textContent = "Copied!";
            setTimeout(() => btn.textContent = orig, 1500);
        });
    }

    // Modal controllers
    function openGuideModal(initialTab = 'linkRules') {
        const modal = document.getElementById('guideModal');
        switchGuideTab(initialTab);
        modal.classList.remove('hidden');
        void modal.offsetWidth;
        modal.classList.remove('opacity-0');
        modal.querySelector('div').classList.remove('scale-95');
    }

    function closeGuideModal() {
        const modal = document.getElementById('guideModal');
        modal.classList.add('opacity-0');
        modal.querySelector('div').classList.add('scale-95');
        setTimeout(() => modal.classList.add('hidden'), 200);
    }

    function switchGuideTab(tabId) {
        const tabs = ['linkRules', 'rarMode', 'copying', 'troubleshooting'];
        tabs.forEach(t => {
            const pane = document.getElementById(`guidePanel_${t}`);
            const btn = document.getElementById(`guideNavBtn_${t}`);
            if (!pane || !btn) return;

            if (t === tabId) {
                pane.classList.remove('hidden');
                btn.className = "guide-tab-btn px-4 py-3 border-b-2 border-indigo-600 text-indigo-600 font-bold whitespace-nowrap transition cursor-pointer";
            } else {
                pane.classList.add('hidden');
                btn.className = "guide-tab-btn px-4 py-3 border-b-2 border-transparent text-slate-500 hover:text-slate-800 font-medium whitespace-nowrap transition cursor-pointer";
            }
        });
    }

    window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeGuideModal();
            closeModal();
            closeBatchModal();
        }
    });

    function openInspectorByIndex(index) {
        const file = currentRenderedFiles[index];
        if (file) openInspector(file);
    }

    function openInspector(file) {
        state.activeFile = file;
        state.markdownFormatted = false;

        document.getElementById('modalFilename').textContent = file.filename_only;
        document.getElementById('modalPath').textContent = file.name;
        const dlBtn = document.getElementById('modalDownloadBtn');

        if (rarNoDownload(file)) {
            dlBtn.removeAttribute('href');
            dlBtn.classList.add('opacity-40', 'pointer-events-none', 'bg-slate-400');
            dlBtn.classList.remove('bg-indigo-600', 'hover:bg-indigo-700');
            dlBtn.title = "This RAR entry is compressed, split across volumes, or encrypted, so it cannot be downloaded from the remote file.";
        } else {
            dlBtn.href = `/download?url=${encodeURIComponent(state.url)}&filename=${encodeURIComponent(file.name)}`;
            dlBtn.classList.remove('opacity-40', 'pointer-events-none', 'bg-slate-400');
            dlBtn.classList.add('bg-indigo-600', 'hover:bg-indigo-700');
            dlBtn.title = "Download file";
        }

        document.getElementById('metaSize').textContent = file.size_str;
        document.getElementById('metaCompSize').textContent = file.comp_size_str;
        document.getElementById('metaRatio').textContent = file.ratio;
        document.getElementById('metaMethod').textContent = file.method;
        document.getElementById('metaCRC').textContent = file.crc32;
        document.getElementById('metaDate').textContent = file.date;
        
        const encEl = document.getElementById('metaEncrypted');
        encEl.textContent = file.encrypted ? "Password Protected (Encrypted)" : "No (Standard)";
        encEl.className = file.encrypted ? "font-bold text-sm text-amber-600" : "font-bold text-sm text-emerald-600";

        switchTab('preview');
        loadPreviewContent(file);

        const modal = document.getElementById('inspectorModal');
        modal.classList.remove('hidden');
        void modal.offsetWidth;
        modal.classList.remove('opacity-0');
    }

    function closeModal() {
        const modal = document.getElementById('inspectorModal');
        modal.classList.add('opacity-0');
        setTimeout(() => {
            modal.classList.add('hidden');
            // Stop audio playback immediately
            const audio = document.getElementById('audioPreviewTag');
            if (audio) { audio.pause(); audio.src = ""; }
            // Clear image and PDF iframe to release RAM
            const img = document.getElementById('imagePreviewTag');
            if (img) img.src = "";
            const pdf = document.getElementById('pdfPreviewTag');
            if (pdf) pdf.src = "about:blank";
        }, 200);
    }

    function switchTab(tab) {
        ['preview', 'metadata', 'hex'].forEach(t => {
            const pane = document.getElementById(`pane${t.charAt(0).toUpperCase() + t.slice(1)}`);
            const btn = document.getElementById(`tabBtn${t.charAt(0).toUpperCase() + t.slice(1)}`);
            if (t === tab) {
                pane.classList.remove('hidden');
                btn.className = "py-3 border-b-2 border-indigo-600 text-indigo-600 transition";
            } else {
                pane.classList.add('hidden');
                btn.className = "py-3 border-b-2 border-transparent hover:text-slate-900 transition";
            }
        });

        if (tab === 'hex' && state.activeFile) {
            loadHexContent(state.activeFile);
        }
    }

    async function loadPreviewContent(file) {
        const ext = '.' + file.name.split('.').pop().toLowerCase();
        const rawUrl = `/api/raw?url=${encodeURIComponent(state.url)}&filename=${encodeURIComponent(file.name)}`;
        const loader = document.getElementById('previewLoader');

        // 1. Reset & hide all preview containers
        [
            'imagePreviewBox', 'audioPreviewBox', 'codePreviewBox',
            'pdfPreviewTag', 'csvPreviewBox', 'unsupportedPreviewBox'
        ].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.classList.add('hidden');
        });

        // 2. RAR entries whose data cannot be read from this one URL
        const isRar = file.archive_type === 'rar';
        if (isRar && (file.prev || file.next || file.encrypted)) {
            document.getElementById('unsupportedTitle').textContent = file.encrypted ? 'Password Protected RAR Entry' : 'Split RAR Entry';
            document.getElementById('unsupportedSub').innerHTML = file.encrypted
                ? 'The data is encrypted. Use the <strong>Hex View</strong> tab to inspect the raw packed bytes.'
                : 'This entry continues in another volume, so its data is not contiguous in this file.';
            document.getElementById('unsupportedPreviewBox').classList.remove('hidden');
            return;
        }

        // 3. Compressed RAR entries: text/code/doc/image can be unpacked server-side; the rest cannot
        const isCompressedRar = isRar && !file.stored;
        const isPreviewable = file.category === 'code' || file.category === 'doc' || file.category === 'image';

        if (isCompressedRar && !isPreviewable) {
            document.getElementById('unsupportedTitle').textContent = `Compressed RAR Entry (${file.method || 'Solid'})`;
            document.getElementById('unsupportedSub').innerHTML = 
                'Binary file inside a compressed RAR. Use the <strong>Hex View</strong> tab to inspect raw packed bytes.';
            document.getElementById('unsupportedPreviewBox').classList.remove('hidden');
            return;
        }

        // 4. Images (with loading spinner & error handling)
        if (file.category === 'image') {
            loader.classList.remove('hidden');
            const img = document.getElementById('imagePreviewTag');
            const imgBox = document.getElementById('imagePreviewBox');

            img.onload = () => {
                loader.classList.add('hidden');
                imgBox.classList.remove('hidden');
            };

            img.onerror = async () => {
                loader.classList.add('hidden');
                imgBox.classList.add('hidden');
                try {
                    const errRes = await fetch(rawUrl);
                    if (!errRes.ok) {
                        const errText = await errRes.text();
                        showUnsupportedError(errText);
                    } else {
                        showUnsupportedError('This image could not be decoded.');
                    }
                } catch (_) {
                    showUnsupportedError('Image could not be loaded from remote archive.');
                }
            };

            img.src = rawUrl;
        }
        // 5. Audio
        else if (file.category === 'audio') {
            const audio = document.getElementById('audioPreviewTag');
            audio.src = rawUrl;
            document.getElementById('audioPreviewBox').classList.remove('hidden');
        }
        // 6. PDF Documents
        else if (ext === '.pdf') {
            const pdf = document.getElementById('pdfPreviewTag');
            pdf.src = rawUrl;
            pdf.classList.remove('hidden');
        }
        // 7. CSV Files
        else if (ext === '.csv') {
            loader.classList.remove('hidden');
            try {
                const res = await fetch(`/api/view?url=${encodeURIComponent(state.url)}&filename=${encodeURIComponent(file.name)}&mode=text`);
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || "Failed to load CSV");
                loader.classList.add('hidden');

                const rows = data.content.trim().split('\n').map(r => r.split(','));
                const table = document.getElementById('csvTable');
                table.innerHTML = rows.map((cols, i) => `
                    <tr class="${i === 0 ? 'bg-slate-100 font-bold sticky top-0 text-slate-700' : 'hover:bg-slate-50 border-t border-slate-100'}">
                        <td class="p-2 text-slate-400 font-mono text-[10px] w-8 select-none">${i + 1}</td>
                        ${cols.map(c => `<td class="p-2 border-l border-slate-200 truncate max-w-xs">${escapeHtml(c.trim())}</td>`).join('')}
                    </tr>
                `).join('');
                document.getElementById('csvPreviewBox').classList.remove('hidden');
            } catch (e) {
                loader.classList.add('hidden');
                showUnsupportedError(e.message);
            }
        }
        // 8. Code & Text Documents (.txt, .json, .url, .nfo, .ini, .md, .xml, .yaml, etc.)
        else if (file.category === 'code' || file.category === 'doc') {
            if (['.doc', '.docx', '.xls', '.xlsx'].includes(ext)) {
                showUnsupportedError(`Binary Office Document (${ext.toUpperCase()}). Please download to view.`);
                return;
            }

            loader.classList.remove('hidden');
            try {
                const res = await fetch(`/api/view?url=${encodeURIComponent(state.url)}&filename=${encodeURIComponent(file.name)}&mode=text`);
                const data = await res.json();
                loader.classList.add('hidden');

                if (!res.ok) {
                    throw new Error(data.error || "Could not read text content");
                }

                let textContent = data.content;

                // 🌟 Auto-format JSON files if minified
                if (ext === '.json') {
                    try {
                        const parsed = JSON.parse(textContent);
                        textContent = JSON.stringify(parsed, null, 2);
                    } catch (_) {}
                }

                state.rawTextContent = textContent;
                const codeBlock = document.getElementById('codeBlock');
                codeBlock.textContent = textContent;

                // Map extension to Prism syntax language
                const langMap = {
                    '.url': 'ini',
                    '.ini': 'ini',
                    '.cfg': 'ini',
                    '.conf': 'ini',
                    '.nfo': 'plaintext',
                    '.diz': 'plaintext',
                    '.log': 'plaintext',
                    '.reg': 'ini'
                };
                const lang = langMap[ext] || ext.replace('.', '') || 'plaintext';
                codeBlock.className = `language-${lang}`;
                Prism.highlightElement(codeBlock);

                // 🌟 Special banner for .url Internet Shortcuts
                if (ext === '.url') {
                    const match = textContent.match(/^URL=(.+)$/im);
                    if (match && match[1] && /^https?:\/\//i.test(match[1].trim())) {
                        const targetUrl = match[1].trim();
                        document.getElementById('codeLangBadge').innerHTML = 
                            `URL SHORTCUT &mdash; <a href="${escapeHtml(targetUrl)}" target="_blank" rel="noopener noreferrer" class="text-indigo-400 hover:text-indigo-300 underline font-semibold">Open: ${escapeHtml(targetUrl)} &nearr;</a>`;
                    } else {
                        document.getElementById('codeLangBadge').textContent = 'URL SHORTCUT';
                    }
                } else {
                    document.getElementById('codeLangBadge').textContent = ext.replace('.', '').toUpperCase();
                }

                document.getElementById('mdToggleBtn').classList.toggle('hidden', ext !== '.md');
                document.getElementById('markdownRendered').classList.add('hidden');
                document.querySelector('#codePreviewBox pre').classList.remove('hidden');
                document.getElementById('codePreviewBox').classList.remove('hidden');
            } catch (e) {
                loader.classList.add('hidden');
                showUnsupportedError(e.message);
            }
        }
        else {
            showUnsupportedError('Inline preview is not supported for this file type.');
        }
    }

    function showUnsupportedError(msg) {
        document.getElementById('unsupportedTitle').textContent = 'Preview Unavailable';
        document.getElementById('unsupportedSub').innerHTML = `${escapeHtml(msg)}<br>Use the <strong>Hex View</strong> tab to inspect binary bytes.`;
        document.getElementById('unsupportedPreviewBox').classList.remove('hidden');
    }

    async function loadHexContent(file) {
        const hexContainer = document.getElementById('hexContainer');
        const loader = document.getElementById('hexLoader');
        hexContainer.textContent = "";
        loader.classList.remove('hidden');

        try {
            const res = await fetch(`/api/view?url=${encodeURIComponent(state.url)}&filename=${encodeURIComponent(file.name)}&mode=hex`);
            const data = await res.json();
            loader.classList.add('hidden');
            if (!res.ok) throw new Error(data.error || "Hex dump failed");

            const formatted = data.hex_dump.map(line => `${line.offset}  ${line.hex}  |${line.ascii}|`).join("\n");
            hexContainer.textContent = formatted + (data.truncated ? "\n\n[... Truncated to first 4KB ...]" : "");
        } catch (err) {
            loader.classList.add('hidden');
            hexContainer.textContent = "Error generating hex dump: " + err.message;
        }
    }

    function toggleMarkdown() {
        const mdRendered = document.getElementById('markdownRendered');
        const codePre = document.querySelector('#codePreviewBox pre');
        const btn = document.getElementById('mdToggleBtn');

        state.markdownFormatted = !state.markdownFormatted;
        if (state.markdownFormatted) {
            mdRendered.innerHTML = marked.parse(state.rawTextContent);
            mdRendered.classList.remove('hidden');
            codePre.classList.add('hidden');
            btn.textContent = "View Raw";
        } else {
            mdRendered.classList.add('hidden');
            codePre.classList.remove('hidden');
            btn.textContent = "View Formatted";
        }
    }

    function copyCode() {
        copyToClipboard(state.rawTextContent, () => alert("Content copied to clipboard!"));
    }

    function copyDirectLink() {
        if (!state.activeFile) return;
        const link = window.location.origin + `/download?url=${encodeURIComponent(state.url)}&filename=${encodeURIComponent(state.activeFile.name)}`;
        copyToClipboard(link, () => alert("Direct download link copied to clipboard!"));
    }

    function copyToClipboard(text, callback) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(callback).catch(() => fallbackCopy(text, callback));
        } else {
            fallbackCopy(text, callback);
        }
    }

    function fallbackCopy(text, callback) {
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        try {
            document.execCommand('copy');
            if (callback) callback();
        } catch (e) {
            console.error('Copy fallback error:', e);
        }
        document.body.removeChild(ta);
    }
    </script>
</body>
</html>
"""


# ======================================================================
# 6. API, STREAMING & DOWNLOAD ROUTES (ZIP + RAR)
# ======================================================================
@app.route('/', methods=['GET'])
def index():
    url = request.args.get('url', '')
    return render_template_string(HTML_TEMPLATE, url=url)


@app.route('/api/list', methods=['GET'])
def api_list():
    url = request.args.get('url')
    if not url:
        return jsonify(error="Missing 'url' parameter"), 400

    url = resolve_download_url(url)
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        return jsonify(error="Invalid URL scheme. Only HTTP and HTTPS are supported."), 400

    path = request.args.get('path', '').strip('/')
    q = request.args.get('q', '').strip()
    scope = request.args.get('scope', 'current')
    category = request.args.get('cat', 'all')
    sort_by = request.args.get('sort', 'name')
    order = request.args.get('order', 'asc')
    
    try:
        page = max(1, int(request.args.get('page', 1)))
        limit = min(200, max(10, int(request.args.get('limit', 50))))
    except ValueError:
        page, limit = 1, 50

    cache_entry = None
    with ZIP_CACHE_LOCK:
        if url in ZIP_CACHE:
            ZIP_CACHE[url]['timestamp'] = time.time()
            cache_entry = ZIP_CACHE[url]

    # IF NOT IN CACHE: Check magic bytes to determine if it is RAR or ZIP
    if not cache_entry:
        try:
            headers = dict(DEFAULT_HEADERS, Range="bytes=0-15")
            headers["Accept-Encoding"] = "identity"
            with requests.get(url, headers=headers, timeout=(10, 15), stream=True) as probe_resp:
                if probe_resp.status_code != 206:
                    return jsonify(error=f"Server returned HTTP {probe_resp.status_code} (HTTP Range Requests not supported)."), 400
                magic = b"".join(probe_resp.iter_content(16))[:16]

                # Check for RAR4 / RAR5 signature
                if magic.startswith(RAR5_SIG) or magic.startswith(RAR4_SIG):
                    fmt = "RAR5" if magic.startswith(RAR5_SIG) else "RAR4"
                    crange = probe_resp.headers.get("Content-Range", "")
                    tail = crange.rsplit("/", 1)[-1]
                    total_sz = int(tail) if tail.isdigit() else None
                    return jsonify(
                        is_rar=True,
                        archive_format=fmt,
                        file_size=total_sz,
                        file_size_str=format_size(total_sz),
                        resolved_url=probe_resp.url or url
                    )
        except Exception as e:
            return jsonify(error=f"Remote probe failed: {e}"), 500

        # Run Standard ZIP Central Directory Inspector
        try:
            tree = {"": {"file_ids": [], "subfolders": set()}}
            flat_files = []
            total_uncomp_size = 0
            total_comp_size = 0
            zip_infos = {}
            with RemoteZip(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=NETWORK_TIMEOUT, support_suffix_range=False) as rz:
                for info in rz.infolist():
                    norm_name = info.filename.replace('\\', '/')
                    zip_infos[norm_name] = info
                    parts = norm_name.rstrip('/').split('/')
                    
                    if norm_name.endswith('/'):
                        current_trace = ""
                        for part in parts:
                            trace_parent = current_trace
                            current_trace = part if current_trace == "" else current_trace + "/" + part
                            if trace_parent not in tree:
                                tree[trace_parent] = {"file_ids": [], "subfolders": set()}
                            tree[trace_parent]["subfolders"].add(part)
                        continue

                    filename_only = parts[-1]
                    parent_path = "/".join(parts[:-1]) if len(parts) > 1 else ""
                    
                    file_size = info.file_size
                    comp_size = info.compress_size
                    total_uncomp_size += file_size
                    total_comp_size += comp_size

                    ratio = 0
                    if file_size > 0:
                        ratio = round((1 - (comp_size / file_size)) * 100, 1)
                        if ratio < 0: ratio = 0

                    dt = info.date_time
                    date_str = f"{dt[0]:04d}-{dt[1]:02d}-{dt[2]:02d} {dt[3]:02d}:{dt[4]:02d}:{dt[5]:02d}" if dt else "N/A"
                    _, ext = os.path.splitext(filename_only)

                    file_id = len(flat_files)

                    file_obj = {
                        'id': file_id,
                        'name': norm_name,
                        'filename_only': filename_only,
                        'folder_path': parent_path if parent_path else "/",
                        'size': file_size,
                        'size_str': format_size(file_size),
                        'comp_size': comp_size,
                        'comp_size_str': format_size(comp_size),
                        'ratio': f"{ratio}%",
                        'ratio_num': ratio,
                        'crc32': f"0x{info.CRC:08X}",
                        'encrypted': bool(info.flag_bits & 0x1),
                        'method': get_compress_method_name(info.compress_type),
                        'date': date_str,
                        'category': infer_category(ext),
                        'archive_type': 'zip'
                    }
                    flat_files.append(file_obj)

                    if parent_path not in tree:
                        tree[parent_path] = {"file_ids": [], "subfolders": set()}
                    tree[parent_path]["file_ids"].append(file_id)

                    current_trace = ""
                    for part in parts[:-1]:
                        trace_parent = current_trace
                        current_trace = part if current_trace == "" else current_trace + "/" + part
                        if trace_parent not in tree:
                            tree[trace_parent] = {"file_ids": [], "subfolders": set()}
                        tree[trace_parent]["subfolders"].add(part)

            overall_ratio = 0
            if total_uncomp_size > 0:
                overall_ratio = round((1 - (total_comp_size / total_uncomp_size)) * 100, 1)

            archive_stats = {
                'total_files': len(flat_files),
                'total_size': format_size(total_uncomp_size),
                'total_comp_size': format_size(total_comp_size),
                'total_ratio': f"{overall_ratio}%",
                'archive_format': 'ZIP',
                'partial': False
            }

            with ZIP_CACHE_LOCK:
                if url not in ZIP_CACHE and len(ZIP_CACHE) >= MAX_CACHE_ENTRIES:
                    oldest = min(ZIP_CACHE.keys(), key=lambda k: ZIP_CACHE[k]['timestamp'])
                    ZIP_CACHE.pop(oldest, None)
                ZIP_CACHE[url] = {
                    'tree': tree,
                    'flat_files': flat_files,
                    'archive_stats': archive_stats,
                    'timestamp': time.time(),
                    'archive_type': 'zip'
                }
                cache_entry = ZIP_CACHE[url]

        except Exception as e:
            return jsonify(error=f"Failed to inspect ZIP: {str(e)}."), 500

    tree = cache_entry['tree']
    flat_files = cache_entry['flat_files']
    subfolders_result = []
    matched_files = []

    def matches_category(f):
        if category == 'all': return True
        if category == 'large': return f['size'] >= 10 * 1024 * 1024
        return f['category'] == category

    def get_folder_metrics(folder_prefix):
        count = 0
        total_b = 0
        prefix = folder_prefix + "/"
        for f in flat_files:
            if f['name'].startswith(prefix):
                count += 1
                total_b += f['size']
        return count, total_b, format_size(total_b)

    if q:
        q_lower = q.lower()
        has_wildcard = '*' in q or '?' in q or '[' in q

        if has_wildcard:
            matcher = lambda f: (
                fnmatch.fnmatch(f['filename_only'].lower(), q_lower) or 
                fnmatch.fnmatch(f['name'].lower(), q_lower) or
                fnmatch.fnmatch(f['name'].lower(), f"*{q_lower}*")
            )
        else:
            matcher = lambda f: (q_lower in f['filename_only'].lower() or q_lower in f['name'].lower())

        for f in flat_files:
            if scope == 'current':
                if path:
                    if not (f['name'].startswith(path + '/') or f['folder_path'] == path):
                        continue
                else:
                    if f['folder_path'] not in ("", "/"):
                        continue
            if matcher(f) and matches_category(f):
                matched_files.append(f)
    else:
        node = tree.get(path, {"file_ids": [], "subfolders": set()})
        for s in node["subfolders"]:
            sub_path = s if not path else f"{path}/{s}"
            cnt, total_b, sz = get_folder_metrics(sub_path)
            subfolders_result.append({
                'name': s,
                'path': sub_path,
                'total_files': cnt,
                'total_bytes': total_b,
                'total_size': sz
            })

        for fid in node["file_ids"]:
            f = flat_files[fid]
            if matches_category(f):
                matched_files.append(f)

    reverse = (order == 'desc')

    if sort_by == 'size':
        subfolders_result.sort(key=lambda x: x['total_bytes'], reverse=reverse)
        matched_files.sort(key=lambda x: x['size'], reverse=reverse)
    elif sort_by == 'comp_size':
        subfolders_result.sort(key=lambda x: x['name'].lower(), reverse=reverse)
        matched_files.sort(key=lambda x: x['comp_size'], reverse=reverse)
    elif sort_by == 'ratio':
        subfolders_result.sort(key=lambda x: x['name'].lower(), reverse=reverse)
        matched_files.sort(key=lambda x: x['ratio_num'], reverse=reverse)
    elif sort_by == 'date':
        subfolders_result.sort(key=lambda x: x['name'].lower(), reverse=reverse)
        matched_files.sort(key=lambda x: x['date'], reverse=reverse)
    else:
        subfolders_result.sort(key=lambda x: x['name'].lower(), reverse=reverse)
        matched_files.sort(key=lambda x: x['filename_only'].lower(), reverse=reverse)

    total_files_count = len(matched_files)
    total_pages = max(1, math.ceil(total_files_count / limit))
    start_idx = (page - 1) * limit
    paged_files = matched_files[start_idx:start_idx + limit]

    return jsonify(
        subfolders=subfolders_result,
        files=paged_files,
        total_files=total_files_count,
        page=page,
        total_pages=total_pages,
        archive_stats=cache_entry['archive_stats'],
        resolved_url=url
    )


# ----------------------------------------------------------------------
# RAR STREAMING SSE ENDPOINTS & CONTROLS
# ----------------------------------------------------------------------
@app.route('/api/rar/scan_stream')
def api_rar_scan_stream():
    url = request.args.get('url')
    if not url:
        return Response("Missing url", status=400)
    url = resolve_download_url(url)
    scan_id = request.args.get('scan_id') or os.urandom(8).hex()
    use_quick_open = request.args.get('qo', '1') != '0'

    stop = threading.Event()
    q = queue.Queue()
    with RAR_SCANS_LOCK:
        RAR_SCANS[scan_id] = {'stop': stop, 'url': url}

    # The scan runs on its own thread; this generator only relays events, so it can send
    # keep-alive pings even while the scan is blocked on a slow range request.
    threading.Thread(target=rar_scan_worker, args=(url, scan_id, q, stop, use_quick_open), daemon=True).start()

    def generate():
        try:
            while True:
                try:
                    ev = q.get(timeout=5)
                except queue.Empty:
                    yield ": ping\n\n"
                    continue
                if ev is None:
                    break
                yield f"data: {json.dumps(ev)}\n\n"
        finally:
            stop.set()      # browser went away (or scan finished): make sure the worker winds down
            with RAR_SCANS_LOCK:
                RAR_SCANS.pop(scan_id, None)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


@app.route('/api/rar/stop', methods=['POST', 'GET'])
def api_rar_stop():
    scan_id = request.args.get('scan_id')
    if not scan_id:
        return jsonify(error="Missing scan_id"), 400
    with RAR_SCANS_LOCK:
        scan = RAR_SCANS.get(scan_id)
    if scan:
        scan['stop'].set()
        return jsonify(status="stopping")
    return jsonify(status="ok")


@app.route('/api/rar/rescan', methods=['POST', 'GET'])
def api_rar_rescan():
    url = request.args.get('url')
    if not url:
        return jsonify(error="Missing url"), 400
    url = resolve_download_url(url)
    with ZIP_CACHE_LOCK:
        ZIP_CACHE.pop(url, None)
    return jsonify(status="cleared")


# ----------------------------------------------------------------------
# PREVIEW, RAW STREAMING & DIRECT DOWNLOADS
# ----------------------------------------------------------------------
MIME_OVERRIDES = {
    '.avif': 'image/avif',
    '.webp': 'image/webp',
    '.svg':  'image/svg+xml',
    '.flac': 'audio/flac',
    '.opus': 'audio/opus',
    '.pdf':  'application/pdf',
    '.csv':  'text/plain',
}


def _norm(name):
    return name.replace('\\', '/')


def find_rar_entry(url, filename):
    """Returns (is_rar_archive, file_obj_or_None) for a cached RAR listing."""
    cached = ZIP_CACHE.get(url)
    if not cached or cached.get('archive_type') != 'rar':
        return False, None
    wanted = _norm(filename)
    return True, next((f for f in cached['flat_files'] if _norm(f['name']) == wanted), None)


def fetch_range(url, off, n):
    headers = {"Range": f"bytes={off}-{off + n - 1}", "Accept-Encoding": "identity"}
    with borrow_session() as s:
        with s.get(url, headers=headers, stream=True, timeout=(10, 45)) as r:
            if r.status_code != 206:
                raise IOError(f"HTTP {r.status_code} (expected 206)")
            buf = bytearray()
            for chunk in r.iter_content(64 * 1024):
                buf += chunk
                if len(buf) >= n:
                    break
    return bytes(buf[:n])



def _make_remote_zip(url, known_size=None):
    class _SizedFetcher(RemoteFetcher):
        def get_file_size(self):
            return known_size if known_size else super().get_file_size()

    return RemoteZip(
        url,
        initial_buffer_size=512 * 1024,   # 512 KB reads most Central Directories in 1 request
        headers=DEFAULT_HEADERS,
        timeout=NETWORK_TIMEOUT,
        support_suffix_range=False,
        fetcher=_SizedFetcher if known_size else RemoteFetcher,
    )


def _iter_zip_member_direct(url, info, limit=None):
    """Stream/decompress a cached ZIP member in 1 HTTP Range request without re-reading the Central Directory."""
    if info.file_size == 0:
        return
    if info.flag_bits & 0x1:
        raise RuntimeError("File is password protected")

    off = info.header_offset
    comp_left = info.compress_size
    if limit is not None:
        # Request just enough compressed bytes so the HTTP response completes cleanly & keeps TLS alive
        comp_fetch = min(comp_left, limit if info.compress_type == 0 else max(64 * 1024, limit))
    else:
        comp_fetch = comp_left

    end = off + 4096 + comp_fetch - 1
    headers = {"Range": f"bytes={off}-{end}", "Accept-Encoding": "identity"}

    decomp = zipfile._get_decompressor(info.compress_type) if info.compress_type != 0 else None
    sent = 0
    with borrow_session() as s:
        with s.get(url, headers=headers, stream=True, timeout=NETWORK_TIMEOUT) as r:
            if r.status_code not in (200, 206):
                raise IOError(f"HTTP {r.status_code} reading ZIP member")
            it = r.iter_content(64 * 1024)
            buf = bytearray()
            while len(buf) < 30:
                chunk = next(it, b"")
                if not chunk:
                    raise IOError("Truncated ZIP local header")
                buf += chunk
            sig, _, _, _, _, _, _, _, _, fn_len, ex_len = struct.unpack('<4sHHHHHIIIHH', buf[:30])
            if sig != b'PK\x03\x04':
                raise IOError("Invalid ZIP local header signature")
            skip = 30 + fn_len + ex_len
            while len(buf) < skip:
                chunk = next(it, b"")
                if not chunk:
                    raise IOError("Truncated ZIP local header fields")
                buf += chunk

            def emit_plain(raw):
                nonlocal sent
                if not raw:
                    return None
                if limit is not None:
                    need = limit - sent
                    if need <= 0:
                        return None
                    raw = raw[:need]
                sent += len(raw)
                return raw

            rem = bytes(buf[skip:])[:comp_left]
            comp_left -= len(rem)
            if rem:
                out = emit_plain(decomp.decompress(rem) if decomp else rem)
                if out:
                    yield out
            while comp_left > 0 and (limit is None or sent < limit):
                chunk = next(it, b"")
                if not chunk:
                    break
                chunk = chunk[:comp_left]
                comp_left -= len(chunk)
                out = emit_plain(decomp.decompress(chunk) if decomp else chunk)
                if out:
                    yield out
            if comp_left == 0 and decomp is not None and (limit is None or sent < limit):
                flush_fn = getattr(decomp, 'flush', None)
                if flush_fn:
                    out = emit_plain(flush_fn())
                    if out:
                        yield out


@app.route('/api/raw', methods=['GET'])
def api_raw():
    url = request.args.get('url')
    filename = request.args.get('filename')
    if not url or not filename:
        return "Missing parameters", 400

    url = resolve_download_url(url)
    _, ext = os.path.splitext(filename.lower())
    mime = MIME_OVERRIDES.get(ext) or mimetypes.guess_type(filename)[0] or 'application/octet-stream'

    # RAR entries
    is_rar, f_obj = find_rar_entry(url, filename)
    if is_rar:
        if not f_obj:
            return "File not found in archive", 404
        block = rar_entry_blocker(f_obj)
        if block:
            return block, 400
        if f_obj.get('stored'):
            return Response(stream_with_context(stream_rar_member(url, f_obj)),
                            headers={"Content-Type": mime, "Content-Length": str(f_obj['size']),
                                     "Cache-Control": "public, max-age=3600"})
        try:
            raw_data = extract_rar_entry_bytes(url, f_obj, f_obj['name'])
        except Exception as e:
            return f"{e}", 400
        return Response(raw_data, headers={"Content-Type": mime, "Cache-Control": "public, max-age=3600"})



    cached = ZIP_CACHE.get(url)
    zinfo = cached.get('zip_infos', {}).get(_norm(filename)) if cached else None
    if zinfo is not None:
        return Response(
            stream_with_context(_iter_zip_member_direct(url, zinfo)),
            headers={"Content-Type": mime, "Content-Length": str(zinfo.file_size), "Cache-Control": "public, max-age=3600"}
        )


    # ZIP File streaming
    try:
        rz = RemoteZip(url, headers=DEFAULT_HEADERS, timeout=NETWORK_TIMEOUT, support_suffix_range=False)
        stream = rz.open(filename)

        def generate():
            try:
                while True:
                    chunk = stream.read(16384)
                    if not chunk: break
                    yield chunk
            finally:
                stream.close()
                rz.close()

        return Response(stream_with_context(generate()), headers={"Content-Type": mime, "Cache-Control": "public, max-age=3600"})
    except Exception as e:
        return f"Error streaming file: {str(e)}", 500


def _cache_preview(key, payload):
    with _PREVIEW_CACHE_LOCK:
        if len(_PREVIEW_CACHE) >= 32:
            _PREVIEW_CACHE.pop(next(iter(_PREVIEW_CACHE)))
        _PREVIEW_CACHE[key] = payload
    return jsonify(payload)


@app.route('/api/view', methods=['GET'])
def api_view():
    url = request.args.get('url')
    filename = request.args.get('filename')
    mode = request.args.get('mode', 'text')

    if not url or not filename:
        return jsonify(error="Missing parameters"), 400

    url = resolve_download_url(url)
    cache_key = (url, _norm(filename), mode)
    with _PREVIEW_CACHE_LOCK:
        if cache_key in _PREVIEW_CACHE:
            return jsonify(_PREVIEW_CACHE[cache_key])

    # 1. Handle RAR Archives
    is_rar, f_obj = find_rar_entry(url, filename)
    if is_rar:
        if not f_obj:
            return jsonify(error="File not found in archive"), 404

        off = f_obj['offset']

        if mode == 'hex':
            try:
                fetch_sz = min(4096, f_obj['comp_size'])
                data = fetch_range(url, off, fetch_sz) if fetch_sz > 0 else b""
                return _cache_preview(cache_key, {
                    "hex_dump": generate_hex_dump(data),
                    "truncated": f_obj['comp_size'] > 4096
                })
            except Exception as e:
                return jsonify(error=f"Hex view error: {e}"), 500

        block = rar_entry_blocker(f_obj)
        if block:
            return jsonify(error=block), 400

        LIMIT = 512 * 1024
        try:
            if f_obj.get('stored'):
                data = fetch_range(url, off, min(LIMIT, f_obj['size'])) if f_obj['size'] > 0 else b""
            else:
                data = extract_rar_entry_bytes(url, f_obj, f_obj['name'])[:LIMIT]
        except Exception as e:
            return jsonify(error=f"{e}"), 400
        try:
            content = data.decode('utf-8')
        except UnicodeDecodeError:
            content = data.decode('cp437', errors='replace')
        return _cache_preview(cache_key, {"content": content, "size": len(data)})

    # 2. Fast Path for Cached ZIP Archives (1 HTTP request, no Central Directory re-download)
    cached = ZIP_CACHE.get(url)
    zinfo = cached.get('zip_infos', {}).get(_norm(filename)) if cached else None
    if zinfo is not None:
        try:
            limit = 4096 if mode == 'hex' else 512 * 1024
            raw_bytes = b"".join(_iter_zip_member_direct(url, zinfo, limit=limit))
            if mode == 'hex':
                return _cache_preview(cache_key, {
                    "hex_dump": generate_hex_dump(raw_bytes),
                    "truncated": zinfo.file_size > 4096
                })
            try:
                content = raw_bytes.decode('utf-8')
            except UnicodeDecodeError:
                content = raw_bytes.decode('latin-1', errors='replace')
            return _cache_preview(cache_key, {"content": content, "size": len(raw_bytes)})
        except Exception as e:
            return jsonify(error=f"Preview error: {e}"), 500

    # 3. Fallback ZIP Preview (if cache missed after a server restart)
    try:
        with RemoteZip(url, headers=DEFAULT_HEADERS, timeout=NETWORK_TIMEOUT, support_suffix_range=False) as rz:
            with rz.open(filename) as f:
                if mode == 'hex':
                    raw_bytes = f.read(4096)
                    return _cache_preview(cache_key, {
                        "hex_dump": generate_hex_dump(raw_bytes),
                        "truncated": len(raw_bytes) == 4096
                    })
                else:
                    content_bytes = f.read(512 * 1024)
                    try:
                        content = content_bytes.decode('utf-8')
                    except UnicodeDecodeError:
                        content = content_bytes.decode('latin-1', errors='replace')
                    return _cache_preview(cache_key, {"content": content, "size": len(content_bytes)})
    except Exception as e:
        return jsonify(error=f"Preview error: {str(e)}"), 500


# ----------------------------------------------------------------------
# EXACT RESILIENT ARCHIVE DOWNLOAD HELPERS
# ----------------------------------------------------------------------
ZIP64_SIZE_LIMIT = 0xFFFFFFFF
ZIP64_COUNT_LIMIT = 0xFFFF
CHUNK_SIZE = 256 * 1024
MAX_MEMBER_RETRIES = 8


def _local_header(name_b, crc, size, dos_time, dos_date):
    if size >= ZIP64_SIZE_LIMIT:
        extra = struct.pack('<HHQQ', 0x0001, 16, size, size)
        sz, ver = 0xFFFFFFFF, 45
    else:
        extra, sz, ver = b'', size, 20
    hdr = struct.pack('<4sHHHHHIIIHH', b'PK\x03\x04', ver, 0x0800, 0,
                      dos_time, dos_date, crc, sz, sz, len(name_b), len(extra))
    return hdr + name_b + extra


def _local_header_dd(name_b, size, dos_time, dos_date):
    """Local header for an entry whose CRC is not known yet (bit 3: CRC + sizes follow in a data descriptor)."""
    zip64 = size >= ZIP64_SIZE_LIMIT
    extra = struct.pack('<HHQQ', 0x0001, 16, 0, 0) if zip64 else b''
    sz, ver = (0xFFFFFFFF, 45) if zip64 else (0, 20)
    hdr = struct.pack('<4sHHHHHIIIHH', b'PK\x03\x04', ver, 0x0808, 0,
                      dos_time, dos_date, 0, sz, sz, len(name_b), len(extra))
    return hdr + name_b + extra


def _data_descriptor(crc, size):
    if size >= ZIP64_SIZE_LIMIT:
        return struct.pack('<4sIQQ', b'PK\x07\x08', crc, size, size)
    return struct.pack('<4sIII', b'PK\x07\x08', crc, size, size)


def _central_entry(name_b, crc, size, offset, dos_time, dos_date, flags=0x0800):
    vals = []
    sz, off = size, offset
    if size >= ZIP64_SIZE_LIMIT:
        sz = 0xFFFFFFFF
        vals += [size, size]
    if offset >= ZIP64_SIZE_LIMIT:
        off = 0xFFFFFFFF
        vals.append(offset)
    extra = b''
    if vals:
        extra = struct.pack('<HH', 0x0001, 8 * len(vals)) + struct.pack('<%dQ' % len(vals), *vals)
    ver = 45 if vals else 20
    hdr = struct.pack('<4sHHHHHHIIIHHHHHII', b'PK\x01\x02', ver, ver, flags, 0,
                      dos_time, dos_date, crc, sz, sz,
                      len(name_b), len(extra), 0, 0, 0, 0o644 << 16, off)
    return hdr + name_b + extra


def _end_records(count, cd_size, cd_offset):
    need64 = (count >= ZIP64_COUNT_LIMIT or cd_size >= ZIP64_SIZE_LIMIT
              or cd_offset >= ZIP64_SIZE_LIMIT)
    out = b''
    if need64:
        out += struct.pack('<4sQHHIIQQQQ', b'PK\x06\x06', 44, 45, 45, 0, 0,
                           count, count, cd_size, cd_offset)
        out += struct.pack('<4sIQI', b'PK\x06\x07', 0, cd_offset + cd_size, 1)
        out += struct.pack('<4sHHHHIIH', b'PK\x05\x06', 0, 0, 0xFFFF, 0xFFFF,
                           0xFFFFFFFF, 0xFFFFFFFF, 0)
    else:
        out += struct.pack('<4sHHHHIIH', b'PK\x05\x06', 0, 0, count, count,
                           cd_size, cd_offset, 0)
    return out


def build_zip_plan(members):
    records, cd, offset = [], [], 0
    for arcname, info in members:
        name_b = arcname.encode('utf-8')
        dos_time, dos_date = to_dos_time(info.date_time)
        lh = _local_header(name_b, info.CRC, info.file_size, dos_time, dos_date)
        records.append((lh, info))
        cd.append(_central_entry(name_b, info.CRC, info.file_size, offset, dos_time, dos_date))
        offset += len(lh) + info.file_size
    cd_bytes = b''.join(cd)
    trailer = cd_bytes + _end_records(len(members), len(cd_bytes), offset)
    return records, trailer, offset + len(trailer)


class ZipSession:
    def __init__(self, factory):
        self._factory = factory
        self._rz = None

    def get(self):
        if self._rz is None:
            self._rz = self._factory()
        return self._rz

    def reset(self):
        if self._rz is not None:
            try:
                self._rz.close()
            except Exception:
                pass
            self._rz = None

    close = reset


def stream_member(session, info):
    size = info.file_size
    sent, crc, retries, f = 0, 0, 0, None
    try:
        while sent < size:
            try:
                if f is None:
                    f = session.get().open(info)
                    skip = sent
                    while skip:
                        b = f.read(min(skip, CHUNK_SIZE))
                        if not b:
                            raise IOError("stream ended while resuming")
                        skip -= len(b)
                chunk = f.read(min(CHUNK_SIZE, size - sent))
                if not chunk:
                    raise IOError("remote stream ended at %d/%d bytes" % (sent, size))
            except Exception as e:
                retries += 1
                try:
                    if f is not None:
                        f.close()
                except Exception:
                    pass
                f = None
                session.reset()
                print("[zip-stream] %s: %s (retry %d/%d at byte %d)"
                      % (info.filename, e, retries, MAX_MEMBER_RETRIES, sent))
                if retries > MAX_MEMBER_RETRIES:
                    raise
                time.sleep(min(2 ** retries, 15))
                continue
            crc = zlib.crc32(chunk, crc)
            sent += len(chunk)
            yield chunk
    finally:
        try:
            if f is not None:
                f.close()
        except Exception:
            pass
    if (crc & 0xFFFFFFFF) != info.CRC:
        raise IOError("CRC mismatch for %s" % info.filename)


def stream_zip(session, records, trailer):
    try:
        for local_hdr, info in records:
            yield local_hdr
            yield from stream_member(session, info)
        yield trailer
    finally:
        session.close()


def _new_session(url):
    return ZipSession(lambda: RemoteZip(url, headers=DEFAULT_HEADERS,
                                        timeout=NETWORK_TIMEOUT,
                                        support_suffix_range=False))


def _unique(name, used):
    if name not in used:
        used.add(name)
        return name
    base, ext = os.path.splitext(name)
    i = 2
    while f"{base} ({i}){ext}" in used:
        i += 1
    name = f"{base} ({i}){ext}"
    used.add(name)
    return name


def _attachment_headers(filename, length, mime):
    clean = re.sub(r'[<>:"/\\|?*]', '_', filename)
    ascii_fb = clean.encode('ascii', 'ignore').decode() or 'download'
    return {
        "Content-Disposition": f'attachment; filename="{ascii_fb}"; filename*=UTF-8\'\'{urllib.parse.quote(clean)}',
        "Content-Type": mime,
        "Content-Length": str(length),
        "Cache-Control": "no-store",
        "X-Accel-Buffering": "no",
    }


def stream_rar_member(url, file_obj, result=None):
    """Streams a STORED (method 0) RAR entry via HTTP Range requests, verifying CRC32 when the header has one.
    If `result` is a dict, the computed CRC32 is stored in result['crc'] once the entry has been fully sent."""
    offset = file_obj['offset']
    size = file_obj['size']
    sent = 0
    crc = 0
    retries = 0
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    session.headers["Accept-Encoding"] = "identity"
    try:
        while sent < size:
            chunk_to_read = min(CHUNK_SIZE, size - sent)
            curr_off = offset + sent
            r = None
            try:
                r = session.get(url, headers={"Range": f"bytes={curr_off}-{curr_off + chunk_to_read - 1}"},
                                timeout=NETWORK_TIMEOUT, stream=True)
                if r.status_code != 206:
                    raise OSError(f"HTTP {r.status_code} while fetching chunk")
                data = b"".join(r.iter_content(64 * 1024))
                if len(data) != chunk_to_read:
                    raise IOError(f"Remote stream ended prematurely at byte {sent}/{size}")
            except Exception:
                retries += 1
                if retries > MAX_MEMBER_RETRIES:
                    raise
                time.sleep(min(2 ** retries, 15))
                continue
            finally:
                if r is not None:
                    r.close()
            retries = 0
            sent += len(data)
            crc = zlib.crc32(data, crc)
            yield data
    finally:
        session.close()

    crc &= 0xFFFFFFFF
    exp = file_obj.get('crc_int')
    if exp is not None and crc != exp:
        raise IOError(f"CRC mismatch for {file_obj['name']}")
    if result is not None:
        result['crc'] = crc


def _rar_zip_response(url, matched_files, zip_name):
    """Builds an on-the-fly .zip from STORED RAR entries with an exact Content-Length.
    Entries whose RAR header has no CRC32 (e.g. BLAKE2-only archives) use a ZIP data descriptor:
    the CRC is computed while streaming and written afterwards, so the zip is still valid."""
    if not matched_files:
        return "No matching files in archive", 404

    bad = []
    for arc, f in matched_files:
        why = rar_entry_blocker(f) or (None if f.get('stored') else f"compressed, {f.get('method')}")
        if why:
            bad.append(f"{arc} ({why})")
    if bad:
        return ("Cannot package these RAR entries into a .zip on the fly: " + ", ".join(bad[:5])
                + (" ..." if len(bad) > 5 else "")
                + ". Only stored, non-split, unencrypted entries can be streamed."), 400

    plan, offset = [], 0
    for arcname, f in matched_files:
        name_b = arcname.encode('utf-8')
        dos_time, dos_date = to_dos_time(parse_date_str(f.get('date', '')))
        size, crc = f['size'], f.get('crc_int')
        if crc is None:
            lh = _local_header_dd(name_b, size, dos_time, dos_date)
            dd_len = 24 if size >= ZIP64_SIZE_LIMIT else 16
        else:
            lh = _local_header(name_b, crc, size, dos_time, dos_date)
            dd_len = 0
        plan.append({'f': f, 'name_b': name_b, 'lh': lh, 'dd_len': dd_len,
                     'offset': offset, 't': (dos_time, dos_date), 'crc': crc})
        offset += len(lh) + size + dd_len

    def central(crcs):
        return b''.join(
            _central_entry(p['name_b'], crcs[i], p['f']['size'], p['offset'], p['t'][0], p['t'][1],
                           0x0808 if p['dd_len'] else 0x0800)
            for i, p in enumerate(plan))

    placeholder = [p['crc'] or 0 for p in plan]
    cd_len = len(central(placeholder))        # entry length does not depend on the CRC value
    total = offset + cd_len + len(_end_records(len(plan), cd_len, offset))

    def stream_rar_zip():
        final = list(placeholder)
        for i, p in enumerate(plan):
            yield p['lh']
            res = {}
            yield from stream_rar_member(url, p['f'], res)
            final[i] = res.get('crc', 0)
            if p['dd_len']:
                yield _data_descriptor(final[i], p['f']['size'])
        cd = central(final)
        yield cd + _end_records(len(plan), len(cd), offset)

    return Response(stream_with_context(stream_rar_zip()),
                    headers=_attachment_headers(zip_name, total, "application/zip"))


def _fetch_range_retry(url, off, n):
    for attempt in range(MAX_MEMBER_RETRIES + 1):
        try:
            data = fetch_range(url, off, n)
            if len(data) != n:
                raise IOError(f"Short read: got {len(data)} of {n} bytes")
            return data
        except Exception:
            if attempt >= MAX_MEMBER_RETRIES:
                raise
            time.sleep(min(2 ** attempt, 10))


def _stream_stored_parallel(url, info):
    """Stream a large STORED ZIP member across 4 parallel 1 MB Range connections (bypasses 1-stream proxy throttling)."""
    hdr = _fetch_range_retry(url, info.header_offset, 30)
    sig, _, _, _, _, _, _, _, _, fn_len, ex_len = struct.unpack('<4sHHHHHIIIHH', hdr)
    if sig != b'PK\x03\x04':
        raise IOError(f"Invalid local header for {info.filename}")
    data_start = info.header_offset + 30 + fn_len + ex_len

    part_sz = 1024 * 1024  # 1 MB chunks
    total = info.file_size
    offsets = list(range(0, total, part_sz))
    crc = 0
    ex = ThreadPoolExecutor(max_workers=4)
    in_flight = {}
    next_q = 0
    try:
        while next_q < len(offsets) and len(in_flight) < 6:
            o = offsets[next_q]
            in_flight[next_q] = ex.submit(_fetch_range_retry, url, data_start + o, min(part_sz, total - o))
            next_q += 1
        for i in range(len(offsets)):
            chunk = in_flight.pop(i).result()
            while next_q < len(offsets) and len(in_flight) < 6:
                o = offsets[next_q]
                in_flight[next_q] = ex.submit(_fetch_range_retry, url, data_start + o, min(part_sz, total - o))
                next_q += 1
            crc = zlib.crc32(chunk, crc)
            yield chunk
    finally:
        for fut in in_flight.values():
            fut.cancel()
        ex.shutdown(wait=False)

    if (crc & 0xFFFFFFFF) != info.CRC:
        raise IOError(f"CRC mismatch for {info.filename}")


def _fetch_zip_member_small(url, info):
    for attempt in range(MAX_MEMBER_RETRIES + 1):
        try:
            data = b"".join(_iter_zip_member_direct(url, info))
            if (zlib.crc32(data) & 0xFFFFFFFF) != info.CRC:
                raise IOError(f"CRC mismatch for {info.filename}")
            return data
        except Exception:
            if attempt >= MAX_MEMBER_RETRIES:
                raise
            time.sleep(min(2 ** attempt, 10))


def stream_zip_fast(url, records, trailer):
    """Stream a ZIP archive with 6-thread parallel lookahead on small/medium files."""
    SMALL_LIMIT = 8 * 1024 * 1024
    MAX_INFLIGHT_BYTES = 24 * 1024 * 1024
    ex = ThreadPoolExecutor(max_workers=6)
    in_flight = {}
    buffered_bytes = 0
    next_idx = 0
    session = _new_session(url)  # only opened lazily if a huge compressed file (>8 MB) appears

    def fill_window():
        nonlocal next_idx, buffered_bytes
        while next_idx < len(records) and len(in_flight) < 6:
            _, inf = records[next_idx]
            if inf.file_size <= SMALL_LIMIT and (buffered_bytes + inf.file_size <= MAX_INFLIGHT_BYTES or not in_flight):
                in_flight[next_idx] = (ex.submit(_fetch_zip_member_small, url, inf), inf.file_size)
                buffered_bytes += inf.file_size
                next_idx += 1
            elif inf.file_size > SMALL_LIMIT:
                next_idx += 1  # skip large files for prefetch; they stream directly
            else:
                break

    try:
        fill_window()
        for i, (local_hdr, info) in enumerate(records):
            if i >= next_idx:
                next_idx = i + 1
            fill_window()
            yield local_hdr
            if i in in_flight:
                fut, sz = in_flight.pop(i)
                buffered_bytes -= sz
                fill_window()
                yield fut.result()
            elif info.compress_type == 0 and info.file_size > 2 * 1024 * 1024:
                yield from _stream_stored_parallel(url, info)
            else:
                yield from stream_member(session, info)
        yield trailer
    finally:
        for fut, _ in in_flight.values():
            fut.cancel()
        ex.shutdown(wait=False)
        session.close()


def _pick_cached_zip_infos(url):
    with ZIP_CACHE_LOCK:
        cached = ZIP_CACHE.get(url)
        if cached and cached.get('zip_infos'):
            return list(cached['zip_infos'].values())
    return None


def _zip_response(url, picker, zip_name):
    infos = _pick_cached_zip_infos(url)
    if infos is None:
        with _make_remote_zip(url) as rz:
            infos = rz.infolist()
    try:
        members = picker(infos)
        if not members:
            return "No matching files in archive", 404
        locked = [n for n, i in members if i.flag_bits & 0x1]
        if locked:
            return ("Cannot stream password-protected files: "
                    + ", ".join(locked[:5]) + (" ..." if len(locked) > 5 else "")), 400
        records, trailer, total = build_zip_plan(members)
    except Exception as e:
        return f"Error preparing archive: {e}", 500
    return Response(stream_with_context(stream_zip_fast(url, records, trailer)),
                    headers=_attachment_headers(zip_name, total, "application/zip"))


# ----------------------------------------------------------------------
# FINAL DOWNLOAD ROUTES (HANDLES BOTH ZIP & RAR)
# ----------------------------------------------------------------------
@app.route('/download', methods=['GET'])
def download():
    url = request.args.get('url')
    filename = request.args.get('filename')
    if not url or not filename:
        return "Missing parameters", 400
    url = resolve_download_url(url)
    wanted = _norm(filename)

    # 1. Handle RAR Archives
    is_rar, f_obj = find_rar_entry(url, filename)
    if is_rar:
        if not f_obj:
            return "File not found in archive", 404
        block = rar_entry_blocker(f_obj)
        if block:
            return block, 400
        if not f_obj.get('stored'):
            return (f"Cannot download compressed RAR entry ({f_obj.get('method')}) directly. "
                    "Solid and compressed RAR archives require full unrar decompression."), 400

        base = os.path.basename(wanted)
        mime, _ = mimetypes.guess_type(base)
        return Response(stream_with_context(stream_rar_member(url, f_obj)),
                        headers=_attachment_headers(base, f_obj['size'], mime or "application/octet-stream"))

    # 2. Handle Standard ZIP Archives
    infos = _pick_cached_zip_infos(url)
    info = next((i for i in infos if _norm(i.filename) == wanted), None) if infos else None

    if info is not None:
        if info.flag_bits & 0x1:
            return "File is password protected", 400
        base = os.path.basename(wanted)
        if info.compress_type == 0 and info.file_size > 2 * 1024 * 1024:
            gen = _stream_stored_parallel(url, info)
        else:
            gen = _iter_zip_member_direct(url, info)
        return Response(stream_with_context(gen),
                        headers=_attachment_headers(base, info.file_size, "application/octet-stream"))

    # Fallback if cache missed (e.g. direct link after server restart)
    session = _new_session(url)
    try:
        info = next((i for i in session.get().infolist() if _norm(i.filename) == wanted), None)
    except Exception as e:
        session.close()
        return f"Error opening archive: {e}", 500
    if info is None:
        session.close()
        return "File not found in archive", 404
    if info.flag_bits & 0x1:
        session.close()
        return "File is password protected", 400

    def generate_zip():
        try:
            yield from stream_member(session, info)
        finally:
            session.close()

    base = os.path.basename(wanted)
    return Response(stream_with_context(generate_zip()),
                    headers=_attachment_headers(base, info.file_size, "application/octet-stream"))


@app.route('/download_folder', methods=['GET'])
def download_folder():
    url = request.args.get('url')
    folder = request.args.get('folder', '').strip('/')
    if not url:
        return "Missing parameters", 400
    url = resolve_download_url(url)
    prefix = (folder + '/') if folder else ''
    zip_name = (folder.split('/')[-1] if folder else 'archive_root') + '.zip'

    # 1. Handle RAR Archives
    cached = ZIP_CACHE.get(url)
    if cached and cached.get('archive_type') == 'rar':
        matched = []
        for f in cached['flat_files']:
            n = _norm(f['name'])
            if not prefix or n.startswith(prefix):
                arcname = n[len(prefix):] if prefix else n
                matched.append((arcname, f))
        return _rar_zip_response(url, matched, zip_name)

    # 2. Handle ZIP Archives
    def picker(infos):
        out = []
        for info in infos:
            n = _norm(info.filename)
            if n.endswith('/'):
                continue
            if not prefix or n.startswith(prefix):
                out.append((n[len(prefix):] if prefix else n, info))
        return out

    return _zip_response(url, picker, zip_name)


@app.route('/download_batch', methods=['GET'])
def download_batch():
    url = request.args.get('url')
    raw = request.args.get('files', '')
    if not url or not raw:
        return "Missing parameters", 400
    url = resolve_download_url(url)
    wanted = set(_norm(f.strip()) for f in raw.split(',') if f.strip())

    # 1. Handle RAR Archives
    cached = ZIP_CACHE.get(url)
    if cached and cached.get('archive_type') == 'rar':
        out, used = [], set()
        for f in cached['flat_files']:
            n = _norm(f['name'])
            if n in wanted or os.path.basename(n) in wanted:
                out.append((_unique(os.path.basename(n), used), f))
        return _rar_zip_response(url, out, 'selected_files.zip')

    # 2. Handle ZIP Archives
    def picker(infos):
        out, used = [], set()
        for info in infos:
            n = _norm(info.filename)
            if n.endswith('/'):
                continue
            if n in wanted or os.path.basename(n) in wanted:
                out.append((_unique(os.path.basename(n), used), info))
        return out

    return _zip_response(url, picker, 'selected_files.zip')


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 7860))
    # threaded=True matters: each RAR scan holds an SSE connection open. If you deploy with gunicorn,
    # use threaded workers (e.g. --workers 1 --threads 16), because the cache and scans live in memory.
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)