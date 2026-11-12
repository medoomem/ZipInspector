
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
import struct
import datetime
import zipfile
import threading
import mimetypes
import urllib.parse
from flask import Flask, render_template_string, request, Response, stream_with_context, jsonify
import requests
from remotezip import RemoteZip
import fnmatch

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


def resolve_download_url(url: str) -> str:
    if not url:
        return url
    if "dlproxy" in url.lower() or "/download/" in url.lower():
        return url
    if "github.com" in url.lower() or "ankergames" in url.lower():
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "*/*"
        }
        try:
            with requests.get(url, headers=headers, stream=True, allow_redirects=True, timeout=12) as response:
                direct_url = response.url
                if direct_url and direct_url != url:
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

RAR_SCANS = {}
RAR_SCANS_LOCK = threading.Lock()


# ======================================================================
# 4. REMOTE RANGE READER & RAR ENGINE (PARSER, QUICK OPEN, SCANNER)
# ======================================================================
class RangeReader:
    """Random-access reader over HTTP with read-ahead caching."""
    def __init__(self, url, window=64 * 1024, timeout=NETWORK_TIMEOUT):
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        self.url = url
        self.window = window
        self.timeout = timeout
        self.requests_count = 0
        self.bytes_read = 0
        self.buf = b""
        self.buf_off = 0
        self.size = 0

    def probe(self):
        r = self.session.get(
            self.url,
            headers={"Range": "bytes=0-0"},
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
            return self.size
        finally:
            r.close()

    def _get(self, offset, length):
        last_err = None
        for attempt in range(3):
            try:
                r = self.session.get(
                    self.url,
                    timeout=self.timeout,
                    headers={"Range": f"bytes={offset}-{offset + length - 1}"}
                )
                self.requests_count += 1
                if r.status_code != 206:
                    raise OSError(f"HTTP {r.status_code} (expected 206)")
                if len(r.content) != length:
                    raise OSError(f"Short read: got {len(r.content)} of {length} bytes")
                self.bytes_read += length
                return r.content
            except Exception as e:
                last_err = e
                time.sleep(0.4 * (attempt + 1))
        raise OSError(f"Range request failed at offset {offset}: {last_err}")

    def read(self, offset, n):
        n = min(n, self.size - offset)
        if n <= 0:
            return b""
        end = offset + n
        if self.buf_off <= offset and end <= self.buf_off + len(self.buf):
            return self.buf[offset - self.buf_off:end - self.buf_off]
        fetch = min(max(n, self.window), self.size - offset)
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


def detect_rar5_quick_open(data):
    """Detects RAR5 Quick Open locator record in the archive header."""
    if not data.startswith(RAR5_SIG) or len(data) < 24:
        return None
    try:
        hsize, pos = vint(data, 12)  # skip 8-byte sig + 4-byte crc
        htype, pos = vint(data, pos)
        hflags, pos = vint(data, pos)
        qo_offset = None
        if hflags & 0x01:  # Extra area present
            extra_size, pos = vint(data, pos)
            end_extra = pos + extra_size
            while pos < end_extra:
                rec_size, pos = vint(data, pos)
                rec_end = pos + rec_size
                rec_type, pos = vint(data, pos)
                if rec_type == 1:  # Locator Record
                    loc_flags, pos = vint(data, pos)
                    if loc_flags & 0x01:  # Quick Open flag
                        raw_off, pos = vint(data, pos)
                        if raw_off != 0:
                            qo_offset = 8 + raw_off
                pos = rec_end
        return qo_offset
    except Exception:
        return None


def parse_rar5_quick_open(rd, qo_offset, info, entries, stop_check):
    """Parses Quick Open cache block directly in contiguous range."""
    head = rd.read(qo_offset, 32)
    if len(head) < 8:
        return
    hsize, p = vint(head, 4)
    total = p + hsize
    blk = rd.read(qo_offset, total)
    htype, pos = vint(blk, p)
    hflags, pos = vint(blk, pos)
    extra = data_size = 0
    if hflags & 0x1:
        extra, pos = vint(blk, pos)
    if hflags & 0x2:
        data_size, pos = vint(blk, pos)
    if htype != 3 or data_size <= 0:
        return

    qo_data_off = qo_offset + total
    qo_data = rd.read(qo_data_off, min(data_size, 16 * 1024 * 1024))
    if len(qo_data) < min(data_size, 16 * 1024 * 1024):
        return

    qpos = 0
    while qpos < len(qo_data):
        if stop_check and stop_check():
            info["notes"].append("Scan stopped by user")
            break
        if qpos + 4 > len(qo_data):
            break
        _scrc = struct.unpack_from("<I", qo_data, qpos)[0]
        qpos += 4
        str_size, qpos = vint(qo_data, qpos)
        str_end = qpos + str_size
        if str_end > len(qo_data):
            break
        _dflags, qpos = vint(qo_data, qpos)
        doff, qpos = vint(qo_data, qpos)
        dsize, qpos = vint(qo_data, qpos)

        cached_blk = qo_data[qpos:str_end]
        qpos = str_end

        # In RAR5 spec, doff is measured backwards from the Quick Open header
        real_archive_pos = max(0, qo_offset - doff)

        bpos = 0
        while bpos + 8 < len(cached_blk):
            try:
                chsize, cp = vint(cached_blk, bpos + 4)
                ctotal = cp + chsize
                chtype, cpos = vint(cached_blk, bpos + cp)
                chflags, cpos = vint(cached_blk, cpos)
                cextra = cdata_size = 0
                if chflags & 0x1:
                    cextra, cpos = vint(cached_blk, cpos)
                if chflags & 0x2:
                    cdata_size, cpos = vint(cached_blk, cpos)

                # Exact data start for this entry in the archive
                real_data_off = real_archive_pos + ctotal

                if chtype == 2:  # File Header
                    cfflags, cpos = vint(cached_blk, cpos)
                    csize, cpos = vint(cached_blk, cpos)
                    _attr, cpos = vint(cached_blk, cpos)
                    mtime_str = "N/A"
                    if cfflags & 0x2:
                        mt = struct.unpack_from("<I", cached_blk, cpos)[0]
                        cpos += 4
                        try:
                            mtime_str = datetime.datetime.fromtimestamp(mt, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                        except Exception:
                            pass
                    crc_val = 0
                    if cfflags & 0x4:
                        crc_val = struct.unpack_from("<I", cached_blk, cpos)[0]
                        cpos += 4
                    comp, cpos = vint(cached_blk, cpos)
                    _host, cpos = vint(cached_blk, cpos)
                    nlen, cpos = vint(cached_blk, cpos)
                    name = cached_blk[cpos:cpos + nlen].decode("utf-8", "replace").replace("\\", "/")

                    entries.append({
                        "name": name,
                        "size": csize,
                        "packed": cdata_size,
                        "method": (comp >> 7) & 0x7,
                        "dir": bool(cfflags & 0x1),
                        "solid": bool(comp & 0x40),
                        "enc": False,
                        "prev": bool(chflags & 0x4),
                        "next": bool(chflags & 0x8),
                        "crc32": crc_val,
                        "date": mtime_str,
                        "off": real_data_off
                    })
                # Advance to next header in both the cache block and the archive stream
                bpos += ctotal
                real_archive_pos += ctotal + cdata_size
            except Exception:
                break


def decode_rar4_name(raw):
    raw = raw.split(b"\0")[0]
    try:
        return raw.decode("utf-8").replace("\\", "/")
    except UnicodeDecodeError:
        return raw.decode("cp437", "replace").replace("\\", "/")


def scan_rar_generator(rd, info, entries, stop_check=None):
    """Generator that traverses RAR4/RAR5 block headers front-to-back over HTTP Range requests."""
    total_size = rd.size
    is_rar5 = info.get("fmt") == "RAR5"

    # 1. Trick 2: RAR5 Quick Open Acceleration
    if is_rar5:
        head_data = rd.read(0, min(1024, total_size))
        qo_offset = detect_rar5_quick_open(head_data)
        if qo_offset:
            info["quick_open"] = True
            yield {
                "type": "log",
                "message": f"⚡ Quick Open locator found at offset {qo_offset}! Loading fast index..."
            }
            yield {
                "type": "qo_found",
                "offset": qo_offset
            }
            try:
                parse_rar5_quick_open(rd, qo_offset, info, entries, stop_check)
                if entries:
                    yield {
                        "type": "progress",
                        "percent": 100.0,
                        "offset": total_size,
                        "offset_str": format_size(total_size),
                        "total_size": total_size,
                        "total_size_str": format_size(total_size),
                        "count": len(entries),
                        "requests": rd.requests_count,
                        "bytes_read": rd.bytes_read,
                        "bytes_read_str": format_size(rd.bytes_read),
                        "current_file": "Quick Open Index Complete"
                    }
                    return
            except Exception as e:
                yield {
                    "type": "log",
                    "message": f"Quick Open parse skipped ({e}). Falling back to sequential range traversal."
                }

    # 2. Trick 1: Sequential Block Header Traversal
    off = len(RAR5_SIG) if is_rar5 else len(RAR4_SIG)
    last_yield_time = 0

    while off < total_size and len(entries) < 100000:
        if stop_check and stop_check():
            info["notes"].append("Scan stopped by user")
            break

        try:
            if is_rar5:
                head = rd.read(off, 16)
                if len(head) < 8:
                    break
                hsize, p = vint(head, 4)
                if hsize == 0 or hsize > 2 * 1024 * 1024:
                    break
                total = p + hsize
                blk = rd.read(off, total)
                if len(blk) < total:
                    break
                htype, pos = vint(blk, p)
                hflags, pos = vint(blk, pos)
                extra = data_size = 0
                if hflags & 0x1:
                    extra, pos = vint(blk, pos)
                if hflags & 0x2:
                    data_size, pos = vint(blk, pos)
                data_off = off + total

                if htype == 4:
                    info["enc_headers"] = True
                    break
                elif htype == 1:
                    aflags, pos = vint(blk, pos)
                    info["volume"] = bool(aflags & 0x1)
                    info["solid"] = bool(aflags & 0x4)
                elif htype == 2:
                    fflags, pos = vint(blk, pos)
                    size, pos = vint(blk, pos)
                    _attr, pos = vint(blk, pos)
                    mtime_str = "N/A"
                    if fflags & 0x2:
                        mt = struct.unpack_from("<I", blk, pos)[0]
                        pos += 4
                        try:
                            mtime_str = datetime.datetime.fromtimestamp(mt, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                        except Exception:
                            pass
                    crc_val = 0
                    if fflags & 0x4:
                        crc_val = struct.unpack_from("<I", blk, pos)[0]
                        pos += 4
                    comp, pos = vint(blk, pos)
                    _host, pos = vint(blk, pos)
                    nlen, pos = vint(blk, pos)
                    name = blk[pos:pos + nlen].decode("utf-8", "replace").replace("\\", "/")
                    enc = False
                    epos = total - extra
                    while extra and epos < total:
                        rsize, q = vint(blk, epos)
                        rtype, _ = vint(blk, q)
                        enc = enc or rtype == 1
                        epos = q + rsize

                    entries.append({
                        "name": name,
                        "size": size,
                        "packed": data_size,
                        "method": (comp >> 7) & 0x7,
                        "dir": bool(fflags & 0x1),
                        "solid": bool(comp & 0x40),
                        "enc": enc,
                        "prev": bool(hflags & 0x4),
                        "next": bool(hflags & 0x8),
                        "crc32": crc_val,
                        "date": mtime_str,
                        "off": data_off
                    })

                    now = time.time()
                    if now - last_yield_time >= 0.12 or len(entries) == 1:
                        last_yield_time = now
                        pct = round((off / max(1, total_size)) * 100, 1)
                        yield {
                            "type": "progress",
                            "percent": min(99.9, pct),
                            "offset": off,
                            "offset_str": format_size(off),
                            "total_size": total_size,
                            "total_size_str": format_size(total_size),
                            "count": len(entries),
                            "requests": rd.requests_count,
                            "bytes_read": rd.bytes_read,
                            "bytes_read_str": format_size(rd.bytes_read),
                            "current_file": name
                        }
                elif htype == 5:
                    break
                off = data_off + data_size
            else:
                # RAR4 Format
                base = rd.read(off, 7)
                if len(base) < 7:
                    break
                _crc, htype, hflags, hsize = struct.unpack("<HBHH", base)
                if hsize < 7:
                    break
                blk = rd.read(off, hsize)
                if len(blk) < hsize:
                    break
                add = struct.unpack_from("<I", blk, 7)[0] if hflags & 0x8000 else 0
                data_off = off + hsize

                if htype == 0x73:
                    info["volume"] = bool(hflags & 0x1)
                    info["solid"] = bool(hflags & 0x8)
                    if hflags & 0x80:
                        info["enc_headers"] = True
                        break
                elif htype == 0x74:
                    (pack, unp, _host, _crc32, ftime, _ver, method, nsz,
                     _attr) = struct.unpack_from("<IIBIIBBHI", blk, 7)
                    pos = 32
                    if hflags & 0x100:
                        hp, hu = struct.unpack_from("<II", blk, pos)
                        pack |= hp << 32
                        unp |= hu << 32
                        pos += 8
                    add = pack
                    name = decode_rar4_name(blk[pos:pos + nsz])
                    sec = (ftime & 0x1F) * 2
                    minute = (ftime >> 5) & 0x3F
                    hour = (ftime >> 11) & 0x1F
                    day = (ftime >> 16) & 0x1F
                    month = (ftime >> 21) & 0x0F
                    year = ((ftime >> 25) & 0x7F) + 1980
                    dt_str = f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{sec:02d}"

                    entries.append({
                        "name": name,
                        "size": unp,
                        "packed": pack,
                        "method": max(0, method - 0x30),
                        "dir": (hflags & 0xE0) == 0xE0,
                        "solid": bool(hflags & 0x10),
                        "enc": bool(hflags & 0x4),
                        "prev": bool(hflags & 0x1),
                        "next": bool(hflags & 0x2),
                        "crc32": _crc32,
                        "date": dt_str,
                        "off": data_off
                    })

                    now = time.time()
                    if now - last_yield_time >= 0.12 or len(entries) == 1:
                        last_yield_time = now
                        pct = round((off / max(1, total_size)) * 100, 1)
                        yield {
                            "type": "progress",
                            "percent": min(99.9, pct),
                            "offset": off,
                            "offset_str": format_size(off),
                            "total_size": total_size,
                            "total_size_str": format_size(total_size),
                            "count": len(entries),
                            "requests": rd.requests_count,
                            "bytes_read": rd.bytes_read,
                            "bytes_read_str": format_size(rd.bytes_read),
                            "current_file": name
                        }
                elif htype == 0x7B:
                    break
                off = data_off + add
        except Exception as e:
            info["notes"].append(f"Header parse error at offset {off}: {e}")
            break


def populate_rar_cache(url, entries, info, is_partial=False):
    """Converts scanned RAR entries into the virtual filesystem tree and flat file list."""
    tree = {"": {"file_ids": [], "subfolders": set()}}
    flat_files = []
    total_uncomp_size = 0
    total_comp_size = 0

    for entry in entries:
        norm_name = entry['name'].replace('\\', '/')
        parts = norm_name.rstrip('/').split('/')

        if entry['dir'] or norm_name.endswith('/'):
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

        file_size = entry['size']
        comp_size = entry['packed']
        total_uncomp_size += file_size
        total_comp_size += comp_size

        ratio = 0
        if file_size > 0:
            ratio = round((1 - (comp_size / file_size)) * 100, 1)
            if ratio < 0:
                ratio = 0

        _, ext = os.path.splitext(filename_only)
        file_id = len(flat_files)

        method_str = "Stored (No compression)" if entry['method'] == 0 else f"RAR (m{entry['method']})"
        crc_str = f"0x{entry.get('crc32', 0):08X}"

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
            'crc32': crc_str,
            'encrypted': bool(entry.get('enc', False)),
            'method': method_str,
            'date': entry.get('date', 'N/A'),
            'category': infer_category(ext),
            'archive_type': 'rar',
            'offset': entry.get('off', 0),
            'solid': entry.get('solid', False),
            'prev': entry.get('prev', False),
            'next': entry.get('next', False)
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
        'archive_format': info.get('fmt', 'RAR'),
        'solid': bool(info.get('solid', False)),
        'volume': bool(info.get('volume', False)),
        'quick_open': bool(info.get('quick_open', False)),
        'partial': is_partial
    }

    with ZIP_CACHE_LOCK:
        if len(ZIP_CACHE) >= MAX_CACHE_ENTRIES:
            oldest = min(ZIP_CACHE.keys(), key=lambda k: ZIP_CACHE[k]['timestamp'])
            ZIP_CACHE.pop(oldest, None)
        ZIP_CACHE[url] = {
            'tree': tree,
            'flat_files': flat_files,
            'archive_stats': archive_stats,
            'timestamp': time.time(),
            'archive_type': 'rar'
        }


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
                <button onclick="rescanRar()" type="button" class="px-2.5 py-1 bg-amber-200/80 hover:bg-amber-300 text-amber-900 font-bold rounded-lg transition text-[11px] cursor-pointer shrink-0">
                    Rescan Full Archive
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
                            <li><strong>⚡ Quick Open Locator (RAR5):</strong> Checks for a pre-indexed Quick Open service record in the archive header. If found, it reads all entries in a single request!</li>
                            <li><strong>🎯 Sequential Header Hopping:</strong> For archives without Quick Open, it reads each header and range-jumps over packed bytes. The <strong>Live Progress Bar</strong> keeps you informed, and you can click <strong>Stop &amp; View Partial</strong> at any time.</li>
                        </ol>
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px] sm:text-xs">
                        <div class="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                            <span class="font-bold text-slate-900 block">Stored (Method 0) Entries</span>
                            <p class="text-slate-600">Files stored without compression in non-solid RARs can be downloaded, previewed, or streamed directly.</p>
                        </div>
                        <div class="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                            <span class="font-bold text-slate-900 block">Solid &amp; Compressed Entries</span>
                            <p class="text-slate-600">Solid archives require decompressing earlier blocks. You can view all metadata and inspect raw payload bytes in the <strong>Hex View</strong> tab.</p>
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
        isRar: false
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

            const res = await fetch(`/api/list?${queryParams.toString()}`);
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

        const streamUrl = `/api/rar/scan_stream?url=${encodeURIComponent(state.url)}`;
        rarEventSource = new EventSource(streamUrl);

        rarEventSource.onmessage = (e) => {
            try {
                const msg = JSON.parse(e.data);
                handleRarStreamEvent(msg);
            } catch (err) {
                console.error("SSE parse error:", err, e.data);
            }
        };

        rarEventSource.onerror = (e) => {
            console.warn("EventSource closed or disconnected.", e);
            if (rarEventSource) {
                rarEventSource.close();
                rarEventSource = null;
            }
        };
    }

    function handleRarStreamEvent(msg) {
        if (msg.type === 'init') {
            document.getElementById('rarFmtBadge').textContent = msg.fmt;
            document.getElementById('rarStatOffset').textContent = `0 B / ${msg.size_str}`;
        } else if (msg.type === 'qo_found') {
            document.getElementById('rarQoBadge').classList.remove('hidden');
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
            if (rarEventSource) {
                rarEventSource.close();
                rarEventSource = null;
            }
            document.getElementById('rarProgressContainer').classList.add('hidden');
            fetchExplorerData();
        } else if (msg.type === 'error') {
            if (rarEventSource) {
                rarEventSource.close();
                rarEventSource = null;
            }
            document.getElementById('rarProgressContainer').classList.add('hidden');
            const errorBox = document.getElementById('errorContainer');
            document.getElementById('errorText').textContent = msg.message;
            errorBox.classList.remove('hidden');
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
            await fetch(`/api/rar/stop?url=${encodeURIComponent(state.url)}`, { method: 'POST' });
        } catch (e) {
            console.error("Stop error:", e);
        }
    }

    async function rescanRar() {
        try {
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
            const tr = document.createElement('tr');
            tr.className = "hover:bg-slate-50/60 transition duration-150 group";
            tr.innerHTML = `
                <td class="py-2.5 px-4 text-center">
                    <input type="checkbox" onchange="toggleFileSelectionByIndex(this, ${index})" 
                           ${isChecked ? 'checked' : ''} 
                           class="file-checkbox rounded border-slate-300 text-indigo-600 focus:ring-indigo-500">
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
                           class="p-1 bg-slate-100 hover:bg-indigo-600 hover:text-white text-slate-600 rounded-lg transition" title="Download">
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
            cb.checked = masterCheckbox.checked;
            cb.dispatchEvent(new Event('change'));
        });
    }

    function updateSelectAllState() {
        const master = document.getElementById('selectAllCheckbox');
        const checkboxes = document.querySelectorAll('.file-checkbox');
        if (checkboxes.length === 0) {
            master.checked = false;
            return;
        }
        master.checked = Array.from(checkboxes).every(cb => cb.checked);
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
        const isCompressedRar = (file.archive_type === 'rar' || state.isRar) && file.method && !file.method.includes('Stored');

        if (isCompressedRar) {
            dlBtn.removeAttribute('href');
            dlBtn.classList.add('opacity-40', 'pointer-events-none', 'bg-slate-400');
            dlBtn.classList.remove('bg-indigo-600', 'hover:bg-indigo-700');
            dlBtn.title = "Cannot download individual compressed RAR files without unpacking the full archive.";
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

        // 2. Immediate check for Compressed RAR entries
        const isRar = file.archive_type === 'rar' || state.isRar;
        const isCompressedRar = isRar && file.method && !file.method.includes('Stored');

        // Allow code, documents, AND images to unpack and preview
        const isPreviewable = file.category === 'code' || file.category === 'doc' || file.category === 'image';
        
        if (isCompressedRar && !isPreviewable) {
            document.getElementById('unsupportedTitle').textContent = `Compressed RAR Entry (${file.method || 'Solid'})`;
            document.getElementById('unsupportedSub').innerHTML = 
                'Binary file inside a compressed RAR. Use the <strong>Hex View</strong> tab to inspect raw bytes.';
            document.getElementById('unsupportedPreviewBox').classList.remove('hidden');
            return;
        }

        // 3. Images (with loading spinner & error handling)
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
                        showUnsupportedError('This image is inside a deep solid stream block and cannot be decoded without extracting preceding files.');
                    }
                } catch (_) {
                    showUnsupportedError('Image could not be loaded from remote archive.');
                }
            };

            img.src = rawUrl;
        }
        // 4. Audio
        else if (file.category === 'audio') {
            const audio = document.getElementById('audioPreviewTag');
            audio.src = rawUrl;
            document.getElementById('audioPreviewBox').classList.remove('hidden');
        }
        // 5. PDF Documents
        else if (ext === '.pdf') {
            const pdf = document.getElementById('pdfPreviewTag');
            pdf.src = rawUrl;
            pdf.classList.remove('hidden');
        }
        // 6. CSV Files
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
        // 7. Code & Text Documents
        // 7. Code & Text Documents (.txt, .json, .url, .nfo, .ini, .md, .xml, .yaml, etc.)
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
                    if (match && match[1]) {
                        const targetUrl = match[1].trim();
                        document.getElementById('codeLangBadge').innerHTML = 
                            `URL SHORTCUT &mdash; <a href="${targetUrl}" target="_blank" rel="noopener" class="text-indigo-400 hover:text-indigo-300 underline font-semibold">Open: ${targetUrl} &nearr;</a>`;
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




import tempfile




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
            with requests.get(url, headers=headers, timeout=(10, 15), stream=True) as probe_resp:
                if probe_resp.status_code != 206:
                    return jsonify(error=f"Server returned HTTP {probe_resp.status_code} (HTTP Range Requests not supported)."), 400
                magic = probe_resp.raw.read(16)
                
                # Check for RAR4 / RAR5 signature
                if magic.startswith(RAR5_SIG) or magic.startswith(RAR4_SIG):
                    fmt = "RAR5" if magic.startswith(RAR5_SIG) else "RAR4"
                    crange = probe_resp.headers.get("Content-Range", "")
                    tail = crange.rsplit("/", 1)[-1]
                    total_sz = int(tail) if tail.isdigit() else 0
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

            with RemoteZip(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=NETWORK_TIMEOUT, support_suffix_range=False) as rz:
                for info in rz.infolist():
                    norm_name = info.filename.replace('\\', '/')
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
                if len(ZIP_CACHE) >= MAX_CACHE_ENTRIES:
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

    with RAR_SCANS_LOCK:
        RAR_SCANS[url] = {'stop': False}

    def stop_check():
        with RAR_SCANS_LOCK:
            return RAR_SCANS.get(url, {}).get('stop', False)

    def generate():
        rd = RangeReader(url, window=64 * 1024, timeout=NETWORK_TIMEOUT)
        try:
            total_size = rd.probe()
            magic = rd.read(0, 16)
            fmt = "RAR5" if magic.startswith(RAR5_SIG) else ("RAR4" if magic.startswith(RAR4_SIG) else "RAR")
            
            yield f"data: {json.dumps({'type': 'init', 'fmt': fmt, 'size': total_size, 'size_str': format_size(total_size)})}\n\n"

            entries = []
            info = {
                "fmt": fmt,
                "solid": False,
                "volume": False,
                "enc_headers": False,
                "quick_open": False,
                "notes": []
            }

            for event in scan_rar_generator(rd, info, entries, stop_check):
                yield f"data: {json.dumps(event)}\n\n"

            is_stopped = stop_check()
            populate_rar_cache(url, entries, info, is_partial=is_stopped)

            status_type = "stopped" if is_stopped else "complete"
            yield f"data: {json.dumps({'type': status_type, 'count': len(entries)})}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
        finally:
            with RAR_SCANS_LOCK:
                RAR_SCANS.pop(url, None)

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


@app.route('/api/rar/stop', methods=['POST', 'GET'])
def api_rar_stop():
    url = request.args.get('url')
    if not url:
        return jsonify(error="Missing url"), 400
    url = resolve_download_url(url)
    with RAR_SCANS_LOCK:
        if url in RAR_SCANS:
            RAR_SCANS[url]['stop'] = True
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
    with RAR_SCANS_LOCK:
        RAR_SCANS.pop(url, None)
    return jsonify(status="cleared")

# Place above /api/raw
MIME_OVERRIDES = {
    '.avif': 'image/avif',
    '.webp': 'image/webp',
    '.svg':  'image/svg+xml',
    '.flac': 'audio/flac',
    '.opus': 'audio/opus',
    '.pdf':  'application/pdf',
    '.csv':  'text/plain',
}

def extract_rar_entry_bytes(url, f_obj, filename):
    """Range-slices and extracts a compressed RAR entry to raw binary bytes."""
    tool_cmd = None
    for candidate in [r"C:\Program Files\7-Zip\7z.exe", r"C:\Program Files\WinRAR\UnRAR.exe"]:
        if os.path.exists(candidate):
            tool_cmd = candidate
            break

    if not tool_cmd:
        raise RuntimeError("Neither 7-Zip nor WinRAR installed.")

    off = f_obj['offset']
    MAX_STREAM_BYTES = 75 * 1024 * 1024  # Raised to 75 MB limit
    target_end = off + f_obj['comp_size'] + 8192

    if target_end > MAX_STREAM_BYTES:
        raise ValueError(f"File is located at {format_size(off)} in this solid RAR (limit: {format_size(MAX_STREAM_BYTES)})")

    headers = dict(DEFAULT_HEADERS, Range=f"bytes=0-{target_end}")
    r = requests.get(url, headers=headers, timeout=(10, 45))
    if r.status_code not in (200, 206):
        raise IOError(f"HTTP {r.status_code} fetching chunk")

    with tempfile.NamedTemporaryFile(suffix=".rar", delete=False) as tmp:
        tmp_path = tmp.name
        tmp.write(r.content)

    try:
        # Use exact relative path normalized for the archive
        norm_target = filename.replace('/', os.sep)
        target_name = os.path.basename(filename)

        if "7z" in tool_cmd.lower():
            proc = subprocess.run(
                [tool_cmd, "e", "-so", "-y", "-bd", "-p-", tmp_path, norm_target, target_name],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25
            )
        else:
            proc = subprocess.run(
                [tool_cmd, "p", "-inul", "-y", "-p-", tmp_path, norm_target],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25
            )

        if proc.stdout and len(proc.stdout) > 0:
            return proc.stdout
        err = proc.stderr.decode('utf-8', errors='ignore') or "Extraction failed"
        raise RuntimeError(err)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
# ----------------------------------------------------------------------
# PREVIEW, RAW STREAMING & DIRECT DOWNLOADS
# ----------------------------------------------------------------------
@app.route('/api/raw', methods=['GET'])
def api_raw():

    url = request.args.get('url')
    filename = request.args.get('filename')
    if not url or not filename:
        return "Missing parameters", 400

    url = resolve_download_url(url)
    _, ext = os.path.splitext(filename.lower())
    mime = MIME_OVERRIDES.get(ext) or mimetypes.guess_type(filename)[0] or 'application/octet-stream'
    if not mime:
        mime = 'application/octet-stream'

    # Check RAR Stored File support
    cached = ZIP_CACHE.get(url)
    if cached and cached.get('archive_type') == 'rar':
        f_obj = next((f for f in cached['flat_files'] if f['name'] == filename), None)
        if f_obj:
            # 1. Uncompressed
            if f_obj.get('method') == 'Stored (No compression)' and f_obj['size'] > 0:
                off = f_obj['offset']
                size = f_obj['size']
                headers = dict(DEFAULT_HEADERS, Range=f"bytes={off}-{off + size - 1}")
                r = requests.get(url, headers=headers, stream=True, timeout=NETWORK_TIMEOUT)
                return Response(r.iter_content(chunk_size=16384), headers={"Content-Type": mime, "Cache-Control": "public, max-age=3600"})
            # 2. Compressed Image or Binary (PNG, JPG, ICO, WEBP, etc.)
            else:
                try:
                    raw_data = extract_rar_entry_bytes(url, f_obj, filename)

                    # Validate image signatures so truncated solid streams don't send garbage
                    is_valid_image = False
                    if ext == '.png' and raw_data.startswith(b'\x89PNG\r\n\x1a\n'):
                        is_valid_image = True
                    elif ext in ('.jpg', '.jpeg') and raw_data.startswith(b'\xff\xd8\xff'):
                        is_valid_image = True
                    elif ext == '.gif' and raw_data.startswith(b'GIF8'):
                        is_valid_image = True
                    elif ext == '.webp' and b'WEBP' in raw_data[:16]:
                        is_valid_image = True
                    elif ext == '.ico' and raw_data.startswith(b'\x00\x00\x01\x00'):
                        is_valid_image = True
                    elif ext == '.bmp' and raw_data.startswith(b'BM'):
                        is_valid_image = True

                    if not is_valid_image:
                        return (
                            "This image is stored inside a deep solid compression block. "
                            "It requires extracting earlier files in the archive first."
                        ), 400

                    return Response(raw_data, headers={"Content-Type": mime, "Cache-Control": "public, max-age=3600"})
                except Exception as e:
                    return f"{e}", 400

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

import subprocess
@app.route('/api/view', methods=['GET'])
def api_view():
    url = request.args.get('url')
    filename = request.args.get('filename')
    mode = request.args.get('mode', 'text')

    if not url or not filename:
        return jsonify(error="Missing parameters"), 400

    url = resolve_download_url(url)

    # 1. Handle RAR Archives
    cached = ZIP_CACHE.get(url)
    if cached and cached.get('archive_type') == 'rar':
        f_obj = next((f for f in cached['flat_files'] if f['name'] == filename), None)
        if not f_obj:
            return jsonify(error="File not found in archive"), 404

        off = f_obj['offset']
        size = f_obj['size']

        # Hex View (Reads raw bytes from calculated offset)
        if mode == 'hex':
            try:
                fetch_sz = min(4096, size if size > 0 else 4096)
                headers = dict(DEFAULT_HEADERS, Range=f"bytes={off}-{off + fetch_sz - 1}")
                r = requests.get(url, headers=headers, timeout=NETWORK_TIMEOUT)
                lines = generate_hex_dump(r.content)
                return jsonify(hex_dump=lines, truncated=(size > 4096))
            except Exception as e:
                return jsonify(error=f"Hex view error: {e}"), 500

        # Text/Code View - Uncompressed (Stored / Method 0)
        if f_obj.get('method') == 'Stored (No compression)':
            try:
                fetch_sz = min(512 * 1024, size)
                headers = dict(DEFAULT_HEADERS, Range=f"bytes={off}-{off + fetch_sz - 1}")
                r = requests.get(url, headers=headers, timeout=NETWORK_TIMEOUT)
                try:
                    content = r.content.decode('utf-8')
                except UnicodeDecodeError:
                    content = r.content.decode('cp437', errors='replace')
                return jsonify(content=content, size=len(r.content))
            except Exception as e:
                return jsonify(error=f"Read error: {e}"), 500

        # Text/Code View - Compressed (RAR m1 - m5 via shared 7-Zip extractor)
        else:
            try:
                raw_bytes = extract_rar_entry_bytes(url, f_obj, filename)
                try:
                    content = raw_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    content = raw_bytes.decode('cp437', errors='replace')
                return jsonify(content=content, size=len(content))
            except Exception as e:
                return jsonify(error=f"{e}"), 400

    # 2. Handle Standard ZIP Archives
    try:
        with RemoteZip(url, headers=DEFAULT_HEADERS, timeout=NETWORK_TIMEOUT, support_suffix_range=False) as rz:
            with rz.open(filename) as f:
                if mode == 'hex':
                    raw_bytes = f.read(4096)
                    lines = generate_hex_dump(raw_bytes)
                    return jsonify(hex_dump=lines, truncated=len(raw_bytes) == 4096)
                else:
                    content_bytes = f.read(512 * 1024)
                    try:
                        content = content_bytes.decode('utf-8')
                    except UnicodeDecodeError:
                        content = content_bytes.decode('latin-1', errors='replace')
                    return jsonify(content=content, size=len(content_bytes))
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


def _central_entry(name_b, crc, size, offset, dos_time, dos_date):
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
    hdr = struct.pack('<4sHHHHHHIIIHHHHHII', b'PK\x01\x02', ver, ver, 0x0800, 0,
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


def _norm(name):
    return name.replace('\\', '/')


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


def stream_rar_member(url, file_obj):
    """Streams an uncompressed (Stored/Method 0) RAR entry via HTTP Range requests."""
    offset = file_obj['offset']
    size = file_obj['size']
    sent = 0
    crc = 0
    retries = 0
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    
    while sent < size:
        chunk_to_read = min(CHUNK_SIZE, size - sent)
        curr_off = offset + sent
        try:
            r = session.get(
                url,
                headers={"Range": f"bytes={curr_off}-{curr_off + chunk_to_read - 1}"},
                timeout=NETWORK_TIMEOUT,
                stream=True
            )
            if r.status_code != 206:
                raise OSError(f"HTTP {r.status_code} while fetching chunk")
            data = r.raw.read(chunk_to_read)
            if not data:
                raise IOError(f"Remote stream ended prematurely at byte {sent}/{size}")
            sent += len(data)
            crc = zlib.crc32(data, crc)
            yield data
        except Exception as e:
            retries += 1
            if retries > MAX_MEMBER_RETRIES:
                raise
            time.sleep(min(2 ** retries, 15))
            continue

    exp_crc = int(file_obj['crc32'], 16) if isinstance(file_obj['crc32'], str) else file_obj.get('crc32', 0)
    if exp_crc and (crc & 0xFFFFFFFF) != exp_crc:
        raise IOError(f"CRC mismatch for {file_obj['name']}")


def _rar_zip_response(url, matched_files, zip_name):
    """Constructs an on-the-fly .zip package from uncompressed (Stored) RAR entries."""
    if not matched_files:
        return "No matching files in archive", 404
        
    compressed = [arc for arc, f in matched_files if f.get('method') != 'Stored (No compression)']
    if compressed:
        return (
            "Cannot package compressed RAR entries into .zip on the fly: "
            + ", ".join(compressed[:5])
            + (" ..." if len(compressed) > 5 else "")
            + ". Solid and compressed RAR archives require full unrar decompression.", 400
        )
        
    locked = [arc for arc, f in matched_files if f.get('encrypted')]
    if locked:
        return ("Cannot stream password-protected files: "
                + ", ".join(locked[:5]) + (" ..." if len(locked) > 5 else "")), 400

    records, cd, offset = [], [], 0
    for arcname, f in matched_files:
        crc_val = int(f['crc32'], 16) if isinstance(f['crc32'], str) else f.get('crc32', 0)
        name_b = arcname.encode('utf-8')
        dos_time, dos_date = to_dos_time((2026, 1, 1, 0, 0, 0))
        lh = _local_header(name_b, crc_val, f['size'], dos_time, dos_date)
        records.append((lh, f))
        cd.append(_central_entry(name_b, crc_val, f['size'], offset, dos_time, dos_date))
        offset += len(lh) + f['size']

    cd_bytes = b''.join(cd)
    trailer = cd_bytes + _end_records(len(matched_files), len(cd_bytes), offset)
    total = offset + len(trailer)

    def stream_rar_zip():
        for local_hdr, f in records:
            yield local_hdr
            yield from stream_rar_member(url, f)
        yield trailer

    return Response(stream_with_context(stream_rar_zip()),
                    headers=_attachment_headers(zip_name, total, "application/zip"))


def _zip_response(url, picker, zip_name):
    session = _new_session(url)
    try:
        members = picker(session.get())
        if not members:
            session.close()
            return "No matching files in archive", 404
        locked = [n for n, i in members if i.flag_bits & 0x1]
        if locked:
            session.close()
            return ("Cannot stream password-protected files: "
                    + ", ".join(locked[:5]) + (" ..." if len(locked) > 5 else "")), 400
        records, trailer, total = build_zip_plan(members)
    except Exception as e:
        session.close()
        return f"Error preparing archive: {e}", 500
    return Response(stream_with_context(stream_zip(session, records, trailer)),
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
    cached = ZIP_CACHE.get(url)
    if cached and cached.get('archive_type') == 'rar':
        f_obj = next((f for f in cached['flat_files'] if _norm(f['name']) == wanted), None)
        if not f_obj:
            return "File not found in archive", 404
        if f_obj.get('encrypted'):
            return "File is password protected", 400
        if f_obj.get('method') != 'Stored (No compression)':
            return (f"Cannot download compressed RAR entry ({f_obj.get('method')}) directly. "
                    "Solid and compressed RAR archives require full unrar decompression."), 400

        def generate_rar():
            yield from stream_rar_member(url, f_obj)

        base = os.path.basename(wanted)
        mime, _ = mimetypes.guess_type(base)
        return Response(stream_with_context(generate_rar()),
                        headers=_attachment_headers(base, f_obj['size'], mime or "application/octet-stream"))

    # 2. Handle Standard ZIP Archives
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
    def picker(rz):
        out = []
        for info in rz.infolist():
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
    def picker(rz):
        out, used = [], set()
        for info in rz.infolist():
            n = _norm(info.filename)
            if n.endswith('/'):
                continue
            if n in wanted or os.path.basename(n) in wanted:
                out.append((_unique(os.path.basename(n), used), info))
        return out

    return _zip_response(url, picker, 'selected_files.zip')


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 7860))
    app.run(host="0.0.0.0", port=port, debug=False)