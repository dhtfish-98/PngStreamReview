# New implementation author: dhtfish98.
import argparse
import hashlib
import json
import os
import stat
import struct

MAX_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 100000


class Invalid(ValueError):
    pass


class Unsupported(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise Invalid(code)


def unpack(fmt, data, offset=0):
    require(
        offset >= 0 and offset + struct.calcsize(fmt) <= len(data), "truncated_field"
    )
    return struct.unpack_from(fmt, data, offset)


def text(data, encoding="utf-8"):
    try:
        return data.decode(encoding)
    except UnicodeError:
        raise Invalid("invalid_text_encoding") from None


def inspect(data):
    if not isinstance(data, bytes):
        raise TypeError("input must be bytes")
    digest = hashlib.sha256(data).hexdigest()
    try:
        require(len(data) <= MAX_BYTES, "input_limit")
        result = analyze(data)
        result.setdefault("status", "PASS")
        result.setdefault("complete", result["status"] == "PASS")
        result.setdefault("findings", [])
    except Unsupported as exc:
        result = {"status": "OPEN", "complete": False, "findings": [str(exc)]}
    except Invalid as exc:
        result = {"status": "FAIL", "complete": False, "findings": [str(exc)]}
    result.update(
        {
            "input_sha256": digest,
            "input_bytes": len(data),
            "claim": "Recorded format checks only; no authenticity, runtime or CVP approval conclusion.",
        }
    )
    return result


def read_local(path):
    nofollow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    if not isinstance(nofollow, int) or not nofollow or not isinstance(nonblock, int) or not nonblock:
        raise Unsupported("safe_local_read_flags_unavailable")
    fd = os.open(path, os.O_RDONLY | nofollow | nonblock)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode), "regular_file_required")
        require(info.st_size <= MAX_BYTES, "input_limit")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(MAX_BYTES + 1)
        require(len(data) <= MAX_BYTES, "input_limit")
        after = os.fstat(fd)
        require(
            (info.st_size, info.st_mtime_ns, info.st_ino)
            == (after.st_size, after.st_mtime_ns, after.st_ino),
            "input_changed_during_read",
        )
        return data
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(
        description="Read an explicitly supplied local evidence file and print a private-safe JSON report."
    )
    parser.add_argument("input")
    args = parser.parse_args()
    try:
        report = inspect(read_local(args.input))
    except Unsupported as exc:
        report = {"status": "OPEN", "complete": False, "findings": [str(exc)]}
    except (OSError, Invalid):
        report = {
            "status": "FAIL",
            "complete": False,
            "findings": ["input_read_failed"],
        }
    print(json.dumps(report, sort_keys=True, ensure_ascii=True))
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[report["status"]]


import zlib

MAX_EXPANDED = 64 * 1024 * 1024


def analyze(data):
    require(data.startswith(b"\x89PNG\r\n\x1a\n"), "invalid_png_signature")
    offset, chunks, seen, idat, stage = 8, [], set(), [], 0
    width = height = depth = color = interlace = None
    palette = None
    while offset < len(data):
        require(len(chunks) < MAX_RECORDS, "chunk_limit")
        (size,) = unpack(">I", data, offset)
        require(size <= MAX_BYTES and offset + size + 12 <= len(data), "chunk_bounds")
        kind = data[offset + 4 : offset + 8]
        require(
            all(65 <= x <= 90 or 97 <= x <= 122 for x in kind) and not (kind[2] & 32),
            "invalid_chunk_type",
        )
        payload = data[offset + 8 : offset + 8 + size]
        (crc,) = unpack(">I", data, offset + 8 + size)
        require(zlib.crc32(kind + payload) & 0xFFFFFFFF == crc, "chunk_crc_mismatch")
        require(chunks or kind == b"IHDR", "ihdr_not_first")
        if kind in (
            b"IHDR",
            b"PLTE",
            b"IEND",
            b"tRNS",
            b"cHRM",
            b"gAMA",
            b"iCCP",
            b"sRGB",
            b"sBIT",
            b"bKGD",
            b"pHYs",
            b"tIME",
        ):
            require(kind not in seen, "duplicate_singleton_chunk")
        if kind == b"IHDR":
            require(size == 13 and not chunks, "invalid_ihdr")
            width, height, depth, color, compression, filtering, interlace = unpack(
                ">IIBBBBB", payload
            )
            require(0 < width < 2**31 and 0 < height < 2**31, "invalid_dimensions")
            valid = {
                0: (1, 2, 4, 8, 16),
                2: (8, 16),
                3: (1, 2, 4, 8),
                4: (8, 16),
                6: (8, 16),
            }
            require(
                color in valid
                and depth in valid[color]
                and compression == 0
                and filtering == 0
                and interlace in (0, 1),
                "invalid_ihdr_fields",
            )
        elif kind == b"PLTE":
            require(b"tRNS" not in seen, "palette_after_transparency")
            require(
                stage == 0
                and size > 0
                and size % 3 == 0
                and size <= 768
                and color not in (0, 4),
                "invalid_palette",
            )
            palette = size // 3
            require(color != 3 or palette <= 2**depth, "palette_depth_mismatch")
        elif kind == b"IDAT":
            require(stage < 2, "noncontiguous_idat")
            require(color != 3 or palette is not None, "missing_palette")
            stage = 1
            idat.append(payload)
        elif kind == b"IEND":
            require(size == 0 and stage > 0 and idat, "invalid_iend")
            require(offset + 12 == len(data), "data_after_iend")
        elif kind == b"tRNS":
            require(stage == 0 and color in (0, 2, 3), "invalid_transparency")
            require(
                (color == 0 and size == 2)
                or (color == 2 and size == 6)
                or (color == 3 and palette is not None and 0 < size <= palette),
                "transparency_length",
            )
        elif kind in (b"acTL", b"fcTL", b"fdAT"):
            raise Unsupported("animated_png_not_in_supported_scope")
        elif not kind[0] & 32:
            raise Unsupported("unknown_critical_chunk")
        if stage == 1 and kind not in (b"IDAT", b"IEND"):
            stage = 2
        if kind in (b"cHRM", b"gAMA", b"iCCP", b"sRGB", b"sBIT"):
            require(stage == 0 and b"PLTE" not in seen, "color_chunk_order")
        chunks.append({"offset": offset, "type": kind.decode("ascii"), "bytes": size})
        seen.add(kind)
        offset += size + 12
    require(b"IEND" in seen and idat, "missing_required_chunk")
    if interlace:
        raise Unsupported("adam7_not_in_supported_scope")
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color]
    row = (width * channels * depth + 7) // 8
    expected = height * (row + 1)
    require(expected <= MAX_EXPANDED, "expanded_image_limit")
    decoder = zlib.decompressobj()
    try:
        expanded = decoder.decompress(b"".join(idat), expected + 1)
    except zlib.error:
        raise Invalid("invalid_zlib_stream") from None
    require(
        len(expanded) == expected
        and decoder.eof
        and not decoder.unused_data
        and not decoder.unconsumed_tail,
        "image_stream_length_or_trailing_data",
    )
    require(
        all(expanded[i * (row + 1)] <= 4 for i in range(height)),
        "invalid_scanline_filter",
    )
    return {
        "chunks": chunks,
        "width": width,
        "height": height,
        "bit_depth": depth,
        "color_type": color,
        "checked_scanlines": height,
        "scope": "Non-interlaced PNG envelope, CRC, chunk order and bounded zlib/scanline syntax; no pixel reconstruction, text decompression or image authenticity claim.",
    }
