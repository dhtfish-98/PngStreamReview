import struct, zlib, unittest
from pngstreamreview import inspect


def chunk(t, p):
    return (
        struct.pack(">I", len(p))
        + t
        + p
        + struct.pack(">I", zlib.crc32(t + p) & 0xFFFFFFFF)
    )


def sample(depth=8, color=2, interlace=0, raw=b"\0\x00\x00\x00"):
    h = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, depth, color, 0, 0, interlace))
    p = chunk(b"PLTE", b"\0\0\0") if color == 3 else b""
    return (
        b"\x89PNG\r\n\x1a\n"
        + h
        + p
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


class Tests(unittest.TestCase):
    def test_valid_colors(self):
        for depth, color, raw in [
            (8, 2, b"\0" * 4),
            (1, 0, b"\0" * 2),
            (8, 3, b"\0" * 2),
            (16, 6, b"\0" * 9),
        ]:
            self.assertEqual(inspect(sample(depth, color, raw=raw))["status"], "PASS")

    def test_crc(self):
        self.assertEqual(inspect(sample()[:-1] + b"x")["status"], "FAIL")

    def test_all_truncated(self):
        d = sample()
        for i in range(len(d)):
            self.assertNotEqual(inspect(d[:i])["status"], "PASS")

    def test_extra(self):
        self.assertEqual(inspect(sample() + b"x")["status"], "FAIL")

    def test_filter(self):
        self.assertEqual(inspect(sample(raw=b"\5\0\0\0"))["status"], "FAIL")

    def test_expansion(self):
        self.assertEqual(inspect(sample(raw=b"\0" * 100))["status"], "FAIL")

    def test_interlace(self):
        self.assertEqual(inspect(sample(interlace=1))["status"], "OPEN")

    def test_unknown(self):
        self.assertEqual(
            inspect(
                sample().replace(
                    chunk(b"IEND", b""), chunk(b"XXXX", b"") + chunk(b"IEND", b"")
                )
            )["status"],
            "OPEN",
        )

    def test_palette_required(self):
        self.assertEqual(
            inspect(
                sample(color=3, raw=b"\0" * 2).replace(chunk(b"PLTE", b"\0" * 3), b"")
            )["status"],
            "FAIL",
        )

    def test_duplicate(self):
        d = sample()
        self.assertEqual(inspect(d[:33] + d[8:33] + d[33:])["status"], "FAIL")

    def test_pillow_generated_image(self):
        from pathlib import Path

        r = inspect(
            (
                Path(__file__).resolve().parents[1] / "examples/pillow_generated.png"
            ).read_bytes()
        )
        self.assertEqual(r["status"], "PASS")
        self.assertEqual((r["width"], r["height"]), (17, 19))

    def test_zlib_extra_member(self):
        good = sample()
        start = 33
        tail = chunk(
            b"IDAT", zlib.compress(b"\0" * 4) + zlib.compress(b"\0" * 4)
        ) + chunk(b"IEND", b"")
        self.assertEqual(inspect(good[:start] + tail)["status"], "FAIL")

    def test_declared_expansion_limit(self):
        good = sample()
        h = chunk(b"IHDR", struct.pack(">IIBBBBB", 2**30, 2**30, 8, 2, 0, 0, 0))
        self.assertEqual(inspect(good[:8] + h + good[33:])["status"], "FAIL")
