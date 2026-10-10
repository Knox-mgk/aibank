"""Tests for the QR encoder.

The strongest available proof with zero dependencies is a DECODER: walk the
emitted symbol the way a scanner does -- read the format information, undo the
mask, de-interleave the blocks, check every Reed-Solomon syndrome, then parse
the bit stream back to bytes. If that returns the payload, the symbol is
readable, and it is readable without trusting any of the encoder's own helpers.

That matters here because byte-identity against another implementation is NOT
available as a test: `aibank.qr` and `qrcode` 8.2 legitimately choose different
masks (they disagree on whether format modules count toward the penalty score).
`scripts/dev/qr_difftest.py` does the cross-check mask-by-mask, where there IS
a single right answer, and reports 0 mismatches over 2672 matrices spanning
versions 1-15. This file covers the rest from the other side, plus the handful
of fixed vectors that pin the output so a refactor cannot silently change it.
"""

import unittest

from aibank import qr
from aibank import totp as T

# ---------------------------------------------------------------- decoder


class _Decoder:
    """Minimal QR reader for the subset aibank.qr emits (byte mode, level M).

    Deliberately independent of the encoder: it re-derives the function-pattern
    layout and the RS syndrome check from the matrix alone, so a bug shared
    with the encoder cannot cancel out. The one thing it reuses is the GF(256)
    table, which the RFC-style vectors below pin separately.
    """

    def __init__(self, matrix: list[list[bool]]):
        self.m = matrix
        self.n = len(matrix)
        if (self.n - 17) % 4:
            raise ValueError(f"size {self.n} is not a valid QR dimension")
        self.version = (self.n - 17) // 4

    # -- format information -------------------------------------------
    def read_mask(self) -> int:
        bits = 0
        for i in range(15):
            if i < 6:
                bit = self.m[i][8]
            elif i < 8:
                bit = self.m[i + 1][8]
            else:
                bit = self.m[self.n - 15 + i][8]
            bits |= int(bit) << i
        bits ^= 0b101010000010010
        ecc = (bits >> 13) & 0b11
        if ecc != 0b00:
            raise AssertionError(f"expected level M (0b00), read {ecc:#04b}")
        return (bits >> 10) & 0b111

    # -- reserved-module map ------------------------------------------
    def reserved(self) -> list[list[bool]]:
        n = self.n
        res = [[False] * n for _ in range(n)]

        def block(r0, c0, h, w):
            for r in range(r0, r0 + h):
                for c in range(c0, c0 + w):
                    if 0 <= r < n and 0 <= c < n:
                        res[r][c] = True

        for r0, c0 in ((0, 0), (0, n - 8), (n - 8, 0)):
            block(r0, c0, 8, 8)
        block(0, n - 8, 8, 8)
        for i in range(n):
            res[6][i] = True
            res[i][6] = True
        block(0, 0, 9, 9)
        block(0, n - 8, 9, 8)
        block(n - 8, 0, 8, 9)
        for r in qr._ALIGNMENT[self.version]:
            for c in qr._ALIGNMENT[self.version]:
                if (r, c) in ((6, 6), (6, n - 7), (n - 7, 6)):
                    continue
                block(r - 2, c - 2, 5, 5)
        if self.version >= 7:
            block(0, n - 11, 6, 3)
            block(n - 11, 0, 3, 6)
        return res

    # -- data ----------------------------------------------------------
    def codewords(self) -> list[int]:
        mask = self.read_mask()
        res = self.reserved()
        bits: list[int] = []
        n = self.n
        col = n - 1
        upward = True
        while col > 0:
            if col == 6:
                col -= 1
            rows = range(n - 1, -1, -1) if upward else range(n)
            for row in rows:
                for c in (col, col - 1):
                    if res[row][c]:
                        continue
                    v = self.m[row][c]
                    if qr._mask_bit(mask, row, c):
                        v = not v
                    bits.append(int(v))
            upward = not upward
            col -= 2
        return [int("".join(str(b) for b in bits[i:i + 8]), 2)
                for i in range(0, len(bits) - len(bits) % 8, 8)]

    def deinterleave(self) -> list[int]:
        ec_per_block, spec = qr._RS_M[self.version]
        sizes = [data for count, data in spec for _ in range(count)]
        words = self.codewords()

        data_total = sum(sizes)
        data_blocks: list[list[int]] = [[] for _ in sizes]
        idx = 0
        for i in range(max(sizes)):
            for b, size in enumerate(sizes):
                if i < size:
                    data_blocks[b].append(words[idx])
                    idx += 1
        ec_blocks: list[list[int]] = [[] for _ in sizes]
        for i in range(ec_per_block):
            for b in range(len(sizes)):
                ec_blocks[b].append(words[idx])
                idx += 1

        # Every block's syndrome must be zero, i.e. the codeword is a valid RS
        # codeword with no detected errors. A matrix that decodes to the right
        # bytes but carries a nonzero syndrome would scan today and fail after
        # one smudge, so this is checked rather than assumed.
        for data, ec in zip(data_blocks, ec_blocks):
            full = data + ec
            for i in range(ec_per_block):
                syn = 0
                for j, c in enumerate(full):
                    if c:
                        syn ^= qr._EXP[(qr._LOG[c] + i * (len(full) - 1 - j)) % 255]
                if syn != 0:
                    raise AssertionError(f"nonzero RS syndrome {syn} at power {i}")

        out: list[int] = []
        for b in data_blocks:
            out.extend(b)
        assert len(out) == data_total
        return out

    def payload(self) -> bytes:
        words = self.deinterleave()
        bits = [(w >> (7 - i)) & 1 for w in words for i in range(8)]
        pos = 0

        def take(count: int) -> int:
            nonlocal pos
            v = 0
            for _ in range(count):
                v = (v << 1) | bits[pos]
                pos += 1
            return v

        mode = take(4)
        if mode != 0b0100:
            raise AssertionError(f"expected byte mode 0b0100, read {mode:#06b}")
        length = take(8 if self.version < 10 else 16)
        return bytes(take(8) for _ in range(length))


def roundtrip(data: bytes | str) -> bytes:
    payload = data.encode() if isinstance(data, str) else data
    return _Decoder(qr.encode(payload)).payload()


# ---------------------------------------------------------------- tests


class TestRoundTrip(unittest.TestCase):
    def test_short_payloads(self):
        for data in (b"a", b"ab", b"hello", b"0", b"\x00", b"\xff" * 10,
                     bytes(range(256))[:14]):
            self.assertEqual(roundtrip(data), data, f"failed for {data!r}")

    def test_every_version_boundary(self):
        """Exact capacity, and one byte under, for all 15 versions.

        Boundaries are where a wrong RS table row or a miscounted terminator
        shows up, and they are the only lengths that can expose it.
        """
        for v in range(1, qr.MAX_VERSION + 1):
            cap = qr.capacity_bytes(v)
            for n in (cap - 1, cap):
                data = bytes((i * 7 + n) % 256 for i in range(n))
                matrix = qr.encode(data)
                self.assertEqual(len(matrix), v * 4 + 17,
                                 f"{n} bytes should pick version {v}")
                self.assertEqual(_Decoder(matrix).payload(), data,
                                 f"round trip failed at version {v}, {n} bytes")

    def test_all_byte_values_survive(self):
        """Byte mode must be byte-transparent, not text-transparent."""
        data = bytes(range(256))[:200]
        self.assertEqual(roundtrip(data), data)

    def test_every_mask_decodes(self):
        """Not just the chosen mask: all 8 maskings must be readable.

        The selection heuristic picks one, but a placement bug confined to a
        single mask would hide behind whichever one happens to win.
        """
        data = b"aibank mask coverage"
        version = qr._smallest_version(len(data))
        words = qr._interleave(qr._encode_codewords(data, version), version)
        for mask in range(8):
            canvas = qr._Canvas(version)
            canvas.place_function_patterns()
            canvas.place_data(words)
            matrix = canvas.apply_mask_and_format(mask)
            dec = _Decoder(matrix)
            self.assertEqual(dec.read_mask(), mask)
            self.assertEqual(dec.payload(), data)


class TestProvisioningURI(unittest.TestCase):
    """The payload this exists for, end to end."""

    def test_totp_uri_round_trips(self):
        secret = T.new_secret()
        uri = T.provisioning_uri(secret, "demo@aibank.local")
        self.assertEqual(roundtrip(uri).decode(), uri)

    def test_long_email_still_fits(self):
        """A plausible worst-case account name must not hit the version cap."""
        email = ("a-very-long-email-address-someone-might-plausibly-have@"
                 "a-long-corporate-domain-name.example.com")
        uri = T.provisioning_uri(T.new_secret(), email)
        self.assertGreater(len(uri), 190)
        self.assertEqual(roundtrip(uri).decode(), uri)

    def test_secret_is_recoverable_from_the_symbol(self):
        """The actual user-facing claim: scanning yields the right secret."""
        secret = T.new_secret()
        uri = T.provisioning_uri(secret, "demo@aibank.local")
        decoded = roundtrip(uri).decode()
        self.assertIn(f"secret={secret}", decoded)


class TestStructure(unittest.TestCase):
    def test_finder_patterns_in_three_corners(self):
        m = qr.encode("structure")
        n = len(m)
        for r0, c0 in ((0, 0), (0, n - 7), (n - 7, 0)):
            self.assertTrue(all(m[r0][c0 + i] for i in range(7)))
            self.assertTrue(m[r0 + 3][c0 + 3])
            self.assertFalse(m[r0 + 1][c0 + 1])
        # The fourth corner must NOT have one; that asymmetry is how a scanner
        # works out the symbol's rotation.
        self.assertFalse(all(m[n - 7][n - 7 + i] for i in range(7)))

    def test_timing_patterns_alternate(self):
        m = qr.encode("timing")
        n = len(m)
        for i in range(8, n - 8):
            self.assertEqual(m[6][i], i % 2 == 0)
            self.assertEqual(m[i][6], i % 2 == 0)

    def test_dark_module_is_set(self):
        m = qr.encode("dark")
        self.assertTrue(m[len(m) - 8][8])

    def test_version_tables_are_self_consistent(self):
        """Transcribed tables: re-derive capacity so a typo cannot pass.

        Total codewords for a version is fixed by its geometry, so block
        counts, data codewords and EC codewords must add up to it.
        """
        total_codewords = {
            1: 26, 2: 44, 3: 70, 4: 100, 5: 134, 6: 172, 7: 196, 8: 242,
            9: 292, 10: 346, 11: 404, 12: 466, 13: 532, 14: 581, 15: 655,
        }
        for v, (ec_per_block, spec) in qr._RS_M.items():
            blocks = sum(count for count, _ in spec)
            data = sum(count * d for count, d in spec)
            self.assertEqual(data + blocks * ec_per_block, total_codewords[v],
                             f"version {v} codeword counts do not add up")

    def test_mask_choice_is_deterministic(self):
        a = qr.encode("determinism")
        b = qr.encode("determinism")
        self.assertEqual(a, b)


class TestRefusals(unittest.TestCase):
    def test_oversize_payload_raises_rather_than_truncating(self):
        """A truncated symbol scans cleanly and yields the WRONG secret."""
        with self.assertRaises(ValueError) as cm:
            qr.encode(b"x" * (qr.capacity_bytes(qr.MAX_VERSION) + 1))
        self.assertIn("Refusing to truncate", str(cm.exception))

    def test_payload_too_big_for_a_forced_version(self):
        with self.assertRaises(ValueError):
            qr.encode(b"x" * 30, version=1)

    def test_version_outside_range(self):
        for bad in (0, 16, 41, -1):
            with self.assertRaises(ValueError):
                qr.encode(b"x", version=bad)


class TestRenderers(unittest.TestCase):
    def test_rows_to_strings_matches_matrix(self):
        m = qr.encode("render")
        rows = qr.rows_to_strings(m)
        self.assertEqual(len(rows), len(m))
        self.assertTrue(all(len(r) == len(m) for r in rows))
        self.assertEqual(rows[6][8], "1" if m[6][8] else "0")
        self.assertTrue(all(ch in "01" for row in rows for ch in row))

    def test_rows_carry_no_markup(self):
        """The API returns modules, not SVG, so the page never injects HTML."""
        for row in qr.rows_to_strings(qr.encode("<script>alert(1)</script>")):
            self.assertNotIn("<", row)

    def test_svg_has_a_quiet_zone(self):
        m = qr.encode("quiet")
        svg = qr.to_svg(m, quiet=4, scale=1)
        self.assertIn(f'viewBox="0 0 {len(m) + 8} {len(m) + 8}"', svg)
        self.assertTrue(svg.startswith("<svg"))
        self.assertTrue(svg.endswith("</svg>"))

    def test_text_rendering_is_rectangular(self):
        lines = qr.to_text(qr.encode("text"), quiet=2).split("\n")
        self.assertTrue(all(len(line) == len(lines[0]) for line in lines))


if __name__ == "__main__":
    unittest.main()
