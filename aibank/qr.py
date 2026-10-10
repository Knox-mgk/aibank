"""QR Code encoder (ISO/IEC 18004), byte mode, stdlib only.

WHY THIS EXISTS AT ALL, since a library would be two lines:

The dashboard is one file with no build step and a strict CSP
(`script-src 'self'`), and that is a *security* property, not a packaging
preference: there is no third-party script on the page that sets an account's
spending limits. A JS QR library would be the first one. Generating the symbol
on the server keeps that property and keeps the dependency count at zero,
which the package asserts in its own tests.

It exists because the enrolment page used to say "scan is unavailable here, so
enter the key by hand" -- a 32-character base32 secret typed into a phone. Every
character is a chance to mistype a secret that then produces codes the server
will reject, which is the failure mode that makes people turn 2FA off.

SCOPE, deliberately narrow:

- Byte mode only. A TOTP provisioning URI is mixed-case ASCII, so alphanumeric
  mode cannot encode it and numeric mode is irrelevant. Implementing modes we
  do not use would be untested code in a security path.
- Error-correction level M (~15% recovery). L is too fragile on a phone screen
  photographed by another phone; Q and H cost versions we do not need.
- Versions 1-15, i.e. up to 412 bytes, against a provisioning URI that is ~131
  characters for a normal email and ~200 for a long one. `encode` raises rather
  than silently truncating -- a truncated QR scans cleanly and yields the WRONG
  secret, which is far worse than an error.

VALIDATION: the module matrices this produces are byte-identical to an
independent implementation (`qrcode` 8.2) across the full byte-length range,
mask selection included; `tests/test_qr.py` pins a sample of those matrices plus
the worked example from the specification itself. Matching on mask choice
matters -- a matrix that differs only by mask is still a valid QR, so pinning
whole matrices is what makes the penalty-scoring code honest.
"""

from __future__ import annotations

# --- Reed-Solomon over GF(256), primitive polynomial 0x11d ----------------

_EXP = [1] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _generator_poly(degree: int) -> list[int]:
    """(x - a^0)(x - a^1)...(x - a^(degree-1)) over GF(256)."""
    poly = [1]
    for i in range(degree):
        nxt = [0] * (len(poly) + 1)
        for j, c in enumerate(poly):
            nxt[j] ^= _gf_mul(c, 1)
            nxt[j + 1] ^= _gf_mul(c, _EXP[i])
        poly = nxt
    return poly


def _ec_codewords(data: list[int], count: int) -> list[int]:
    gen = _generator_poly(count)
    rem = list(data) + [0] * count
    for i in range(len(data)):
        coef = rem[i]
        if coef == 0:
            continue
        for j, g in enumerate(gen):
            rem[i + j] ^= _gf_mul(g, coef)
    return rem[len(data):]


# --- Version tables, error-correction level M ----------------------------
# version -> (ec codewords per block, [(block count, data codewords), ...])
# Transcribed from ISO/IEC 18004 table 13-22 and cross-checked against an
# independent implementation; `tests/test_qr.py` re-derives total capacity from
# these rows so a typo cannot pass silently.
_RS_M: dict[int, tuple[int, list[tuple[int, int]]]] = {
    1: (10, [(1, 16)]),
    2: (16, [(1, 28)]),
    3: (26, [(1, 44)]),
    4: (18, [(2, 32)]),
    5: (24, [(2, 43)]),
    6: (16, [(4, 27)]),
    7: (18, [(4, 31)]),
    8: (22, [(2, 38), (2, 39)]),
    9: (22, [(3, 36), (2, 37)]),
    10: (26, [(4, 43), (1, 44)]),
    11: (30, [(1, 50), (4, 51)]),
    12: (22, [(6, 36), (2, 37)]),
    13: (22, [(8, 37), (1, 38)]),
    14: (24, [(4, 40), (5, 41)]),
    15: (24, [(5, 41), (5, 42)]),
}

_ALIGNMENT: dict[int, list[int]] = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
    7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
    11: [6, 30, 54], 12: [6, 32, 58], 13: [6, 34, 62], 14: [6, 26, 46, 66],
    15: [6, 26, 48, 70],
}

MAX_VERSION = 15
_ECC_LEVEL_BITS = 0b00  # level M, per the format-information table


def _data_codeword_count(version: int) -> int:
    _, blocks = _RS_M[version]
    return sum(count * data for count, data in blocks)


def capacity_bytes(version: int) -> int:
    """Payload bytes that fit in `version` at level M, in byte mode."""
    header_bits = 4 + (8 if version < 10 else 16)
    return _data_codeword_count(version) - (header_bits + 7) // 8


def _smallest_version(length: int) -> int:
    for v in range(1, MAX_VERSION + 1):
        if length <= capacity_bytes(v):
            return v
    raise ValueError(
        f"{length} bytes exceeds QR version {MAX_VERSION} at level M "
        f"({capacity_bytes(MAX_VERSION)} bytes). Refusing to truncate: a "
        "truncated symbol scans cleanly and returns the wrong data.")


# --- Bit stream ----------------------------------------------------------

class _Bits:
    def __init__(self) -> None:
        self.bits: list[int] = []

    def put(self, value: int, length: int) -> None:
        for i in range(length - 1, -1, -1):
            self.bits.append((value >> i) & 1)

    def __len__(self) -> int:
        return len(self.bits)


def _encode_codewords(payload: bytes, version: int) -> list[int]:
    total_data = _data_codeword_count(version)
    bs = _Bits()
    bs.put(0b0100, 4)                                  # byte mode
    bs.put(len(payload), 8 if version < 10 else 16)    # character count
    for byte in payload:
        bs.put(byte, 8)

    capacity_bits = total_data * 8
    # Terminator, but only as much of it as fits.
    bs.put(0, min(4, capacity_bits - len(bs)))
    while len(bs) % 8:
        bs.bits.append(0)

    words = [int("".join(str(b) for b in bs.bits[i:i + 8]), 2)
             for i in range(0, len(bs), 8)]
    # Pad alternately with the two specified pad codewords.
    pads = (0xEC, 0x11)
    while len(words) < total_data:
        words.append(pads[(len(words) - len(bs) // 8) % 2])
    return words


def _interleave(words: list[int], version: int) -> list[int]:
    """Split into RS blocks, compute EC, then interleave both as specified.

    Interleaving is what makes the error correction work against a smudge: a
    physically contiguous damaged area hits one codeword of many blocks rather
    than many codewords of one block, and per-block correction capacity is the
    limit that matters.
    """
    ec_per_block, spec = _RS_M[version]
    blocks: list[tuple[list[int], list[int]]] = []
    pos = 0
    for count, data_cw in spec:
        for _ in range(count):
            chunk = words[pos:pos + data_cw]
            pos += data_cw
            blocks.append((chunk, _ec_codewords(chunk, ec_per_block)))
    assert pos == len(words), (pos, len(words))

    out: list[int] = []
    for i in range(max(len(d) for d, _ in blocks)):
        for data, _ in blocks:
            if i < len(data):
                out.append(data[i])
    for i in range(ec_per_block):
        for _, ec in blocks:
            out.append(ec[i])
    return out


# --- Module placement ----------------------------------------------------

_FORMAT_MASK = 0b101010000010010
_FORMAT_GEN = 0b10100110111
_VERSION_GEN = 0b1111100100101


def _bch(value: int, generator: int, bits: int) -> int:
    v = value << bits
    glen = generator.bit_length() - 1
    while v.bit_length() - 1 >= glen + bits - bits:
        if v.bit_length() <= bits:
            break
        v ^= generator << (v.bit_length() - generator.bit_length())
    return v


def _format_bits(mask: int) -> int:
    data = (_ECC_LEVEL_BITS << 3) | mask
    rem = data << 10
    while rem.bit_length() > 10:
        rem ^= _FORMAT_GEN << (rem.bit_length() - _FORMAT_GEN.bit_length())
    return ((data << 10) | rem) ^ _FORMAT_MASK


def _version_bits(version: int) -> int:
    rem = version << 12
    while rem.bit_length() > 12:
        rem ^= _VERSION_GEN << (rem.bit_length() - _VERSION_GEN.bit_length())
    return (version << 12) | rem


def _mask_bit(mask: int, row: int, col: int) -> bool:
    if mask == 0:
        return (row + col) % 2 == 0
    if mask == 1:
        return row % 2 == 0
    if mask == 2:
        return col % 3 == 0
    if mask == 3:
        return (row + col) % 3 == 0
    if mask == 4:
        return (row // 2 + col // 3) % 2 == 0
    if mask == 5:
        return (row * col) % 2 + (row * col) % 3 == 0
    if mask == 6:
        return ((row * col) % 2 + (row * col) % 3) % 2 == 0
    return ((row + col) % 2 + (row * col) % 3) % 2 == 0


class _Canvas:
    def __init__(self, version: int) -> None:
        self.version = version
        self.size = version * 4 + 17
        self.mod: list[list[bool | None]] = [
            [None] * self.size for _ in range(self.size)]
        self.reserved = [[False] * self.size for _ in range(self.size)]

    def _set(self, r: int, c: int, dark: bool, reserve: bool = True) -> None:
        self.mod[r][c] = dark
        if reserve:
            self.reserved[r][c] = True

    def place_function_patterns(self) -> None:
        n = self.size
        for orow, ocol in ((0, 0), (0, n - 7), (n - 7, 0)):
            for r in range(7):
                for c in range(7):
                    dark = (r in (0, 6) or c in (0, 6)
                            or (2 <= r <= 4 and 2 <= c <= 4))
                    self._set(orow + r, ocol + c, dark)
            # separators
            for i in range(8):
                for rr, cc in ((orow + i, ocol - 1), (orow + i, ocol + 7),
                               (orow - 1, ocol + i), (orow + 7, ocol + i)):
                    if 0 <= rr < n and 0 <= cc < n:
                        self._set(rr, cc, False)

        for pos in range(8, n - 8):
            self._set(6, pos, pos % 2 == 0)
            self._set(pos, 6, pos % 2 == 0)

        centers = _ALIGNMENT[self.version]
        for r in centers:
            for c in centers:
                if (r, c) in ((6, 6), (6, n - 7), (n - 7, 6)):
                    continue
                for dr in range(-2, 3):
                    for dc in range(-2, 3):
                        dark = max(abs(dr), abs(dc)) != 1
                        self._set(r + dr, c + dc, dark)

        # Dark module, and the format-information areas (filled in later but
        # reserved now so data placement skips them).
        self._set(n - 8, 8, True)
        for i in range(9):
            if self.mod[8][i] is None:
                self._set(8, i, False)
            if self.mod[i][8] is None:
                self._set(i, 8, False)
        for i in range(8):
            if self.mod[8][n - 1 - i] is None:
                self._set(8, n - 1 - i, False)
            if self.mod[n - 1 - i][8] is None:
                self._set(n - 1 - i, 8, False)

        if self.version >= 7:
            bits = _version_bits(self.version)
            for i in range(18):
                bit = bool((bits >> i) & 1)
                self._set(i // 3, n - 11 + i % 3, bit)
                self._set(n - 11 + i % 3, i // 3, bit)

    def place_data(self, codewords: list[int]) -> None:
        bits = [(w >> (7 - i)) & 1 for w in codewords for i in range(8)]
        n = self.size
        idx = 0
        col = n - 1
        upward = True
        while col > 0:
            if col == 6:        # the vertical timing pattern is not a column
                col -= 1
            rows = range(n - 1, -1, -1) if upward else range(n)
            for row in rows:
                for c in (col, col - 1):
                    if self.reserved[row][c]:
                        continue
                    self.mod[row][c] = bool(bits[idx]) if idx < len(bits) else False
                    idx += 1
            upward = not upward
            col -= 2

    def apply_mask_and_format(self, mask: int) -> list[list[bool]]:
        n = self.size
        out = [[bool(self.mod[r][c]) for c in range(n)] for r in range(n)]
        for r in range(n):
            for c in range(n):
                if not self.reserved[r][c] and _mask_bit(mask, r, c):
                    out[r][c] = not out[r][c]

        fmt = _format_bits(mask)
        for i in range(15):
            bit = bool((fmt >> i) & 1)
            # Copy 1: the vertical strip beside the top-left finder, LSB at the
            # top, skipping the horizontal timing row at index 6.
            if i < 6:
                out[i][8] = bit
            elif i < 8:
                out[i + 1][8] = bit
            else:
                out[n - 15 + i][8] = bit
            # Copy 2: the horizontal run, split between the top-right and
            # bottom-left finders. The whole point of the second copy is that
            # losing one corner must not cost the mask number, without which
            # the symbol cannot be read at all.
            if i < 8:
                out[8][n - 1 - i] = bit
            else:
                out[8][14 - i + (1 if i == 8 else 0)] = bit
        out[n - 8][8] = True
        return out


# --- Mask selection ------------------------------------------------------

def _penalty(m: list[list[bool]]) -> int:
    n = len(m)
    score = 0

    # Rule 1: runs of five or more same-coloured modules in a line.
    for line in (m, [[m[r][c] for r in range(n)] for c in range(n)]):
        for row in line:
            run, prev = 1, row[0]
            for v in row[1:]:
                if v == prev:
                    run += 1
                else:
                    if run >= 5:
                        score += 3 + run - 5
                    run, prev = 1, v
            if run >= 5:
                score += 3 + run - 5

    # Rule 2: 2x2 blocks of one colour.
    for r in range(n - 1):
        for c in range(n - 1):
            if m[r][c] == m[r][c + 1] == m[r + 1][c] == m[r + 1][c + 1]:
                score += 3

    # Rule 3: the finder-like 1:1:3:1:1 pattern with four light modules either
    # side, which a scanner can mistake for a position marker.
    pat_a = [True, False, True, True, True, False, True,
             False, False, False, False]
    pat_b = list(reversed(pat_a))
    for r in range(n):
        for c in range(n - 10):
            window = m[r][c:c + 11]
            if window == pat_a or window == pat_b:
                score += 40
    for c in range(n):
        col = [m[r][c] for r in range(n)]
        for r in range(n - 10):
            window = col[r:r + 11]
            if window == pat_a or window == pat_b:
                score += 40

    # Rule 4: deviation from 50% dark.
    dark = sum(1 for row in m for v in row if v)
    ratio = dark * 100 // (n * n)
    score += 10 * (abs(ratio - 50) // 5)
    return score


def encode(data: str | bytes, version: int | None = None) -> list[list[bool]]:
    """Encode `data` as a QR matrix of booleans (True == dark module).

    Byte mode, error-correction level M, smallest version that fits unless one
    is given. The returned matrix carries NO quiet zone -- renderers add it,
    because a symbol without one does not reliably scan and the margin is a
    presentation concern.
    """
    payload = data.encode() if isinstance(data, str) else bytes(data)
    # `version or _smallest_version(...)` would be wrong: 0 is falsy, so an
    # explicit version=0 would be silently replaced by a computed one instead
    # of rejected, and the caller would never learn its argument was ignored.
    if version is None:
        version = _smallest_version(len(payload))
    if not 1 <= version <= MAX_VERSION:
        raise ValueError(f"version {version} outside supported range 1-{MAX_VERSION}")
    if len(payload) > capacity_bytes(version):
        raise ValueError(
            f"{len(payload)} bytes does not fit version {version} "
            f"({capacity_bytes(version)} bytes at level M)")

    words = _interleave(_encode_codewords(payload, version), version)

    best = None
    for mask in range(8):
        canvas = _Canvas(version)
        canvas.place_function_patterns()
        canvas.place_data(words)
        matrix = canvas.apply_mask_and_format(mask)
        score = _penalty(matrix)
        if best is None or score < best[0]:
            best = (score, matrix)
    assert best is not None
    return best[1]


def rows_to_strings(matrix: list[list[bool]]) -> list[str]:
    """Matrix as '0'/'1' strings -- the JSON-friendly form the API returns.

    The API deliberately returns MODULES, not SVG markup. Returning markup
    would mean the page injecting server-supplied HTML into the DOM, and the
    page's whole defence is that it never does that; a grid of digits cannot
    carry a script no matter what the server sends.
    """
    return ["".join("1" if v else "0" for v in row) for row in matrix]


def to_svg(matrix: list[list[bool]], *, quiet: int = 4, scale: int = 4) -> str:
    """Standalone SVG, for the CLI and for tests. The page builds its own."""
    n = len(matrix)
    dim = (n + quiet * 2) * scale
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{dim}" height="{dim}" '
        f'viewBox="0 0 {n + quiet * 2} {n + quiet * 2}" shape-rendering="crispEdges">',
        f'<rect width="{n + quiet * 2}" height="{n + quiet * 2}" fill="#fff"/>',
        '<path fill="#000" d="',
    ]
    d = []
    for r, row in enumerate(matrix):
        c = 0
        while c < n:
            if row[c]:
                run = 1
                while c + run < n and row[c + run]:
                    run += 1
                d.append(f"M{c + quiet} {r + quiet}h{run}v1h-{run}z")
                c += run
            else:
                c += 1
    parts.append("".join(d))
    parts.append('"/></svg>')
    return "".join(parts)


def to_text(matrix: list[list[bool]], quiet: int = 2) -> str:
    """Terminal rendering, two half-blocks per row so modules stay square."""
    n = len(matrix)
    padded = ([[False] * (n + quiet * 2) for _ in range(quiet)]
              + [[False] * quiet + row + [False] * quiet for row in matrix]
              + [[False] * (n + quiet * 2) for _ in range(quiet)])
    if len(padded) % 2:
        padded.append([False] * len(padded[0]))
    lines = []
    for i in range(0, len(padded), 2):
        top, bottom = padded[i], padded[i + 1]
        line = []
        for t, b in zip(top, bottom):
            line.append("█" if t and b else "▀" if t else "▄" if b else " ")
        lines.append("".join(line))
    return "\n".join(lines)
