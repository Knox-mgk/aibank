"""Recover a QR payload from a SCREENSHOT, using only the stdlib.

WHY THIS EXISTS

`tests/test_qr.py` proves the encoder's matrix round-trips, and
`scripts/dom_check.mjs` proves the page builds an SVG whose geometry decodes.
Neither touches a single rendered PIXEL. Everything after the DOM -- the SVG
viewBox, `shape-rendering`, the CSS that sizes and pads the symbol, the dark
theme behind it, the browser's own rasteriser -- is unverified, and that is
exactly the layer that decides whether a phone camera can read the thing.

So: screenshot the enrolment card in a real browser, run it through here, and
either the otpauth URI comes back or the rendering is broken. That is the only
check in this project that speaks for an actual scanner.

WHAT IT DOES NOT NEED: Pillow, numpy, zbar, a QR library, or a network. PNG is
zlib plus a byte layout, and a browser-rendered QR is a clean axis-aligned grid,
so sampling it is arithmetic rather than computer vision. Keeping it
dependency-free means it runs on the phone that has no room to install anything.

LIMITS, stated so a failure is not misread as a broken symbol:
  - PNG only (that is what both Playwright and Chrome produce), 8-bit, any of
    the greyscale/RGB/palette/alpha colour types, non-interlaced.
  - The symbol must be axis-aligned and roughly unrotated. A photograph of a
    screen needs perspective correction, which is where computer vision would
    actually start.

Usage:
    python scripts/dev/decode_png_qr.py shot.png [--expect-secret ABC...]
    python scripts/dev/decode_png_qr.py --selftest
"""
from __future__ import annotations

import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))

from aibank import qr as myqr                                    # noqa: E402
from tests.test_qr import _Decoder                               # noqa: E402

# ------------------------------------------------------------------ PNG


def read_png_gray(path: str) -> tuple[int, int, list[list[int]]]:
    """Return (width, height, rows of 0-255 luminance). Stdlib only."""
    with open(path, "rb") as fh:
        blob = fh.read()
    if blob[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError(f"{path}: not a PNG")

    pos, idat, hdr, palette, trns = 8, [], None, None, None
    while pos < len(blob):
        (length,) = struct.unpack(">I", blob[pos:pos + 4])
        kind = blob[pos + 4:pos + 8]
        body = blob[pos + 8:pos + 8 + length]
        if kind == b"IHDR":
            hdr = struct.unpack(">IIBBBBB", body)
        elif kind == b"IDAT":
            idat.append(body)
        elif kind == b"PLTE":
            palette = body
        elif kind == b"tRNS":
            trns = body
        elif kind == b"IEND":
            break
        pos += 12 + length

    if hdr is None:
        raise ValueError(f"{path}: no IHDR")
    w, h, depth, colour, comp, filt, interlace = hdr
    if depth != 8:
        raise ValueError(f"{path}: only 8-bit PNG supported, got {depth}")
    if interlace:
        raise ValueError(f"{path}: interlaced PNG not supported")
    if comp or filt:
        raise ValueError(f"{path}: unexpected compression/filter method")

    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(colour)
    if channels is None:
        raise ValueError(f"{path}: unsupported colour type {colour}")

    raw = zlib.decompress(b"".join(idat))
    stride = w * channels
    out, prev = [], bytearray(stride)
    at = 0
    for _ in range(h):
        ftype = raw[at]
        line = bytearray(raw[at + 1:at + 1 + stride])
        at += 1 + stride
        # Undo the per-scanline filter (PNG spec 9.2). Each is defined in terms
        # of the already-reconstructed bytes to its left and above.
        if ftype == 1:
            for i in range(channels, stride):
                line[i] = (line[i] + line[i - channels]) & 0xFF
        elif ftype == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ftype == 3:
            for i in range(stride):
                left = line[i - channels] if i >= channels else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif ftype == 4:
            for i in range(stride):
                a = line[i - channels] if i >= channels else 0
                b = prev[i]
                c = prev[i - channels] if i >= channels else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pred = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pred) & 0xFF
        elif ftype != 0:
            raise ValueError(f"{path}: bad filter type {ftype}")
        prev = line

        row = []
        for x in range(w):
            px = line[x * channels:(x + 1) * channels]
            if colour == 3:                               # palette
                idx = px[0]
                r, g, b = palette[idx * 3:idx * 3 + 3]
                alpha = trns[idx] if trns and idx < len(trns) else 255
            elif colour in (0, 4):                        # grey, grey+alpha
                r = g = b = px[0]
                alpha = px[1] if colour == 4 else 255
            else:                                         # rgb, rgba
                r, g, b = px[0], px[1], px[2]
                alpha = px[3] if colour == 6 else 255
            lum = (r * 299 + g * 587 + b * 114) // 1000
            # Composite onto WHITE: a transparent screenshot region is page
            # background, and treating it as black would invent dark modules.
            if alpha != 255:
                lum = (lum * alpha + 255 * (255 - alpha)) // 255
            row.append(lum)
        out.append(row)
    return w, h, out

# ------------------------------------------------------------ locate grid


def _is_dark(v: int, threshold: int) -> bool:
    return v < threshold


def find_symbol(rows: list[list[int]], threshold: int = 128):
    """Bounding box of the dark region, i.e. the symbol minus its quiet zone."""
    h, w = len(rows), len(rows[0])
    top = left = None
    bottom = right = -1
    for y in range(h):
        row = rows[y]
        for x in range(w):
            if _is_dark(row[x], threshold):
                if top is None:
                    top = y
                bottom = y
                left = x if left is None else min(left, x)
                right = max(right, x)
    if top is None:
        raise ValueError("no dark pixels: blank image, or the QR did not render")
    return left, top, right, bottom


def module_size(rows, left, top, right, threshold=128) -> float:
    """Measure one module from the top-left finder pattern.

    The finder's TOP row is 7 solid dark modules, so the dark run along row
    `top` starting at column `left` is exactly 7 modules wide -- a measurement
    taken from the symbol itself rather than assumed from the image size, which
    is what makes this work under arbitrary CSS scaling and device pixel ratios.

    Measure on row `top` itself, not one below: at 1 pixel per module the next
    row is the finder's HOLLOW second row (dark, light x5, dark) and the run is
    one pixel, which reads as "symbol too small" on a perfectly good symbol.
    """
    y = top
    while y <= right and not _is_dark(rows[y][left], threshold):
        y += 1                      # tolerate a stray lighter first row
    run, x = 0, left
    while x <= right and _is_dark(rows[y][x], threshold):
        run += 1
        x += 1
    if run < 7:
        raise ValueError(f"finder run too short ({run}px): symbol too small "
                         f"or not axis-aligned")
    return run / 7.0


def sample_matrix(rows, threshold: int = 128) -> list[list[bool]]:
    left, top, right, bottom = find_symbol(rows, threshold)
    mod = module_size(rows, left, top, right, threshold)
    n_w = round((right - left + 1) / mod)
    n_h = round((bottom - top + 1) / mod)
    if n_w != n_h:
        raise ValueError(f"symbol is not square: {n_w}x{n_h} modules")
    if (n_w - 17) % 4:
        raise ValueError(f"{n_w} is not a legal QR dimension "
                         f"(expected 17+4v); clipped or padded by CSS?")
    step_x = (right - left + 1) / n_w
    step_y = (bottom - top + 1) / n_h
    matrix = []
    for r in range(n_h):
        out = []
        for c in range(n_w):
            # Sample the module's CENTRE, never its edge: an antialiased
            # boundary pixel is a coin flip and would corrupt whole codewords.
            y = int(top + (r + 0.5) * step_y)
            x = int(left + (c + 0.5) * step_x)
            out.append(_is_dark(rows[y][x], threshold))
        matrix.append(out)
    return matrix


def decode_png(path: str) -> bytes:
    _, _, rows = read_png_gray(path)
    return _Decoder(sample_matrix(rows)).payload()

# ------------------------------------------------------------- self test


def _write_png(path: str, pixels: list[list[int]]) -> None:
    """Minimal 8-bit greyscale PNG writer, for the self test only."""
    h, w = len(pixels), len(pixels[0])
    raw = b"".join(b"\x00" + bytes(row) for row in pixels)

    def chunk(kind: bytes, body: bytes) -> bytes:
        return (struct.pack(">I", len(body)) + kind + body
                + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF))

    with open(path, "wb") as fh:
        fh.write(b"\x89PNG\r\n\x1a\n")
        fh.write(chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 0, 0, 0, 0)))
        fh.write(chunk(b"IDAT", zlib.compress(raw, 9)))
        fh.write(chunk(b"IEND", b""))


def _render(matrix, scale: int, quiet: int, pad_left=0, pad_top=0,
            soften=False) -> list[list[int]]:
    n = len(matrix)
    dim = (n + quiet * 2) * scale
    img = [[255] * (dim + pad_left) for _ in range(dim + pad_top)]
    for r in range(n):
        for c in range(n):
            if not matrix[r][c]:
                continue
            for dy in range(scale):
                for dx in range(scale):
                    y = pad_top + (r + quiet) * scale + dy
                    x = pad_left + (c + quiet) * scale + dx
                    img[y][x] = 0
    if soften:
        # Crude antialiasing: grey every pixel on a dark/light boundary, which
        # is what a real rasteriser produces at fractional scales. The sampler
        # must survive it by reading module centres.
        src = [row[:] for row in img]
        for y in range(1, len(img) - 1):
            for x in range(1, len(img[0]) - 1):
                if src[y][x] == 0 and 255 in (src[y - 1][x], src[y + 1][x],
                                              src[y][x - 1], src[y][x + 1]):
                    img[y][x] = 96
    return img


def selftest() -> int:
    import tempfile
    from aibank import totp as T

    tmp = os.path.join(os.path.expanduser("~"), "tmp")
    os.makedirs(tmp, exist_ok=True)
    secret = T.new_secret()
    uri = T.provisioning_uri(secret, "demo@aibank.local")
    matrix = myqr.encode(uri)
    failures = 0
    cases = [
        ("scale 1, quiet 4", dict(scale=1, quiet=4)),
        ("scale 3, quiet 4", dict(scale=3, quiet=4)),
        ("scale 8, quiet 4", dict(scale=8, quiet=4)),
        ("scale 4, quiet 1 (tight crop)", dict(scale=4, quiet=1)),
        ("offset inside a larger page", dict(scale=5, quiet=4,
                                             pad_left=37, pad_top=11)),
        ("antialiased edges", dict(scale=6, quiet=4, soften=True)),
    ]
    for label, kw in cases:
        path = os.path.join(tmp, "qr_selftest.png")
        _write_png(path, _render(matrix, **kw))
        try:
            got = decode_png(path).decode()
            ok = got == uri
        except Exception as exc:                        # noqa: BLE001
            got, ok = f"{type(exc).__name__}: {exc}", False
        print(f"  {'ok  ' if ok else 'FAIL'} {label}")
        if not ok:
            failures += 1
            print(f"       got {got[:90]!r}")
        os.remove(path)

    # A blank page must be reported as a failure to render, NOT decoded as
    # something. Session-0 headless Chrome writes exactly this file.
    path = os.path.join(tmp, "qr_blank.png")
    _write_png(path, [[255] * 64 for _ in range(64)])
    try:
        decode_png(path)
        print("  FAIL a blank screenshot must raise")
        failures += 1
    except ValueError as exc:
        print(f"  ok   a blank screenshot raises ({exc})")
    os.remove(path)

    # And a corrupted symbol must fail the RS check rather than return junk.
    broken = [row[:] for row in matrix]
    for c in range(20, 30):
        broken[20][c] = not broken[20][c]
    path = os.path.join(tmp, "qr_broken.png")
    _write_png(path, _render(broken, scale=4, quiet=4))
    try:
        out = decode_png(path)
        print(f"  FAIL a corrupted symbol decoded anyway: {out[:40]!r}")
        failures += 1
    except Exception as exc:                            # noqa: BLE001
        print(f"  ok   a corrupted symbol is refused ({type(exc).__name__})")
    os.remove(path)

    print(f"\n{len(cases) + 2 - failures} passed, {failures} failed")
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    if not argv:
        print(__doc__)
        return 2
    path = argv[0]
    payload = decode_png(path).decode()
    print(f"decoded: {payload}")
    if "--expect-secret" in argv:
        want = argv[argv.index("--expect-secret") + 1]
        if f"secret={want}" not in payload:
            print(f"MISMATCH: symbol does not carry secret {want}")
            return 1
        print("secret matches: a scanner would bind the right account")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
