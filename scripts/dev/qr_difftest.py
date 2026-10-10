"""Differential check of aibank.qr against an independent implementation.

NOT part of the shipped test suite: it needs the third-party `qrcode` package,
which this project refuses to depend on. It is the tool that PROVED the
encoder, kept in the repo so the proof can be re-run.

WHAT IT COMPARES, and why it is not whole-symbol equality:

`aibank.qr` and `qrcode` 8.2 pick DIFFERENT MASKS for the same payload, and
both are right. The penalty rules are evaluated over the symbol, and the two
implementations disagree on whether the format-information modules are part of
it: `qrcode` blanks them while scoring (`setup_type_info(test=True)`), while
`aibank.qr` scores the finished symbol, which is what ZXing does -- i.e. what
the scanner on an Android phone does. A symbol differing only by mask is a
valid, scannable encoding of the same data, so demanding byte-identity would
mean copying someone else's reading of an ambiguity and calling it correctness.

So this compares MASK BY MASK: for each payload and each of the 8 masks, the
two matrices must be identical. That pins everything that has a single right
answer -- version selection, bit stream, pad codewords, Reed-Solomon, block
interleaving, function patterns, data placement, format bits -- and leaves only
the selection heuristic, which `tests/test_qr.py` covers from the other side by
DECODING the symbol actually emitted.

Usage: python scripts/dev/qr_difftest.py [/path/to/unpacked/qrcode/wheel]
"""
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, sys.argv[1] if len(sys.argv) > 1
                else os.path.expanduser("~/tmp/qrref"))

import qrcode                                      # noqa: E402
from qrcode.constants import ERROR_CORRECT_M       # noqa: E402
from qrcode.util import QRData, MODE_8BIT_BYTE     # noqa: E402
from aibank import qr as myqr                      # noqa: E402


def reference_masks(data: bytes, version: int) -> dict[int, list[list[bool]]]:
    """The reference's matrix for every mask, at a fixed version.

    Byte mode must be FORCED. `add_data` auto-selects numeric mode for a
    digit-only payload and alphanumeric for an uppercase-and-digits one, which
    produces a legitimately different, denser symbol -- so comparing against
    the default makes aibank.qr look broken on exactly the payloads where it is
    behaving as documented (byte mode only, deliberately).
    """
    out = {}
    for mask in range(8):
        q = qrcode.QRCode(version=version, error_correction=ERROR_CORRECT_M,
                          border=0, mask_pattern=mask)
        q.add_data(QRData(data, mode=MODE_8BIT_BYTE))
        q.make()
        out[mask] = [[bool(v) for v in row] for row in q.modules]
    return out


def mine_masks(data: bytes, version: int) -> dict[int, list[list[bool]]]:
    words = myqr._interleave(myqr._encode_codewords(data, version), version)
    out = {}
    for mask in range(8):
        canvas = myqr._Canvas(version)
        canvas.place_function_patterns()
        canvas.place_data(words)
        out[mask] = canvas.apply_mask_and_format(mask)
    return out


def main() -> int:
    random.seed(7)
    cases = [b"hello", b"a", b"0", b"\x00\xff\x80",
             b"otpauth://totp/aibank%3Ademo%40aibank.local?secret="
             b"EIRU6SKX57SELUTQD2JUXBTWVFZXYGA4&issuer=aibank&algorithm=SHA1"
             b"&digits=6&period=30"]
    alphabet = "ABCdef019:/?&=%@.-_"
    for n in range(1, 300):
        cases.append("".join(random.choice(alphabet) for _ in range(n)).encode())
    # Every exact capacity boundary, where an off-by-one in the RS tables shows.
    for v in range(1, myqr.MAX_VERSION + 1):
        for n in (myqr.capacity_bytes(v) - 1, myqr.capacity_bytes(v)):
            if n > 0:
                cases.append(b"x" * n)

    compared = mismatches = 0
    versions = set()
    for data in cases:
        version = myqr._smallest_version(len(data))
        versions.add(version)
        ref = reference_masks(data, version)
        mine = mine_masks(data, version)
        for mask in range(8):
            compared += 1
            if mine[mask] != ref[mask]:
                mismatches += 1
                if mismatches <= 5:
                    diff = [(r, c) for r in range(len(mine[mask]))
                            for c in range(len(mine[mask]))
                            if mine[mask][r][c] != ref[mask][r][c]]
                    print(f"MISMATCH len={len(data)} version={version} "
                          f"mask={mask}: {len(diff)} modules, {diff[:8]}")

    print(f"compared {compared} matrices over {len(cases)} payloads, "
          f"versions {min(versions)}-{max(versions)}: {mismatches} mismatches")

    # The selection heuristic itself: report the spread rather than asserting
    # agreement, since the two conventions legitimately differ.
    agree = total = 0
    for data in cases[:200]:
        version = myqr._smallest_version(len(data))
        mine = myqr.encode(data)
        ref = reference_masks(data, version)
        total += 1
        if any(mine == ref[m] for m in range(8)):
            agree += 1
    print(f"mask-selection: {agree}/{total} of our chosen symbols are one of "
          "the reference's 8 valid maskings (should be all of them)")
    return 1 if mismatches or agree != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
