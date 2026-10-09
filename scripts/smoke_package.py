#!/usr/bin/env python3
"""Build the distribution, install it into a clean venv, and run it.

WHY this is a separate script and not a unit test: it needs the network (pip
fetching setuptools into a build environment), a few hundred MB of disk, and
upwards of a minute. `tests/test_packaging.py` asserts everything about the
distribution that can be checked from the source tree; this asserts the part
that can only be checked by actually installing it.

What a source-tree test structurally CANNOT catch, and this does:

  * `aibank/static/dashboard.html` is read off disk at request time, so a
    wheel missing it serves 404 on `GET /` while every repo test still passes.
  * The console scripts are declared in `pyproject.toml` and never executed by
    a source-tree run.
  * `sys.path` in the repo root makes `import aibank` succeed whether or not
    the package was installed correctly. This runs from a different directory
    so an accidental source import cannot mask a packaging gap.

Usage:

    python scripts/smoke_package.py            # build, install, exercise
    python scripts/smoke_package.py --keep     # leave the venv for poking

Exit 0 means `pip install aibank` would give a working service.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PASS = FAIL = 0


def check(label: str, got, want) -> None:
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  ok   {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label}: got {got!r}, want {want!r}")


def run(cmd, **kw):
    """Never check a build or test through a pipe; capture and return it."""
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(url: str, timeout: float = 20.0) -> int | None:
    """Poll rather than sleep blind: a fixed sleep is either flaky or slow."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code
        except (urllib.error.URLError, OSError):
            time.sleep(0.3)
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true",
                    help="keep the scratch venv instead of deleting it")
    args = ap.parse_args()

    work = Path(tempfile.mkdtemp(prefix="aibank_pkg_"))
    print(f"-- scratch: {work}")
    proc = None
    try:
        print("\n-- build --")
        r = run([sys.executable, "-m", "build", "--outdir", str(work / "dist")],
                cwd=ROOT)
        if r.returncode != 0:
            print(r.stdout[-3000:], r.stderr[-3000:])
            if "No module named build" in (r.stderr + r.stdout):
                print("\nSKIP: `pip install build` first (needs network).")
                return 0
            check("build succeeds", r.returncode, 0)
            return 1
        check("build succeeds", r.returncode, 0)

        wheels = sorted((work / "dist").glob("*.whl"))
        sdists = sorted((work / "dist").glob("*.tar.gz"))
        check("one wheel produced", len(wheels), 1)
        check("one sdist produced", len(sdists), 1)
        if not wheels:
            return 1
        wheel = wheels[0]

        print("\n-- wheel contents --")
        names = zipfile.ZipFile(wheel).namelist()
        check("dashboard is inside the wheel",
              "aibank/static/dashboard.html" in names, True)
        check("entry points declared",
              any(n.endswith("entry_points.txt") for n in names), True)
        check("license shipped",
              any("LICENSE" in n for n in names), True)
        check("tests are NOT in the wheel",
              any(n.startswith("tests/") for n in names), False)
        check("no database swept into the wheel",
              any(n.endswith(".db") for n in names), False)

        print("\n-- install into a clean venv --")
        venv = work / "venv"
        r = run([sys.executable, "-m", "venv", str(venv)])
        check("venv created", r.returncode, 0)
        vpy = venv / "bin" / "python"
        if not vpy.exists():                      # Windows layout
            vpy = venv / "Scripts" / "python.exe"
        r = run([str(vpy), "-m", "pip", "install", "--no-cache-dir", "-q",
                 str(wheel)])
        if r.returncode != 0:
            print(r.stdout[-2000:], r.stderr[-2000:])
        check("wheel installs", r.returncode, 0)

        bindir = vpy.parent
        cli = bindir / "aibank"
        mcp = bindir / "aibank-mcp"
        check("`aibank` console script exists", cli.exists(), True)
        check("`aibank-mcp` console script exists", mcp.exists(), True)

        print("\n-- no dependencies pulled in --")
        r = run([str(vpy), "-m", "pip", "list", "--format=json"])
        installed = {p["name"].lower() for p in json.loads(r.stdout)}
        # pip/setuptools/wheel are venv furniture, not our dependencies.
        extra = installed - {"aibank", "pip", "setuptools", "wheel"}
        check("installs nothing but itself", sorted(extra), [])

        print("\n-- the installed copy is the one being used --")
        # Run from the scratch dir, NOT the repo, so `import aibank` cannot
        # resolve to the source tree.
        r = run([str(vpy), "-c",
                 "import aibank, aibank.api as a;"
                 "print(aibank.__file__);"
                 "print((a.STATIC_DIR / 'dashboard.html').is_file())"],
                cwd=work)
        out = r.stdout.strip().splitlines()
        check("imports from site-packages",
              "site-packages" in (out[0] if out else ""), True)
        check("dashboard reachable via STATIC_DIR",
              out[-1] if out else "", "True")

        print("\n-- operator CLI against a fresh database --")
        env = dict(os.environ)
        env.update(
            AIBANK_DB=str(work / "pkg.db"),
            AIBANK_ADMIN_KEY="smoke-admin-not-a-real-secret",
            AIBANK_KEY_PEPPER="smoke-pepper-not-a-real-secret",
            AIBANK_SCRYPT_N="1024",
        )
        env.pop("AIBANK_ALLOW_DEV_SECRETS", None)   # prove it needs no escape hatch

        r = run([str(cli), "version"], env=env, cwd=work)
        check("`aibank version` runs", r.returncode, 0)
        check("reports v0 before migrating", "v0" in r.stdout, True)

        r = run([str(cli), "migrate"], env=env, cwd=work)
        check("`aibank migrate` succeeds", r.returncode, 0)

        r = run([str(cli), "create-user", "pkg@smoke.local",
                 "--password", "smoke-password-1234"], env=env, cwd=work)
        check("`aibank create-user` succeeds", r.returncode, 0)

        r = run([str(cli), "trial-balance"], env=env, cwd=work)
        check("books balance on a fresh ledger", "balanced" in r.stdout, True)

        r = run([str(cli), "needs-reconciliation"], env=env, cwd=work)
        check("empty reconciliation queue exits 0", r.returncode, 0)

        r = run([str(cli), "backup", "--dir", str(work / "backups")],
                env=env, cwd=work)
        check("`aibank backup` succeeds", r.returncode, 0)
        check("backup file written",
              len(list((work / "backups").glob("*.db"))) >= 1, True)

        print("\n-- MCP entry point refuses dangerous credentials --")
        r = run([str(mcp)], env={**env, "AIBANK_API_KEY": ""}, cwd=work,
                input="")
        check("refuses to start with no api key", r.returncode, 1)
        r = run([str(mcp)], env={**env, "AIBANK_API_KEY": "sess_abc"},
                cwd=work, input="")
        check("refuses a user session token", r.returncode, 1)
        check("names the reason", "SESSION token" in r.stderr + r.stdout, True)
        r = run([str(mcp), "--port", "9"],
                env={**env, "AIBANK_API_KEY": "sk_agent_x"}, cwd=work, input="")
        check("rejects stray argv", r.returncode, 1)

        print("\n-- serve from the installed package --")
        port = free_port()
        env["AIBANK_PORT"] = str(port)
        proc = subprocess.Popen(
            [str(cli), "serve", "--host", "127.0.0.1", "--port", str(port)],
            env=env, cwd=work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
        status = wait_for(f"http://127.0.0.1:{port}/health")
        check("/health answers 200", status, 200)

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as resp:
            page = resp.read().decode()
            check("GET / serves the dashboard", resp.status, 200)
        # The real failure mode of a missing package-data entry is a small
        # error page, not an exception -- so assert on the content.
        check("page is the real dashboard", "<title>aibank</title>" in page, True)
        check("page is not a stub", len(page) > 20000, True)

        print("\n-- schema guard survives packaging --")
        # `serve` must refuse an un-migrated database. This is the guarantee
        # the README makes, and it is enforced in code the wheel ships.
        env2 = dict(env, AIBANK_DB=str(work / "unmigrated.db"))
        r = run([str(cli), "serve", "--port", str(free_port())], env=env2,
                cwd=work, timeout=30)
        check("refuses to serve an un-migrated database", r.returncode != 0, True)
        check("names `migrate` as the fix",
              "migrate" in (r.stdout + r.stderr), True)

    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        if args.keep:
            print(f"\n-- kept: {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)

    print("\n" + "=" * 52)
    print(f"{PASS} passed, {FAIL} failed")
    print("=" * 52)
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
