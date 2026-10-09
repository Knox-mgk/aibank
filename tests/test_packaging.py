"""The distribution is a product surface, so it gets tests like any other.

`pip install aibank` is how the agent-builder audience is meant to get this,
and packaging fails in ways no source-tree test can see: the dashboard is read
off disk at request time, so a wheel that omits `static/dashboard.html` serves
a 404 on `GET /` while every test in the repo still passes. Likewise the
console scripts are declared in `pyproject.toml` and never exercised by a
source-tree run, so a typo'd entry point ships broken.

These tests read `pyproject.toml` and the real filesystem. They deliberately
do NOT build a wheel: `python -m build` needs network and a few hundred MB of
build environment, which does not belong in a unit suite. Building and
installing is the job of `scripts/smoke_package.py`.

Run: python -m unittest discover -s tests
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("AIBANK_SCRYPT_N", "1024")
os.environ.setdefault("AIBANK_ALLOW_DEV_SECRETS", "1")

import aibank
from aibank import api as A

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"


def load_pyproject() -> dict:
    """tomllib is stdlib from 3.11, which is also this project's floor.

    No skip branch: a host that cannot import tomllib cannot run aibank
    either, so skipping would hide a real incompatibility behind a green dot.
    """
    import tomllib
    with open(PYPROJECT, "rb") as fh:
        return tomllib.load(fh)


class TestPackageMetadata(unittest.TestCase):
    def setUp(self):
        self.cfg = load_pyproject()
        self.project = self.cfg["project"]

    def test_version_matches_the_package(self):
        """Two sources of truth for a version is how you ship 0.1.0 as 0.2.0.

        PyPI refuses to overwrite a released version, so a mismatch here is
        not a cosmetic bug: it publishes an artifact whose own `__version__`
        disagrees with the filename users downloaded.
        """
        self.assertEqual(self.project["version"], aibank.__version__)

    def test_declares_no_runtime_dependencies(self):
        """'Zero dependencies' is the README's headline claim and a security
        argument. If a dependency ever gets added, this failing is the point.
        """
        self.assertEqual(self.project.get("dependencies", []), [])

    def test_console_scripts_resolve_to_real_callables(self):
        """A typo'd entry point is only discovered after installing."""
        import importlib

        scripts = self.project["scripts"]
        self.assertIn("aibank", scripts)
        self.assertIn("aibank-mcp", scripts)
        for name, target in scripts.items():
            module, _, attr = target.partition(":")
            mod = importlib.import_module(module)
            self.assertTrue(callable(getattr(mod, attr, None)),
                            f"{name} -> {target} is not callable")

    def test_requires_python_floor_matches_the_documented_install_path(self):
        """Claiming a lower floor than the installer accepts breaks installs.

        A wheel is `py3-none-any`, so pip on an older interpreter installs it
        happily and the failure surfaces at runtime on the user's host.
        `deploy/quickstart.sh` refuses anything below 3.11, so that is the
        supported floor regardless of what the syntax would tolerate.
        """
        self.assertEqual(self.project["requires-python"], ">=3.11")

        quickstart = (ROOT / "deploy" / "quickstart.sh").read_text(encoding="utf-8")
        self.assertIn("(3, 11)", quickstart,
                      "quickstart's version gate moved; update requires-python")

    def test_version_classifiers_do_not_contradict_the_floor(self):
        """Trove classifiers are what PyPI's sidebar shows, so a stale 3.9
        there advertises support the metadata refuses to install.
        """
        declared = sorted(
            c.rsplit(" :: ", 1)[1]
            for c in self.project["classifiers"]
            if c.startswith("Programming Language :: Python :: 3.")
        )
        floor = tuple(int(p) for p in
                      self.project["requires-python"].lstrip(">=").split("."))
        for v in declared:
            parts = tuple(int(p) for p in v.split("."))
            self.assertGreaterEqual(
                parts, floor,
                f"classifier claims {v} but requires-python is "
                f"{self.project['requires-python']}")

    def test_only_the_library_package_is_shipped(self):
        """tests/, scripts/ and deploy/ must not become importable modules.

        setuptools auto-discovery would otherwise put `tests` on the user's
        import path, where it shadows their own `tests` package.
        """
        self.assertEqual(self.cfg["tool"]["setuptools"]["packages"], ["aibank"])


class TestPackagedDataIsReachable(unittest.TestCase):
    """The dashboard is the half of this product a human uses."""

    def test_dashboard_ships_as_package_data(self):
        patterns = (self.pkg_data())
        self.assertTrue(any(p.startswith("static/") for p in patterns),
                        f"dashboard not in package-data: {patterns}")

    def pkg_data(self):
        cfg = load_pyproject()
        return cfg["tool"]["setuptools"]["package-data"]["aibank"]

    def test_static_dir_is_inside_the_package(self):
        """`api.STATIC_DIR` is derived from `__file__`, so it only resolves in
        an installed copy if the file sits under `aibank/`. A path like
        `ROOT/static` would work in the repo and 404 after `pip install`.
        """
        pkg_root = Path(aibank.__file__).resolve().parent
        self.assertEqual(A.STATIC_DIR.parent, pkg_root)
        self.assertTrue((A.STATIC_DIR / "dashboard.html").is_file())

    def test_every_file_api_serves_is_declared(self):
        """Whatever `_send_static` can be asked for must be in the wheel.

        Enumerates the directory rather than a hard-coded list, so adding a
        second page without adding a pattern fails here instead of in
        production.
        """
        import fnmatch

        patterns = self.pkg_data()
        for path in sorted(A.STATIC_DIR.iterdir()):
            if path.name.startswith("__"):
                continue
            rel = f"static/{path.name}"
            self.assertTrue(any(fnmatch.fnmatch(rel, p) for p in patterns),
                            f"{rel} is served but not packaged")


class TestSdistCarriesItsOwnGate(unittest.TestCase):
    """A reviewer who downloads the sdist must be able to run the suite.

    setuptools' default sdist heuristic picks up `tests/test_*.py` but not
    `tests/__init__.py` or `tests/fake_flw.py` -- shipping a suite that cannot
    import itself, which is worse than shipping none. MANIFEST.in fixes that
    and this pins it.
    """

    def test_manifest_includes_the_test_support_modules(self):
        manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
        self.assertIn("recursive-include tests *.py", manifest)
        self.assertIn("recursive-include scripts", manifest)

    def test_manifest_excludes_state_and_secrets(self):
        """An sdist built in a working directory would otherwise sweep up the
        operator's live ledger, their .env, and TLS private keys.
        """
        manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
        for pattern in ("*.db", "*.pem", "*.key"):
            self.assertIn(pattern, manifest)
        self.assertIn("exclude .env", manifest)
        self.assertIn("prune deploy/certs", manifest)

    def test_test_support_modules_exist_to_be_shipped(self):
        for name in ("__init__.py", "fake_flw.py"):
            self.assertTrue((ROOT / "tests" / name).is_file(), name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
