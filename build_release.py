#!/usr/bin/env python3
"""
build_release.py — OTscope field-deployment package builder

Creates dist/OTscope_v<VERSION>.zip containing everything a field assessor
needs: the Python program, requirements, README, empty workspace folders,
and the User Guide.

Usage:
    python build_release.py           # builds the zip
    python build_release.py --dry-run # prints the file list without writing
"""

from __future__ import annotations

import argparse
import re
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
SRC_DIR   = REPO_ROOT / "otscope" / "src"
DOCS_DIR  = REPO_ROOT / "otscope" / "docs"
DIST_DIR  = REPO_ROOT / "dist"


def read_version() -> str:
    """Extract VERSION = "x.y.z" from otscope.py without importing it."""
    source = (SRC_DIR / "otscope.py").read_text(encoding="utf-8")
    match = re.search(r'^VERSION\s*=\s*["\']([^"\']+)["\']', source, re.MULTILINE)
    if not match:
        raise RuntimeError("Could not find VERSION constant in otscope.py")
    return match.group(1)


def build_manifest(pkg_name: str) -> list[tuple[Path, str]]:
    """Return [(source_path, archive_path)] pairs for the release package.

    source_path=None means a directory-only entry (empty folder in the zip).
    """
    manifest: list[tuple[Path | None, str]] = []

    def add(src: Path, arc_name: str) -> None:
        if not src.exists():
            print(f"[!] Skipping missing file: {src}")
            return
        manifest.append((src, f"{pkg_name}/{arc_name}"))

    # Core program files
    add(SRC_DIR / "otscope.py",   "otscope.py")
    add(SRC_DIR / "README.txt",   "README.txt")
    add(REPO_ROOT / "otscope" / "requirements.txt", "requirements.txt")

    # User Guide — prefer PDF, fall back to Markdown
    pdf  = DOCS_DIR / "OTscope_User_Guide.pdf"
    md   = DOCS_DIR / "OTscope_User_Guide.md"
    if pdf.exists():
        add(pdf, "OTscope_User_Guide.pdf")
    elif md.exists():
        add(md, "OTscope_User_Guide.md")
    else:
        print("[!] User Guide not found in docs/ — omitting from package.")

    # Empty workspace directories (represented by a hidden placeholder that
    # most zip tools strip, leaving just the directory entry)
    manifest.append((None, f"{pkg_name}/pcaps/"))
    manifest.append((None, f"{pkg_name}/output/"))

    return manifest


def build(dry_run: bool = False) -> Path:
    version  = read_version()
    pkg_name = f"OTscope_v{version}"
    zip_name = f"{pkg_name}.zip"

    manifest = build_manifest(pkg_name)

    print(f"OTscope release builder")
    print(f"  Version : {version}")
    print(f"  Package : {zip_name}")
    print(f"  Items   : {len(manifest)}")
    print()

    for src, arc in manifest:
        label = str(src.relative_to(REPO_ROOT)) if src else "(empty dir)"
        print(f"  {label:<55} -> {arc}")

    if dry_run:
        print("\n[dry-run] No file written.")
        return DIST_DIR / zip_name

    DIST_DIR.mkdir(exist_ok=True)
    zip_path = DIST_DIR / zip_name

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for src, arc in manifest:
            if src is None:
                # Add an explicit directory entry for the empty folder.
                zf.mkdir(arc.rstrip("/"))
            else:
                zf.write(src, arc)

    size_kb = zip_path.stat().st_size / 1024
    print(f"\n[OK] Written: {zip_path}  ({size_kb:.0f} KB)")
    return zip_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the file list without writing the zip.")
    args = parser.parse_args()
    try:
        build(dry_run=args.dry_run)
        return 0
    except Exception as exc:
        print(f"[!] Build failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
