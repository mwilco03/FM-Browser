#!/usr/bin/env python3
"""Build a single-file .pyz zipapp for FM-Browser.

Usage:
    python scripts/build_zipapp.py          # produces fm-browser.pyz
    python fm-browser.pyz /path/to/evidence.7z --port 8888

The .pyz bundles the history_search package and Flask.  It requires
only a Python 3.9+ interpreter on the target machine — no pip install
needed.  For .7z support without system p7zip, install py7zr into the
bundle by passing --portable:

    python scripts/build_zipapp.py --portable
"""
import argparse
import shutil
import subprocess
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description="Build fm-browser.pyz")
    parser.add_argument(
        "--portable", action="store_true",
        help="Bundle py7zr and rarfile for fully portable archive support",
    )
    parser.add_argument(
        "-o", "--output", default="fm-browser.pyz",
        help="Output filename (default: fm-browser.pyz)",
    )
    parser.add_argument(
        "-r", "--requirements",
        help="Pinned requirements file (e.g. requirements-build.txt) for reproducible builds",
    )
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        staging = Path(tmp) / "app"
        staging.mkdir()

        # Copy package
        shutil.copytree(ROOT / "history_search", staging / "history_search")

        # Install dependencies into staging dir
        pip_cmd = [
            sys.executable, "-m", "pip", "install",
            "--target", str(staging),
            "--quiet",
        ]

        if args.requirements:
            # Use pinned requirements file for reproducible builds
            pip_cmd.extend(["-r", args.requirements])
        else:
            deps = ["flask"]
            if args.portable:
                deps.extend(["py7zr", "rarfile"])
            pip_cmd.extend(deps)

        subprocess.check_call(pip_cmd)

        # Write __main__.py entry point
        (staging / "__main__.py").write_text(
            "from history_search.server import main\nmain()\n"
        )

        # Build zipapp
        output = Path(args.output)
        zipapp.create_archive(
            staging,
            target=output,
            interpreter="/usr/bin/env python3",
            compressed=True,
        )
        size_mb = output.stat().st_size / (1024 * 1024)
        print(f"Built {output} ({size_mb:.1f} MB)")


if __name__ == "__main__":
    main()
