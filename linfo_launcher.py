#!/usr/bin/env python3
"""PyInstaller-compatible LinFo entrypoint."""
from linfo.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
