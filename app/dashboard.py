#!/usr/bin/env python3
"""Open the polinrider-survival-kit dashboard.  Run with --help for options.  Python 3.8+, no dependencies."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
