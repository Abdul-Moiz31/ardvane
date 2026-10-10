"""The `ardvane` command (and `python -m ardvane`) for the installed package (pipx / pip).

The package carries the whole kit (app, scanner, scripts, guides) next to this file, so every feature works exactly
as it does from a clone of the repository.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    os.environ["ARDVANE_KIT"] = HERE              # where the kit's files are
    os.environ["ARDVANE_INSTALLED"] = "1"         # tells the app it runs as the installed `ardvane` command
    sys.path.insert(0, os.path.join(HERE, "app"))
    from backend.cli import main as cli_main      # noqa: E402 (needs the path above)
    return cli_main(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
