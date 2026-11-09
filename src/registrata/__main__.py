"""Allow ``python -m registrata`` alongside the installed console script.

Useful when the package is unpacked rather than installed -- an editable checkout, a container,
or a machine where you are pointing at one tree in particular -- and the only way to reach the
CLI without first installing an entry point.
"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
