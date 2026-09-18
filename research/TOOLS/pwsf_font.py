"""Compatibility shim: this module moved to the `pwsf` package.

Kept so the `_probe_*` / `_poc_*` evidence scripts in this folder keep
running unchanged. New code should `from pwsf.font import ...` instead.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf.font import *          # noqa: F401,F403
from pwsf import font as _module

sys.modules[__name__].__dict__.update(
    {k: v for k, v in vars(_module).items() if not k.startswith("__")})
