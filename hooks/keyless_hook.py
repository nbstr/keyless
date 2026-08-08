#!/usr/bin/env python3
"""The one process the harness runs. Reads a hook payload on stdin, decides, exits 0.

Registered on both PreToolUse and PostToolUse with no matcher, because a matcher
scopes the WHOLE handler and every branch for a tool outside it becomes dead code
that never errors and never runs.

Deliberately tiny: everything it does is `keyless_hooks.engine`, and the only
work at module scope is one `sys.path` insert. Import cost is paid on every tool
call in every session, so nothing heavier belongs here.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from keyless_hooks.engine import cli  # noqa: E402

if __name__ == "__main__":
    cli()
