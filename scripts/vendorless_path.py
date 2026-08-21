#!/usr/bin/env python3
"""Print a PATH identical to the caller's, minus two vendor CLIs.

The workflows this replaced asserted that neither `infisical` nor `pass-cli` was
installed on the runner, and called that proof the suites stand up their own
stubs rather than leaning on a real binary. A runner gets that for free. A
developer Mac does not -- both are installed here, which is the whole point of
the machine -- so on this machine the property has to be MANUFACTURED rather
than observed.

So: build a directory of symlinks to every executable the caller can already
reach, leave those two out, and hand back a PATH containing only it. The suite
then runs with everything it needs and no way to reach either vendor binary. A
green run under this PATH proves what the runner's bare filesystem proved, and
proves it on the machine where both binaries actually exist.

The first name wins, exactly as PATH resolution does, so shadowing order is
preserved rather than shuffled.
"""

import os
import pathlib
import sys

EXCLUDED = {"infisical", "pass-cli"}


def main() -> int:
    out = pathlib.Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)

    linked: set[str] = set()
    dropped: set[str] = set()

    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry:
            continue
        directory = pathlib.Path(entry)
        try:
            names = sorted(directory.iterdir())
        except OSError:
            continue
        for item in names:
            name = item.name
            if name in linked or name in dropped:
                continue
            if not os.access(item, os.X_OK) or item.is_dir():
                continue
            if name in EXCLUDED:
                # Recorded, so it is never linked later from a further
                # directory: PATH resolution stops at the first hit, and so
                # does this.
                dropped.add(name)
                continue
            try:
                (out / name).symlink_to(item)
            except OSError:
                continue
            linked.add(name)

    if not dropped:
        print(
            "neither infisical nor pass-cli was on PATH, so this scrub changed "
            "nothing. That is the runner's situation, not this machine's -- if "
            "you expected them installed, something moved.",
            file=sys.stderr,
        )
    if len(linked) < 100:
        print(
            f"only {len(linked)} executables were linked. A PATH this small "
            f"cannot run the suite, and a suite that cannot start looks exactly "
            f"like one that passed.",
            file=sys.stderr,
        )
        return 1

    print(f"linked={len(linked)} dropped={','.join(sorted(dropped)) or 'none'}", file=sys.stderr)
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
