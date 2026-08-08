"""The checks. Each exports `run(payload, cfg) -> (verdict, message, detail) | None`.

`None` means no opinion, and it is the correct answer on every path where the
check could not determine what the action touches. An empty parse is "I don't
know", never "it is safe".
"""
