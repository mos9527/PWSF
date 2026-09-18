"""Minimal gettext .po reader for the PWSF pipeline.

Only what the project emits and consumes: comments, references, flags, msgid,
msgstr, and the multi-line continuation form.  Plural forms and msgctxt are
parsed but unused -- the exporter identifies slots through `#:` references
instead, because one entry commonly covers several slots.
"""

from dataclasses import dataclass, field
from pathlib import Path

ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "0": "\0"}


@dataclass
class PoEntry:
    msgid: str = ""
    msgstr: str = ""
    msgctxt: str = None
    refs: list = field(default_factory=list)
    comments: list = field(default_factory=list)
    flags: list = field(default_factory=list)
    lineno: int = 0


def unescape(s: str) -> str:
    out, i = [], 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            out.append(ESCAPES.get(s[i + 1], s[i + 1]))
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def _literal(line: str, path, lineno: int) -> str:
    line = line.strip()
    if len(line) < 2 or not line.startswith('"') or not line.endswith('"'):
        raise ValueError(f"{path}:{lineno}: malformed .po string: {line!r}")
    return unescape(line[1:-1])


def parse_po(path) -> list:
    """Return the entries of a .po file; the header (empty msgid) is included."""
    path = Path(path)
    entries, cur, field_name = [], PoEntry(), None

    def flush():
        nonlocal cur, field_name
        if field_name is not None:
            entries.append(cur)
        cur, field_name = PoEntry(), None

    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.rstrip()
        if not line:
            continue
        if line.startswith("#"):
            if field_name is not None:
                flush()
            tag = line[1:2]
            body = line[2:].strip() if len(line) > 2 else ""
            if tag == ":":
                cur.refs += body.split()
            elif tag == ",":
                cur.flags += [f.strip() for f in body.split(",") if f.strip()]
            elif tag == ".":
                cur.comments.append(body)
            continue
        if line.startswith("msgctxt "):
            cur.msgctxt = _literal(line[8:], path, lineno)
            field_name = "msgctxt"
        elif line.startswith("msgid "):
            if field_name in ("msgstr",):
                flush()
            cur.lineno = lineno
            cur.msgid = _literal(line[6:], path, lineno)
            field_name = "msgid"
        elif line.startswith("msgstr "):
            cur.msgstr = _literal(line[7:], path, lineno)
            field_name = "msgstr"
        elif line.startswith('"'):
            if field_name is None:
                raise ValueError(f"{path}:{lineno}: continuation without a field")
            setattr(cur, field_name, getattr(cur, field_name)
                    + _literal(line, path, lineno))
        else:
            raise ValueError(f"{path}:{lineno}: unexpected line {line!r}")
    flush()
    return entries


def translated(path) -> dict:
    """reference -> translated string, for every entry that has an msgstr."""
    out = {}
    for e in parse_po(path):
        if not e.msgid or not e.msgstr:
            continue
        for r in e.refs:
            out[r] = e.msgstr
    return out
