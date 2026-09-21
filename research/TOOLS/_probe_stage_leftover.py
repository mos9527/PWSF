"""Probe: the STAGEDAT payloads whose inner archive parses but leaves bytes over.

`pwsf.stage.inner_files` demands that the layout account for EVERY byte, which
is what makes the layout trustworthy -- but that also means an archive with a
trailing section is rejected whole.  There are ~15 such payloads
(leftover 0.6 MB .. 36 MB).  This probe parses what it can, then shows what
sits past the last file: another file list, padding, or a different section.

Run:  python _probe_stage_leftover.py [max_entries]
"""
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import _probe_pkg_scan as S
import pwsf_archive as A

f = S.GAME / "MLG" / "disc0_rel" / "009645fa.PDT"


def parse_partial(body: bytes):
    """Parse as many files as the layout allows; return (files, end)."""
    count, = struct.unpack_from("<I", body, 0)
    if not 0 < count <= 4096:
        return [], 0
    files, o = [], 4
    for _ in range(count):
        end = body.find(b"\x00", o)
        if end < 0 or end - o > 256:
            break
        name = body[o:end]
        p = end + 1
        p += (-p) % 4
        if p + 4 > len(body):
            break
        size, = struct.unpack_from("<I", body, p)
        p += 4
        p += (-p) % 16
        data = body[p:p + size]
        if size == 0 or len(data) < size:
            break
        files.append((name.decode("latin-1"), size, data))
        o = p + size + 1
    return files, o


def main() -> None:
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 6
    arc = A.parse(f.open("rb").read(8 << 20), f.stem, str(f),
                  max_entries=200000)
    shown = 0
    with f.open("rb") as h:
        for i in range(arc.count):
            e = arc.entries[i]
            h.seek(e.c)
            body, note = S.inflate(S.unmask(arc, h.read(e.a)))
            if body is None:
                continue
            files, end = parse_partial(body)
            left = len(body) - end
            if not files or left < 4096:
                continue
            print(f"\nentry {i}: {len(files)} file(s) parsed, "
                  f"{left} B left over ({note})")
            for nm, sz, d in files[:4]:
                print(f"    {sz:9d} {d[:4]!r:10} {nm}")
            tail = body[end:end + 64]
            print(f"    tail head: {tail[:48]!r}")
            runs = [m.group().decode("latin-1")
                    for m in re.finditer(rb"[ -~]{8,}", body[end:])][:8]
            print(f"    tail ascii: {runs}")
            low = body[end:].lower()
            for nd in (b"shooting practice", b"no one around"):
                if nd in low:
                    print(f"    *** NEEDLE {nd} in the tail ***")
            shown += 1
            if shown >= limit:
                break


if __name__ == "__main__":
    main()
