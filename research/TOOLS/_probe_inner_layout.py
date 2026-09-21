"""Probe: pin down the inner-archive entry layout by exhaustive layout search.

The judgement criterion is objective, not eyeballed: the header says `count`
files, and a correct layout must (a) parse exactly `count` entries and (b)
consume every byte of the inflated body.  Any variant that fails either is
rejected, so the surviving layout is the format.

Entries 1 / 11 / 27 share one layout (pad 4, align 16, tail 1) -- that is the
one STAGEDAT's lang_* tables use.  Entry 15 (1.1 MB inflated, 2593 sentence-
looking runs, "MISSION COMPLETE", "Snake and Miller") does NOT parse under it,
so it is a second variant; this probe is what settles it.

Variants searched:
    name pad      4 / 8 / 16        (after the NUL terminator)
    extra u32s    0 / 1 / 2 / 3     after the size field
    data align    4 / 8 / 16 / 32   (start of data)
    tail          skip 0 / 1 / all NUL bytes after data
"""
import itertools
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import _probe_pkg_peek as P
import pwsf_archive as A

CONTAINERS = {
    "stage": P.GAME / "MLG" / "disc0_rel" / "009645fa.PDT",
}


def try_layout(body: bytes, pad: int, extra: int, align: int, tail: str):
    count, = struct.unpack_from("<I", body, 0)
    if not 0 < count <= 4096:
        return None, "count"
    o, files = 4, []
    for _ in range(count):
        end = body.find(b"\x00", o)
        if end < 0 or end - o > 256:
            return None, f"name at {o:#x}"
        name = body[o:end]
        p = end + 1
        p += (-p) % pad
        need = 4 * (1 + extra)
        if p + need > len(body):
            return None, "size cut"
        size = struct.unpack_from("<I", body, p)[0]
        p += need
        p += (-p) % align
        data = body[p:p + size]
        if size == 0 or len(data) < size:
            return None, f"data cut at {p:#x}"
        files.append((name.decode("latin-1"), size, p, data))
        o = p + size
        if tail == "1":
            o += 1
        elif tail == "nul":
            while o < len(body) and body[o] == 0:
                o += 1
    return files, ("ok" if o == len(body) else f"leftover {len(body) - o}")


def main() -> None:
    entry_ids = [int(x) for x in sys.argv[1:]] or [1, 15, 7, 31]
    for key, path in CONTAINERS.items():
        arc = A.parse(path.open("rb").read(8 << 20), path.stem, str(path),
                      max_entries=200000)
        with path.open("rb") as h:
            for idx in entry_ids:
                e = arc.entries[idx]
                h.seek(e.c)
                body, note = P.inflate(P.unmask(arc, h.read(e.a)))
                if body is None:
                    print(f"entry {idx}: {note}, skipped")
                    continue
                count, = struct.unpack_from("<I", body, 0)
                print(f"entry {idx}: {note}, {len(body)} B, count={count}")
                for pad, extra, align, tail in itertools.product(
                        (4, 8, 16), (0, 1, 2, 3), (4, 8, 16, 32),
                        ("0", "1", "nul")):
                    files, err = try_layout(body, pad, extra, align, tail)
                    if err == "ok":
                        print(f"  MATCH pad={pad} extra={extra} align={align} "
                              f"tail={tail}: {len(files)} files")
                        for nm, sz, off, d in files[:6]:
                            print(f"    {sz:8d} @{off:#07x} {d[:4]!r:10} {nm}")
                        break
                else:
                    print("  no layout matched")


if __name__ == "__main__":
    main()
