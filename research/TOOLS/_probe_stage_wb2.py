"""Probe: are the STAGEDAT entries we want to rewrite really inner archives?

`stage.inner_files` returns err == "" as soon as `count` files parse, without
checking that the walk consumed the whole body -- so a payload that is not an
inner archive at all can still "parse" a handful of tiny files and stop early
(_probe_stage_wb.py --check: 92 entries repack byte-identically, 36 do not).

Write-back must never touch one of those, so this reports, per entry that
carries a translation:

    files   how many inner files the parser found
    tail    where the walk ends / the body length  (must be equal)
    repack  does _inner_pack(files) reproduce the body byte for byte?

Usage:  python _probe_stage_wb2.py
"""
import collections
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pwsf import po, slots, stage                   # noqa: E402
from pwsf import stage_build as SB                  # noqa: E402
from pwsf.archive import parse as arc_parse         # noqa: E402


def walk_end(body, files) -> int:
    o = 4
    for _nm, sz, _d in files:
        o = body.find(b"\x00", o) + 1
        o += (-o) % 4
        o += 4
        o += (-o) % 16
        o += sz + 1
    return o


def main() -> None:
    recs = collections.Counter()
    for p, e in po.iter_entries(Path("src/stage")):
        if not e.msgstr.strip():
            continue
        for r in e.refs:
            recs[slots.parse_ref(r).rec] += 1

    src = SB.source_path()
    with src.open("rb") as f:
        head = f.read(stage.HEAD_CAP)
    arc = arc_parse(head, src.stem, str(src), max_entries=200000)
    s0, inc = stage.seeding(arc)

    print(f"{'rec':>5} {'files':>6} {'tail/body':>20} {'repack':>8} "
          f"{'olang':>6} {'written':>8}")
    with src.open("rb") as f:
        for rec in sorted(recs):
            e = arc.entries[rec]
            f.seek(e.c)
            plain = stage.payload(arc, f.read(e.a), s0, inc)
            body, _n = stage.inflate(plain)
            if body is None:
                print(f"{rec:>5}  not zlib")
                continue
            files, err = stage.inner_files(body)
            end = walk_end(body, files)
            repack = SB._inner_pack([(nm, d) for nm, _s, d in files])
            olang = sum(1 for nm, _s, _d in files if nm.endswith(".olang"))
            print(f"{rec:>5} {len(files):>6} {hex(end) + '/' + hex(len(body)):>20}"
                  f" {'ok' if repack == body else 'DIFF':>8} {olang:>6} "
                  f"{recs[rec]:>8}"
                  + (f"   err={err}" if err else ""))


if __name__ == "__main__":
    main()
