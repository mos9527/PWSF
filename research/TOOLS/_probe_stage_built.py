"""Probe: decode EVERY entry of a built 009645fa.PDT, not just the rebuilt ones.

`stage_build.rebuild` rewrites the container's index+names tables (re-masked),
so a systemic bug there would break entries we did NOT touch.  This decodes all
557 entries of the built file and reports how many decrypt+inflate+parse cleanly,
and spot-checks that the translated strings are present.

Usage:  python _probe_stage_built.py [built.pdt]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pwsf import stage                                   # noqa: E402
from pwsf.archive import parse as arc_parse, verify as arc_verify
from pwsf import stage_build as SB                        # noqa: E402


def main() -> None:
    built = Path(sys.argv[1]) if len(sys.argv) > 1 else \
        (SB.source_path().parent.parent.parent.parent / "research" / "BUILD"
         / "009645fa.PDT")
    if not built.is_file():
        from pwsf import config
        built = config.BUILD_DIR / "009645fa.PDT"
    print(f"built: {built}  ({built.stat().st_size >> 20} MB)")

    size = built.stat().st_size
    with built.open("rb") as f:
        head = f.read(stage.HEAD_CAP)
    arc = arc_parse(head, built.stem, str(built), max_entries=200000)
    problems = arc_verify(arc, size)
    print("arc_verify:", problems or "ok")
    s0, inc = stage.seeding(arc)

    ok = miss = err = skip = 0
    with built.open("rb") as f:
        for i, e in enumerate(arc.entries):
            f.seek(e.c)
            try:
                plain = stage.payload(arc, f.read(e.a), s0, inc)
                body, _n = stage.inflate(plain)
                if body is None:
                    skip += 1
                    continue
                files, e2 = stage.inner_files(body)
                if e2:
                    err += 1
                    continue
                ok += 1
            except Exception as ex:                        # noqa: BLE001
                err += 1
                if err <= 4:
                    print(f"  entry {i}: {type(ex).__name__}: {ex}")
    print(f"entries: {len(arc.entries)}  decode-ok {ok}  "
          f"not-an-archive {skip}  error {err}")

    # spot-check a genuinely translated (Chinese) string reads back
    from pwsf import po, slots
    trans = {}
    for p, en in po.iter_entries(Path("src/stage")):
        if en.msgstr.strip() and en.msgstr != en.msgid and \
                any(ord(c) > 0x4E00 for c in en.msgstr):
            for r in en.refs:
                ref = slots.parse_ref(r)
                trans[(ref.rec, ref.file, ref.group, ref.entry)] = en.msgstr
    print(f"\ngenuinely translated stage slots available for spot-check: "
          f"{len(trans)}")
    rec = next(iter(trans))
    with built.open("rb") as f:
        e = arc.entries[rec[0]]
        f.seek(e.c)
        plain = stage.payload(arc, f.read(e.a), s0, inc)
        body, _n = stage.inflate(plain)
        files, _e2 = stage.inner_files(body)
    nm = rec[1]
    for name, _sz, data in files:
        if name == nm:
            from pwsf.olang import parse as olang_parse
            from pwsf.olang_build import OlangBuilder
            b = OlangBuilder(olang_parse(data, nm))
            got = b.get_text(rec[2], rec[3], 0x0D0E)
            print(f"spot-check {rec}:")
            print(f"  want: {trans[rec][:50]!r}")
            print(f"  got:  {got[:50]!r}")
            print(f"  match: {got == trans[rec]}")
            break


if __name__ == "__main__":
    main()
