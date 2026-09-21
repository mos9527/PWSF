"""End-to-end PoC: one GTT line translated, rebuilt into SLOT.DAT, read back.

The unit-level proof is `_probe_gtt7.py` (all 462 pools round-trip byte for
byte).  This is the integration proof: hand a GTT translation to
`pwsf.slotdat_build.rebuild`, then read the rebuilt 544 MB container back and
check that

  * the translated line reads back as the translation,
  * every other GTT line still reads back as its English,
  * the pool lengths and the record layout survived (slotdat_build.verify).

It writes into research/BUILD/_gtt_probe and deletes it again, because a
rebuild of SLOT.DAT is 544 MB.

Usage:  python _poc_gtt_writeback.py [--keep]
"""
import argparse
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pwsf import config, gtt, slotdat as S, slotdat_build   # noqa: E402

REF = (0x1C79F20B, 0x440, 0)          # "There's no one around - why not try"
TEXT = "周围没人——要不要\n练练射击？"

OUT = config.BUILD_DIR / "_gtt_probe"


def lint_smoke() -> None:
    """Feed po_lint one translation that fits and one that does not.

    The budget rule is the whole contract of the in-place write-back, so it is
    worth watching it fire: a line that cannot be written must be an ERROR
    before the build, not a silent skip inside it.
    """
    import tempfile

    from pwsf import po_lint, slots

    def po_str(prefix: str, s: str) -> str:
        """A .po string, split at line breaks the way gettext writes them."""
        parts = s.split("\n")
        if len(parts) == 1:
            return f'{prefix} "{parts[0]}"'
        out = [f'{prefix} ""']
        for i, p in enumerate(parts):
            out.append(f'"{p}\\n"' if i < len(parts) - 1 else f'"{p}"')
        return "\n".join(out)

    src = slots.gtt_sources()
    key = f"gtt/{REF[0]:#010x}/{REF[1]:#x}/{REF[2]}"
    long_text = "周围一个人都没有，所以为什么不顺便做一些射击方面的练习呢？"
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "a.po").write_text(
            f"#: {key}\n{po_str('msgid', src[key])}\n"
            f"{po_str('msgstr', TEXT)}\n", encoding="utf-8")
        (d / "b.po").write_text(
            f"#: gtt/0x1c0fb1c9/0x1040/0\n{po_str('msgid', 'Good job.')}\n"
            f"{po_str('msgstr', long_text)}\n", encoding="utf-8")
        rep = po_lint.lint(d, check_font=False)
        for p in rep.problems:
            print(f"  {p.severity} {p.code}: {p.message}")
        fired = [p for p in rep.problems if p.code == "gtt-budget"]
        print(f"  gtt-budget: {len(fired)} error(s)")
        for p in fired:
            print(f"    {p.message.split(':')[0]}")
        over = "gtt/0x1c0fb1c9/0x1040/0"
        print(f"  over-budget line rejected: "
              f"{any(over in p.message for p in fired)}")
        print(f"  fitting line ({key}) accepted: "
              f"{not any(key in p.message for p in fired)}")


def check_built(pool: int, block: int, line: int) -> None:
    """Read one GTT line out of the built SLOT.DAT, from every copy of its pool.

    Used when the build says a line was not found: it shows whether the record
    that holds the pool fell back (English) or the write genuinely failed.
    """
    dat = config.BUILD_DIR / f"{S.STEM}.DAT"
    key = config.BUILD_DIR / f"{S.STEM}.KEY"
    recs = S.load_index(key)
    state, inc = S.lcg_params(key)
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)
    print(f"{dat} ({dat.stat().st_size} bytes)")
    for rec_i, eid, blob in gtt.pool_blobs(ks, dat):
        if eid != pool:
            continue
        for b in gtt.parse(blob):
            if b.off != block:
                continue
            print(f"  record {rec_i}: {b.line(line).decode('utf-8')!r}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true",
                    help="do not delete the rebuilt container")
    ap.add_argument("--all-lines", action="store_true",
                    help="translate every line whose budget allows (slow)")
    ap.add_argument("--lint", action="store_true",
                    help="only run the po_lint budget smoke test")
    ap.add_argument("--check", nargs=3, metavar=("POOL", "BLOCK", "LINE"),
                    help="read one line back out of the BUILT container")
    args = ap.parse_args()
    if args.lint:
        lint_smoke()
        return
    if args.check:
        check_built(int(args.check[0], 0), int(args.check[1], 0),
                    int(args.check[2]))
        return

    budgets = {r: b for r, b in
               ((k, v) for k, v in __import__("pwsf").slots.gtt_budgets().items())}
    key = f"gtt/{REF[0]:#010x}/{REF[1]:#x}/{REF[2]}"
    print(f"target {key}  budget {budgets.get(key)} B")
    print(f"  stored translation: {gtt.to_game_text(TEXT)!r} "
          f"({len(gtt.to_game_text(TEXT))} B)")

    gtt_items = {REF: TEXT}
    if args.all_lines:
        for r, b in budgets.items():
            p = __import__("pwsf").slots.parse_ref(r)
            raw = gtt.to_game_text(TEXT)
            if len(raw) <= b:
                gtt_items[(p.pool, p.block, p.line)] = TEXT
        print(f"  {len(gtt_items)} line(s) fit the budget")

    t0 = time.time()
    OUT.mkdir(parents=True, exist_ok=True)
    dat, key_path, stats = slotdat_build.rebuild({}, None, OUT, gtt=gtt_items)
    print(f"\nrebuild: {stats}  ({time.time() - t0:.0f}s)")

    problems = slotdat_build.verify(dat, key_path, {}, None, gtt=gtt_items)
    print("verify problems:", problems or "none")

    # independent read-back: walk the rebuilt file ourselves
    recs = S.load_index(key_path)
    state, inc = S.lcg_params(key_path)
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)
    checked = other = 0
    for rec_i, eid, blob in gtt.pool_blobs(ks, dat):
        for b in gtt.parse(blob):
            for li in range(len(b.starts)):
                txt = b.line(li)
                if not txt:
                    continue
                other += 1
                if eid == REF[0] and b.off == REF[1] and li == REF[2]:
                    checked += 1
                    print(f"  patched line: {txt.decode('utf-8')!r}")
                    if txt != gtt.to_game_text(TEXT):
                        problems.append(f"read back {txt!r}")
    print(f"  {other} GTT lines still readable, target seen {checked}x")

    if not args.keep:
        shutil.rmtree(OUT, ignore_errors=True)
        print(f"  removed {OUT}")
    print("\nPROBLEMS:" if problems else "\nOK: GTT write-back round-trips "
          "through a full SLOT.DAT rebuild")
    for p in problems[:10]:
        print("  " + p)


if __name__ == "__main__":
    main()
