"""End to end: translate a few cutscene lines and write SLOT.DAT back.

Takes the first N English strings of one cutscene table (0x003af54d -- the
offshore-plant line from ANALYSIS/08 §1), replaces them with Chinese, runs
`pwsf.slotdat_build.rebuild()` and then reads the whole rebuilt container
back with `verify()`: every one of the 2,137 records must still inflate to the
size its header claims, and the translated strings must come back verbatim.

usage: _poc_slotdat_writeback.py [--count N] [--table 0x...] [--outdir PATH]
"""

import argparse
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config as C
from pwsf import slotdat as S
from pwsf import slotdat_build as B

FAKE = ["他们愿意给我们一座海上平台",
        "一个我们终于能扎根的地方。",
        "这就是我们扩张无国界军队的机会。",
        "教授来自哥斯达黎加和平大学。",
        "你要明白，过去这一年里，",
        "别动！",
        "我们得赶紧走。",
        "你听见我说话了吗？"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=8)
    ap.add_argument("--table", default="0x003af54d")
    ap.add_argument("--outdir", default=str(C.BUILD_DIR / "slotdat"))
    ap.add_argument("--level", type=int, default=9)
    args = ap.parse_args()

    tid = int(args.table, 0)
    rows = C.SLOT_OLANG_TSV.read_text(encoding="utf-8").splitlines()
    col = {n: i for i, n in enumerate(rows[0].split("\t"))}
    picks = []
    for r in rows[1:]:
        c = r.split("\t")
        if len(c) <= col["text"]:
            continue
        if int(c[col["table_id"]], 0) != tid or c[col["lang"]] != "en":
            continue
        picks.append((int(c[col["group"]], 0), int(c[col["entry"]], 0),
                      c[col["text"]]))
        if len(picks) >= args.count:
            break
    if not picks:
        raise SystemExit(f"no English rows for table {tid:#010x}")

    print(f"table {tid:#010x}: {len(picks)} string(s)")
    translations = {}
    for i, (gk, ek, text) in enumerate(picks):
        zh = FAKE[i % len(FAKE)]
        translations[(tid, gk, ek)] = zh
        print(f"  {gk:#08x}/{ek:#08x}  {S.unescape(text)[:56]!r}")
        print(f"               -> {zh!r}")

    outdir = Path(args.outdir)
    if outdir.exists():
        shutil.rmtree(outdir)
    free = shutil.disk_usage(outdir.parent).free
    print(f"\nfree space: {free / 2**30:.1f} GiB (output ~0.5 GiB)")

    dat, key, stats = B.rebuild(translations, outdir=outdir,
                                level=args.level)
    print(f"\nrebuilt: {stats}")
    print(f"  {dat}  {dat.stat().st_size} bytes")
    print(f"  {key}  {key.stat().st_size} bytes")
    print(f"  original {S.dat_path().stat().st_size} bytes -> "
          f"{dat.stat().st_size - S.dat_path().stat().st_size:+d}")

    print("\nverifying (re-reads all 2,137 records)...")
    problems = B.verify(dat, key, translations)
    if problems:
        print(f"{len(problems)} problem(s):")
        for p in problems[:20]:
            print(f"  {p}")
    else:
        print("  OK: every record inflates to its declared size and all "
              f"{len(translations)} translation(s) read back verbatim")


if __name__ == "__main__":
    main()
