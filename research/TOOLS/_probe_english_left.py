"""Probe: what is still English in game?  (screenshot 2026-09-22)

The in-mission radio line came out Chinese, but the speaker label above it
still reads `Miller`.  That label is not the codec speaker id (that is an
internal number) -- it has to be looked up in a text table, so this asks:

  1. per corpus, how many entries are still untranslated, and in which tables
     the bulk sits;
  2. which table/entry holds the speaker names, and whether they are
     translated.

Usage:  python _probe_english_left.py [--names MILLER,KAZ,SNAKE]
"""
import argparse
import collections
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pwsf import po                     # noqa: E402

DUMP = Path("research/ANALYSIS/_dump_olang.tsv")


def coverage() -> None:
    per = collections.Counter()
    tot = collections.Counter()
    where = collections.defaultdict(collections.Counter)
    for p, e in po.iter_entries(Path("src")):
        k = p.parent.name
        tot[k] += 1
        if e.msgstr.strip():
            per[k] += 1
        else:
            for r in e.refs:
                where[k][r.split("/")[1] if "/" in r else r] += 1
    print("corpus      translated / total        biggest untranslated group")
    for k in sorted(tot):
        top = where[k].most_common(2)
        left = tot[k] - per[k]
        print(f"  {k:8} {per[k]:6}/{tot[k]:6} ({100 * per[k] / tot[k]:5.1f}%)"
              f"   {left:5} left   {top}")


def names(wanted: set) -> None:
    if not DUMP.is_file():
        print(f"{DUMP} missing")
        return
    rows = list(csv.reader(DUMP.open(encoding="utf-8"), delimiter="\t"))
    # the dump has no header row: file, table_id, group, entry, lang, meta, text
    while rows and not rows[0][0].lower().endswith(".olang"):
        rows = rows[1:]
    print(f"\n{DUMP.name}: {len(rows)} rows, first = {rows[0]}")
    hit = [r for r in rows
           if len(r) > 6 and r[6].strip().upper() in wanted]
    print(f"rows whose text is exactly one of {sorted(wanted)}: {len(hit)}")
    by_table = collections.Counter(r[1] for r in hit)
    for table, n in by_table.most_common(6):
        sub = [r for r in hit if r[1] == table]
        print(f"  table {table} ({n} rows): "
              f"{[(r[2], r[3], r[6]) for r in sub[:8]]}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--names", default="MILLER,KAZ,SNAKE,BOSS,HUEY,PAZ")
    args = ap.parse_args()
    coverage()
    names({x.strip().upper() for x in args.names.split(",") if x.strip()})


if __name__ == "__main__":
    main()
