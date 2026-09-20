"""Inventory of the olang tables embedded in SLOT.DAT.

`pwsf.slotdat.embedded_olang()` gives one row per (table, lang, group, entry)
with every duplicate copy already folded away (they were verified identical).
This probe prints a per table inventory -- table id, the record it first shows
up in, row count and a sample line -- which is how the cutscene tables were
first told apart from the UI ones.

The corpus files themselves are written by _probe_slot25.py (which also adds
the cutscene/other split), so this one writes nothing unless --out is given.
"""

import argparse
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config as C
from pwsf import slotdat as S

DEFAULT_OUT = ""      # nothing on by default; _probe_slot25.py owns the TSVs


def esc(text: bytes) -> str:
    return (text.decode("utf-8", "replace")
            .replace("\\", "\\\\")
            .replace("\t", "\\t")
            .replace("\r", "\\r")
            .replace("\n", "\\n"))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args()

    rows, first_seen, locations = S.embedded_olang()
    print(f"rows: {len(rows)}   distinct (table, lang): {len(locations)}")

    # inventory, keyed on the English copy
    en = defaultdict(list)
    for r in rows:
        if r.lang == C.LANG_EN:
            en[r.table_id].append(r)
    print(f"\ndistinct tables: {len(en)}")
    print(f"{'table':<12} {'rec':>5} {'rows':>5}  sample")
    for tid in sorted(en, key=lambda t: first_seen[(t, C.LANG_EN)]):
        lst = en[tid]
        rec = first_seen[(tid, C.LANG_EN)]
        sample = esc(next((r.text for r in lst if len(r.text) > 12),
                          lst[0].text))[:52]
        print(f"{tid:#010x} {rec:>5} {len(lst):>5}  {sample}")

    if not args.out:
        return
    out = Path(args.out)
    lines = ["table_id\tlang\tgroup\tentry\tmeta\trecord\tlocations\ttext"]
    for r in rows:
        key = (r.table_id, r.lang)
        locs = ";".join(f"{rec}:{eid:#010x}" for rec, eid in locations[key])
        lines.append("\t".join((
            f"{r.table_id:#010x}",
            C.LANG_KEYS.get(r.lang, f"{r.lang:#06x}"),
            f"{r.group:#08x}",
            f"{r.entry:#08x}",
            f"{r.meta:#06x}",
            str(first_seen[key]),
            locs,
            esc(r.text),
        )))
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nwrote {out}  ({len(lines) - 1} rows)")


if __name__ == "__main__":
    main()
