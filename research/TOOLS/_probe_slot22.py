"""Parse the RBX (olang) tables embedded in SLOT.DAT.

_probe_slot21.py: record 1874's six pools are all `RBX\0` containers with
identical headers -- one olang table in six languages.  So the comic cutscene
text is not a bespoke format at all, it is plain .olang carried inside
SLOT.DAT, which is why nothing in `MLG/Text` ever matched.

This probe walks every pool of every record, classifies it by magic, parses
the RBX ones with `pwsf.olang` (which also yields the language key), and looks
for the screenshot line.
"""

import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import slotdat as S
from pwsf import olang
from pwsf import config as C

RBX = b"RBX\x00"
GTT = b"GTT\x00"
NEEDLE = b"willing to give us an offshore plant"


def pools_of(data, area, entries):
    """[(entry_id, offset, blob)] for the live entries, in offset order."""
    live = sorted((e for e in entries if e[0] and (e[0] >> 24) != 0x7F),
                  key=lambda e: e[2] & 0x3FFFFFFF)
    bounds = [e[2] & 0x3FFFFFFF for e in live]
    ends = bounds[1:] + [len(data) - area]
    out = []
    for e, off, stop in zip(live, bounds, ends):
        out.append((e[0], off, data[area + off:area + min(stop, len(data) - area)]))
    return out


def main() -> None:
    recs = S.load_index()
    state, inc = S.lcg_params()
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)

    magic_hist = Counter()
    rbx_tables = 0
    lang_hist = Counter()
    rows = 0
    tables = {}          # (table_id, lang) -> Counter of (group, entry, key) -> text
    hits = []
    bad = []

    for rec in recs:
        data = S.inflate(S.decrypt(S.read_block(rec), ks))
        count, entries, area = S.res_table(data)
        for eid, off, blob in pools_of(data, area, entries):
            if len(blob) < 0x20:
                continue
            magic_hist[blob[:4]] += 1
            if blob[:4] != RBX:
                continue
            try:
                tbl = olang.parse(blob, f"slot/{rec.index}/{eid:#010x}")
            except Exception as exc:                      # noqa: BLE001
                bad.append((rec.index, eid, str(exc)))
                continue
            rbx_tables += 1
            for g in tbl.groups:
                for ei in range(g.entry_start, g.entry_start + g.entry_count):
                    if ei >= len(tbl.entries):
                        continue
                    e = tbl.entries[ei]
                    for ki in range(e.key_start, e.key_start + e.key_count):
                        if ki >= len(tbl.keys):
                            continue
                        lang, so, meta, _pad = tbl.keys[ki]
                        text = olang.string_at(tbl, so)
                        if not text:
                            continue
                        rows += 1
                        lang_hist[lang] += 1
                        key = (tbl.table_id, lang)
                        tables.setdefault(key, {})[(g.key, e.key, lang)] = text
                        if NEEDLE.lower() in text.lower():
                            hits.append((rec.index, eid, tbl.table_id,
                                         g.key, e.key, lang, text))

    print("pool magics:")
    for m, n in magic_hist.most_common(10):
        print(f"  {m!r:<10} {n}")
    print(f"\nRBX tables parsed: {rbx_tables}   (unparsable: {len(bad)})")
    for b in bad[:5]:
        print(f"    {b}")
    print(f"rows (group/entry/lang): {rows}")
    print(f"\nlanguage keys: ")
    for k, n in lang_hist.most_common(12):
        print(f"  {k:#06x} {C.LANG_KEYS.get(k, '?'):<3} {n}")
    print(f"\ndistinct (table_id, lang): {len(tables)}")

    print(f"\n{len(hits)} hit(s) for the screenshot line:")
    for rec, eid, tid, gk, ek, lang, text in hits[:12]:
        print(f"  rec {rec} pool {eid:#010x} table {tid:#010x} "
              f"group {gk:#08x} entry {ek:#08x} lang {lang:#06x}")
        print(f"      {text!r}")


if __name__ == "__main__":
    main()
