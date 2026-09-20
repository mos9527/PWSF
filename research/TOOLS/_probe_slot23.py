"""De-duplicate the embedded olang tables and check every copy agrees.

4,458 RBX pools but only 865 distinct (table_id, lang) pairs: the same table
is carried in several records (different regions / builds).  Before any of it
can be a translation source we must know whether the copies are identical --
if they are, one reference per (table_id, lang) is enough and write-back can
simply patch every copy.

Also: 54,720 rows carry language key 0x34bc87, which is not in
config.LANG_KEYS.  Find out what those are.
"""

import hashlib
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import slotdat as S
from pwsf import olang
from pwsf import config as C

RBX = b"RBX\x00"
UNKNOWN = 0x34BC87


def pools_of(data, area, entries):
    live = sorted((e for e in entries if e[0] and (e[0] >> 24) != 0x7F),
                  key=lambda e: e[2] & 0x3FFFFFFF)
    bounds = [e[2] & 0x3FFFFFFF for e in live]
    ends = bounds[1:] + [len(data) - area]
    for e, off, stop in zip(live, bounds, ends):
        yield e[0], off, data[area + off:area + min(stop, len(data) - area)]


def rows_of(tbl):
    """[(lang, group, entry, meta, text)] in table order."""
    out = []
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
                if text:
                    out.append((lang, g.key, e.key, meta, text))
    return out


def main() -> None:
    recs = S.load_index()
    state, inc = S.lcg_params()
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)

    copies = defaultdict(list)        # (table_id, lang) -> [(rec, pool, digest)]
    canon = {}                        # (table_id, lang) -> {row_key: text}
    unknown_sample = []
    sizes = Counter()

    for rec in recs:
        data = S.inflate(S.decrypt(S.read_block(rec), ks))
        count, entries, area = S.res_table(data)
        for eid, off, blob in pools_of(data, area, entries):
            if len(blob) < 0x20 or blob[:4] != RBX:
                continue
            tbl = olang.parse(blob, f"slot/{rec.index}/{eid:#010x}")
            rows = rows_of(tbl)
            by_lang = defaultdict(dict)
            for lang, gk, ek, meta, text in rows:
                by_lang[lang][(gk, ek, meta)] = text
            for lang, mapping in by_lang.items():
                key = (tbl.table_id, lang)
                h = hashlib.blake2b(
                    b"\x00".join(
                        f"{a:#x}:{b:#x}:{c:#x}:{d!r}".encode()
                        for (a, b, c), d in sorted(mapping.items())),
                    digest_size=8).digest()
                copies[key].append((rec.index, eid, h))
                canon.setdefault(key, mapping)
                sizes[key] = len(mapping)
                if lang == UNKNOWN and len(unknown_sample) < 12:
                    unknown_sample.append((rec.index, tbl.table_id, gk, ek,
                                           text[:80]))

    print(f"distinct (table_id, lang): {len(copies)}")
    print(f"total copies: {sum(len(v) for v in copies.values())}")

    mismatched = 0
    for key, lst in copies.items():
        if len({h for _r, _p, h in lst}) > 1:
            mismatched += 1
            if mismatched <= 5:
                print(f"  MISMATCH table {key[0]:#010x} lang {key[1]:#06x}: "
                      f"{[ (r, hex(p), h.hex()) for r, p, h in lst ]}")
    print(f"copies that disagree: {mismatched}")

    per_lang = Counter()
    rows_per_lang = Counter()
    for (tid, lang), mapping in canon.items():
        per_lang[lang] += 1
        rows_per_lang[lang] += len(mapping)
    print("\ndistinct tables / rows per language:")
    for lang, n in per_lang.most_common():
        name = C.LANG_KEYS.get(lang, "?")
        print(f"  {lang:#08x} {name:<3} tables={n:<5} rows={rows_per_lang[lang]}")

    print(f"\nunknown lang {UNKNOWN:#08x} samples:")
    for rec, tid, gk, ek, text in unknown_sample:
        print(f"  rec {rec} table {tid:#010x} {gk:#08x}/{ek:#08x}  {text!r}")

    print("\nlargest tables (by rows, any language):")
    for key, n in sizes.most_common(10):
        print(f"  table {key[0]:#010x} lang {key[1]:#06x}  {n} rows")

    en = sum(n for (tid, lang), n in sizes.items()
             if lang == C.LANG_EN)
    print(f"\nEnglish rows after de-duplication: {en}")


if __name__ == "__main__":
    main()
