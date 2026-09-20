"""Plan B: repack the pools, re-compress, and rebuild the container.

_probe_slot28.py: writing a CJK translation into the existing pool slot only
fits 14 of 43 cutscene tables (worst case +1,462 B).  The pool slot is fixed
by the *next* entry's offset, so plan B is to lay the pools out again from
scratch and update every entry offset -- the inflated slot is ours to rebuild,
it is not a fixed image.

That makes the record bigger, which means:
    A (inflated sectors) grows          -> SLOT.KEY field, 12 bits
    B (stored sectors)   grows          -> moves every later record, so
                                           SLOT.KEY start/end need rewriting
                                           and the whole 544 MB is re-emitted

This probe measures that cost: per cutscene record, old (A, B) against the
(A, B) needed after a Japanese-into-English rewrite, at zlib level 9.

usage: _probe_slot29.py [--level 9]
"""

import argparse
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config as C
from pwsf import olang
from pwsf.olang_build import OlangBuilder
from pwsf import slotdat as S

JA = 0x0DB0


def rows_of(tbl):
    out = {}
    for g in tbl.groups:
        for ei in range(g.entry_start, g.entry_start + g.entry_count):
            if ei >= len(tbl.entries):
                continue
            e = tbl.entries[ei]
            for ki in range(e.key_start, e.key_start + e.key_count):
                if ki >= len(tbl.keys):
                    continue
                lang, so, meta, _pad = tbl.keys[ki]
                out.setdefault((g.key, e.key), {})[lang] = \
                    olang.string_at(tbl, so)
    return out


def repack(rec, ks, patch, level=9):
    """Return (compressed bytes, inflated size) for a rewritten record."""
    data = S.inflate(S.decrypt(S.read_block(rec), ks))
    count, entries, area = S.res_table(data)

    live = [e for e in entries if e[0] and (e[0] >> 24) != 0x7F]
    live.sort(key=lambda e: e[2] & 0x3FFFFFFF)
    bounds = [e[2] & 0x3FFFFFFF for e in live]
    ends = bounds[1:] + [len(data) - area]
    blobs = [data[area + o:area + min(s, len(data) - area)]
             for o, s in zip(bounds, ends)]

    # patch the ones we can parse as olang
    for i, blob in enumerate(blobs):
        if len(blob) < 0x20 or blob[:4] != b"RBX\x00":
            continue
        blobs[i] = patch(blob)

    # lay them out again, offsets in the original entry order
    body = bytearray()
    new_off = {}
    for e, blob in zip(live, blobs):
        new_off[id(e)] = len(body)
        body += blob
        while len(body) % 4:          # keep dword alignment for the XOR layers
            body.append(0)
    sentinel = len(body)

    table = bytearray(data[:area])
    for e in entries:
        pass
    # rewrite the offset field of every live entry, in table order
    idx = 0
    for pos, e in enumerate(entries):
        if not e[0] or (e[0] >> 24) == 0x7F:
            continue
        off_in_table = 8 + 16 * pos
        val = new_off[id(e)] if e in new_off else sentinel
        struct.pack_into("<I", table, off_in_table + 8, val)

    inflated = b"".join((bytes(table[:area]), bytes(body)))
    comp = zlib.compress(inflated, level)
    return comp, len(inflated), sentinel


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--level", type=int, default=9)
    args = ap.parse_args()

    recs = S.load_index()
    state, inc = S.lcg_params()
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)

    # every (table_id, lang) -> set of records holding it
    where = {}
    for rec in recs:
        for eid, off, blob in S.pools(rec, ks):
            if len(blob) < 0x20 or blob[:4] != b"RBX\x00":
                continue
            tbl = olang.parse(blob, f"slot/{rec.index}/{eid:#010x}")
            for lang in {k[0] for k in tbl.keys}:
                where.setdefault((tbl.table_id, lang), set()).add(rec.index)

    # build the ja -> en rewrite keyed by table id
    targets = sorted(t for t, l in where if S.is_cutscene(t)
                     and l == C.LANG_EN)
    ja_text = {}
    for tid in targets:
        if (tid, JA) not in where:
            continue
        rec = min(where[(tid, JA)])
        for eid, off, blob in S.pools(recs[rec], ks):
            if blob[:4] == b"RBX\x00":
                tbl = olang.parse(blob, "")
                if tbl.table_id == tid and JA in {k[0] for k in tbl.keys}:
                    ja_text[tid] = rows_of(tbl)
                    break

    def patch(blob):
        tbl = olang.parse(blob, "")
        if tbl.table_id not in ja_text:
            return blob
        rows = rows_of(tbl)
        b = OlangBuilder(tbl)
        for (gk, ek), bylang in rows.items():
            dst = ja_text[tbl.table_id].get((gk, ek), {}).get(JA)
            if dst and bylang.get(C.LANG_EN):
                b.set_text(gk, ek, C.LANG_EN,
                           dst.decode("utf-8", "replace"))
        return b.serialize()

    touched = set()
    for tid in targets:
        touched |= where.get((tid, C.LANG_EN), set())
    touched = sorted(touched)
    print(f"cutscene tables: {len(targets)}  records touched: {len(touched)}")

    da = db = 0
    grew_b = 0
    for idx in touched:
        rec = recs[idx]
        try:
            comp, inflated, _ = repack(rec, ks, patch, args.level)
        except Exception as exc:                        # noqa: BLE001
            print(f"  rec {idx}: FAILED {exc}")
            continue
        need_b = (len(comp) + 16 + S.SECTOR - 1) // S.SECTOR
        need_a = (inflated + S.SECTOR - 1) // S.SECTOR
        da += need_a - rec.inflated
        db += need_b - rec.stored
        if need_b != rec.stored:
            grew_b += 1
        if need_b != rec.stored or need_a != rec.inflated:
            print(f"  rec {idx:<5} A {rec.inflated} -> {need_a}   "
                  f"B {rec.stored} -> {need_b}   "
                  f"(comp {len(comp)} B, inflated {inflated} B)")

    print(f"\nrecords whose B changes: {grew_b}/{len(touched)}")
    print(f"total delta: A {da:+d} sectors, B {db:+d} sectors "
          f"({db * S.SECTOR / 1048576:+.1f} MiB)")
    print(f"SLOT.DAT would grow by {db * S.SECTOR} bytes "
          f"if every later record shifts")


if __name__ == "__main__":
    main()
