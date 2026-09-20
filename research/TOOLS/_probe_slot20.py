"""Census: which SLOT.DAT resource entries are NUL-separated text pools?

slotdat_parse_res_entry @ 0x14008CF10 turns out to be the *install* path --
it reads flags from the entry payload, grabs one of 8 slots and calls
sub_1400A59A0.  It never touches strings, so it cannot tell us which entries
hold dialogue.  Go at it from the data side instead:

  * every record's table gives (id, offset); the length of an entry is the
    next entry's offset minus this one's (0x7f000000 / 0x00000000 are the
    sentinels that slotdat_find_res_entry's filter skips)
  * an entry is a "text pool" when it is almost entirely printable ASCII /
    NUL and splits into runs that look like sentences

Prints the per-record summary, the id distribution of text pools, and the raw
table bytes of one record so the 16-byte entry layout can be checked by eye.
"""

import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import slotdat as S

PRINT = set(range(32, 127)) | {0, 9, 10, 13}


def textiness(buf: bytes) -> float:
    if not buf:
        return 0.0
    step = max(1, len(buf) // 4096)
    sample = buf[::step]
    return sum(1 for c in sample if c in PRINT) / len(sample)


def strings(buf: bytes, minlen: int = 2):
    out = []
    for part in buf.split(b"\x00"):
        part = part.strip(b"\r\n\t ")
        if len(part) >= minlen and textiness(part) > 0.95:
            out.append(part)
    return out


def main() -> None:
    recs = S.load_index()
    state, inc = S.lcg_params()
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)

    dump_done = False
    pool_recs = []
    id_hist = Counter()
    n_strings = 0
    n_pools = 0

    for rec in recs:
        plain = S.decrypt(S.read_block(rec), ks)
        data = S.inflate(plain)
        count, entries, area = S.res_table(data)
        # live entries: skip the 0 / 0x7f... sentinels, sort by offset
        live = sorted((e for e in entries if e[0] and (e[0] >> 24) != 0x7F),
                      key=lambda e: e[2] & 0x3FFFFFFF)
        bounds = [(e[2] & 0x3FFFFFFF) for e in live]
        end = [b for b in bounds[1:]] + [len(data) - area]
        pools = []
        for e, off, stop in zip(live, bounds, end):
            blob = data[area + off:area + min(stop, len(data) - area)]
            if len(blob) < 64 or textiness(blob) < 0.9:
                continue
            strs = strings(blob)
            if len(strs) < 3:
                continue
            avg = sum(len(s) for s in strs) / len(strs)
            if avg < 8:
                continue
            pools.append((e[0], off, len(strs), avg, strs[0][:60]))
            id_hist[e[0]] += 1
            n_pools += 1
            n_strings += len(strs)
        if pools:
            pool_recs.append((rec.index, rec.id_hash, count, pools))

        if not dump_done and rec.index == 1874:
            dump_done = True
            print(f"== record 1874 table: count={count}, area=+{area:#x}")
            print("   raw +0..+160:")
            print("   " + data[:160].hex(" "))
            print(f"   {len(live)} live entries (id, d1, off, d3):")
            for e in live:
                print(f"     {e[0]:#010x} {e[1]:#010x} "
                      f"{e[2] & 0x3FFFFFFF:#08x} {e[3]:#010x}")

    print(f"\nrecords with text pools: {len(pool_recs)} / {len(recs)}")
    print(f"text pools: {n_pools}   strings: {n_strings}")
    print(f"\nmost common pool ids:")
    for eid, n in id_hist.most_common(20):
        print(f"  {eid:#010x}  {n}")
    print(f"\ndistinct pool ids: {len(id_hist)}")

    print("\nfirst 25 records with pools:")
    for idx, ihash, count, pools in pool_recs[:25]:
        print(f"  rec {idx:<5} id_hash={ihash:#010x} entries={count} "
              f"pools={len(pools)}")
        for eid, off, n, avg, first in pools[:3]:
            print(f"      {eid:#010x} +{off:#06x}  {n} strings "
                  f"avg {avg:.0f}  {first!r}")


if __name__ == "__main__":
    main()
