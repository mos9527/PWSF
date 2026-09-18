"""Probe: everything a byte-exact olang serialiser has to preserve.

Checks across all 17 shipped tables:
  * the two header fields the parser calls "zero" -- are they actually zero?
  * section order and whether the four sections are contiguous or padded
  * do the table sizes implied by the offsets match the counts we derive?
  * is the string pool deduplicated (several keys sharing one str_off)?
  * is every pool byte reachable from some key, or are there gaps?
  * are str_off values monotonically increasing in key order?
"""

import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash, buffer_xor_decrypt

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
HEADER_SIZE = 0x20


def analyse(path: Path) -> dict:
    data = bytes(buffer_xor_decrypt(bytearray(path.read_bytes()), name_hash(path.stem)))
    table_id, z0 = struct.unpack_from("<II", data, 4)
    z1, group_count = struct.unpack_from("<HH", data, 0x0C)
    off_grp, off_ent, off_key, off_pool = struct.unpack_from("<4I", data, 0x10)

    groups = [struct.unpack_from("<IHH", data, off_grp + 8 * i)
              for i in range(group_count)]
    n_ent = max(g[1] + g[2] for g in groups)
    entries = [struct.unpack_from("<IHH", data, off_ent + 8 * i)
               for i in range(n_ent)]
    n_key = max(e[1] + e[2] for e in entries)
    keys = [struct.unpack_from("<IIHH", data, off_key + 12 * i)
            for i in range(n_key)]

    pool = data[off_pool:]
    offs = [k[1] for k in keys]
    dup = sum(c - 1 for c in Counter(offs).values() if c > 1)

    # which pool bytes are covered by some string (including its NUL)
    covered = bytearray(len(pool))
    for o in set(offs):
        end = pool.find(b"\x00", o)
        end = len(pool) if end < 0 else end
        covered[o:end + 1] = b"\x01" * (end + 1 - o)
    gap = len(covered) - sum(covered)

    return dict(
        name=path.name, size=len(data), table_id=table_id,
        z0=z0, z1=z1, groups=group_count, entries=n_ent, keys=n_key,
        off_grp=off_grp, off_ent=off_ent, off_key=off_key, off_pool=off_pool,
        grp_end=off_grp + 8 * group_count,
        ent_end=off_ent + 8 * n_ent,
        key_end=off_key + 12 * n_key,
        pool_len=len(pool), dup=dup, gap=gap,
        sorted_offs=offs == sorted(offs),
        pads=(off_grp - HEADER_SIZE, off_ent - (off_grp + 8 * group_count),
              off_key - (off_ent + 8 * n_ent), off_pool - (off_key + 12 * n_key)),
        metas=sorted({k[2] for k in keys}),
        pad_field=sorted({k[3] for k in keys}),
    )


def main() -> None:
    rows = []
    for sub in ("MLG/Text", "EXLANG/Text"):
        for f in sorted((GAME / sub.replace("/", "\\")).glob("*.olang")):
            rows.append(analyse(f))

    print(f"{'file':<16} {'grp':>4} {'ent':>5} {'keys':>6} {'pool':>8} "
          f"{'dup':>5} {'gap':>5} {'pads(h,g,e,k)':>18} {'srt':>4} "
          f"{'z0':>3} {'z1':>3}")
    for r in rows:
        print(f"{r['name']:<16} {r['groups']:>4} {r['entries']:>5} {r['keys']:>6} "
              f"{r['pool_len']:>8} {r['dup']:>5} {r['gap']:>5} "
              f"{str(r['pads']):>18} {str(r['sorted_offs'])[:1]:>4} "
              f"{r['z0']:>3} {r['z1']:>3}")

    print("\nsection order always group < entry < key < pool:",
          all(r['off_grp'] < r['off_ent'] < r['off_key'] < r['off_pool']
              for r in rows))
    print("header always 0x20 and first section right after it:",
          all(r['off_grp'] == HEADER_SIZE for r in rows))
    print("all inter-section padding zero:",
          all(all(p == 0 for p in r['pads']) for r in rows))
    print("pool always ends the file:",
          all(r['off_pool'] + r['pool_len'] == r['size'] for r in rows))
    print("z0 always 0:", all(r['z0'] == 0 for r in rows))
    print("z1 always 0:", all(r['z1'] == 0 for r in rows))
    print("table_id == name:",
          all(r['table_id'] == int(r['name'].split('.')[0], 16) for r in rows))
    print("key.meta values seen:", sorted({m for r in rows for m in r['metas']}))
    print("key.pad values seen:", sorted({p for r in rows for p in r['pad_field']}))
    print("pool dedup in use:", any(r['dup'] for r in rows))
    print("unreachable pool bytes:", {r['name']: r['gap'] for r in rows if r['gap']})
    print("str_off sorted in key order:", all(r['sorted_offs'] for r in rows))


if __name__ == "__main__":
    main()
