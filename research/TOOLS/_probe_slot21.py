"""What are the 'GTT' and 'RBX' pools inside SLOT.DAT?

_probe_slot20.py showed every text pool starts with a short marker string --
either `GTT`, `RBX`, or (for id 0x1e4c1146) straight dialogue.  `RBX\0` is the
.olang container magic (01_olang_text.md), so SLOT.DAT is carrying olang
tables *inside* it.  `GTT` is unknown (nothing in the repo mentions it).

Dump the first bytes of one pool of each kind, plus all six pools of record
1874 (the one that holds the comic cutscene line).
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import slotdat as S

TARGETS = [
    (0, 0x1c767903, "GTT (rec 0)"),
    (2, 0x5d1f6f19, "RBX (rec 2)"),
    (18, 0x5d90fff3, "RBX long (rec 18)"),
]


def pools_of(rec_index, data, area, entries):
    live = sorted((e for e in entries if e[0] and (e[0] >> 24) != 0x7F),
                  key=lambda e: e[2] & 0x3FFFFFFF)
    bounds = [e[2] & 0x3FFFFFFF for e in live]
    ends = bounds[1:] + [len(data) - area]
    out = {}
    for e, off, stop in zip(live, bounds, ends):
        out[e[0]] = data[area + off:area + min(stop, len(data) - area)]
    return out


def main() -> None:
    recs = S.load_index()
    state, inc = S.lcg_params()
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)

    want = {idx: (eid, label) for idx, eid, label in TARGETS}
    want[1874] = (None, "record 1874 (all pools)")

    for rec in recs:
        if rec.index not in want:
            continue
        data = S.inflate(S.decrypt(S.read_block(rec), ks))
        count, entries, area = S.res_table(data)
        pools = pools_of(rec.index, data, area, entries)
        eid, label = want[rec.index]
        print(f"\n{'=' * 70}\nrecord {rec.index}  id_hash={rec.id_hash:#010x}  "
              f"count={count}  area=+{area:#x}   {label}")
        if eid is None:
            for pid, blob in pools.items():
                print(f"\n  -- pool {pid:#010x}  {len(blob)} bytes")
                print(f"     head {blob[:96].hex(' ')}")
                strs = [s for s in blob.split(b'\x00') if s.strip()][:6]
                for s in strs:
                    print(f"       {s[:90]!r}")
        else:
            blob = pools[eid]
            print(f"  pool {eid:#010x}  {len(blob)} bytes")
            print(f"  head {blob[:128].hex(' ')}")
            words = struct.unpack_from("<16I", blob, 0)
            print("  as u32: " + " ".join(f"{w:#010x}" for w in words))
            strs = [s for s in blob.split(b'\x00') if s.strip()][:8]
            for s in strs:
                print(f"       {s[:90]!r}")


if __name__ == "__main__":
    main()
