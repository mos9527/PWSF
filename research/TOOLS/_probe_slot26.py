"""The cutscene records also carry `FEL\\x07` blocks -- peek at them.

The tail records (1863..2137) hold 270 RBX (text) pools and 181 `FEL\\x07`
pools.  If FEL is the comic page script it would say which string goes in a
speech bubble and which is the bottom caption -- the open question in
ANALYSIS/08 §8.  This is a first look only: size, header, and whether any
string offsets from the RBX pool show up inside it.
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import slotdat as S

FEL = b"FEL\x07"


def main() -> None:
    recs = S.load_index()
    state, inc = S.lcg_params()
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)

    shown = 0
    for rec in recs:
        if rec.index < 1874:
            continue
        pools = S.pools(rec, ks)
        for eid, off, blob in pools:
            if blob[:4] != FEL:
                continue
            print(f"\nrec {rec.index} pool {eid:#010x} off {off:#x} "
                  f"{len(blob)} bytes")
            print("  " + blob[:96].hex(" "))
            w = struct.unpack_from("<12I", blob, 0)
            print("  u32: " + " ".join(f"{x:#010x}" for x in w))
            # any ASCII runs?
            runs = []
            cur = b""
            for c in blob[:2048]:
                if 32 <= c < 127:
                    cur += bytes([c])
                else:
                    if len(cur) >= 5:
                        runs.append(cur)
                    cur = b""
            if cur and len(cur) >= 5:
                runs.append(cur)
            for r in runs[:6]:
                print(f"    ascii: {r[:70]!r}")
            shown += 1
            if shown >= 4:
                return


if __name__ == "__main__":
    main()
