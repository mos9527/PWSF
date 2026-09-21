"""Probe: the `GTT\\x00` pools -- the text container we never extracted.

ANALYSIS/08 §8.3 records it and leaves it open:

    `GTT\x00` pools (462, all in records 0..870): another text container,
    strings are suffix-merged (splitting on NUL yields fragments like `n.`
    / `Cett`), header is `GTT` then 01 00 00 00 / 0x38 / 0x65.  Not solved.

Every corpus we extracted is RBX/olang (SLOT 144 tables / STAGEDAT 738 tables /
17 on-disk .olang / BRIEFING / the DLCVOICE fixed-width tables).  The missing
in-mission radio line

    "There's no one around - why not try some shooting practice?"  (Miller)

is in none of them, and every container payload on disk has now been decrypted
and searched (ANALYSIS/09 §9, §10).  So the first thing to check is whether it
is sitting in this never-parsed pool type.

Step 1 (this probe): find every GTT pool, needle-search them, and dump one
header so the layout can be read.

Usage:
  python _probe_gtt1.py                 # full SLOT.DAT walk, needles + dumps
  python _probe_gtt1.py --max-rec 900   # stop early
"""
import argparse
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pwsf import slotdat as S          # noqa: E402

GTT = b"GTT\x00"
NEEDLES = [b"shooting practice", b"no one around",
           b"Investigate the Supply"]


def dump(tag: str, blob: bytes, limit: int = 192) -> None:
    print(f"\n=== {tag}: {len(blob)} bytes")
    head = blob[:limit]
    for off in range(0, len(head), 16):
        row = head[off:off + 16]
        print(f"  {off:04x}  {row.hex(' '):<47}  "
              f"{''.join(chr(c) if 32 <= c < 127 else '.' for c in row)}")
    if len(blob) >= 24:
        print("  u32[0..5]: " + " ".join(
            f"{struct.unpack_from('<I', blob, 4 * i)[0]:#010x}"
            for i in range(6)))
    runs = [m.group() for m in re.finditer(rb"[ -~]{10,}", blob)]
    runs.sort(key=len, reverse=True)
    print(f"  longest ASCII runs ({len(runs)}):")
    for r in runs[:8]:
        print(f"    {len(r):4d}  {r[:80]!r}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-rec", type=int, default=0)
    ap.add_argument("--dump", type=int, default=2)
    args = ap.parse_args()

    recs = S.load_index()
    state, inc = S.lcg_params()
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)

    n = dumps = 0
    hits = []
    rec_span = []
    for rec in recs:
        if args.max_rec and rec.index >= args.max_rec:
            break
        for eid, off, blob in S.pools(rec, ks):
            if blob[:4] != GTT:
                continue
            n += 1
            rec_span.append(rec.index)
            low = blob.lower()
            for nd_ in NEEDLES:
                if nd_ in low:
                    hits.append((rec.index, eid, nd_.decode(),
                                 hex(low.find(nd_))))
                    print(f"  *** HIT rec {rec.index} pool {eid:#010x} "
                          f"{nd_.decode()}")
            if dumps < args.dump:
                dump(f"rec {rec.index} pool {eid:#010x}", blob)
                dumps += 1
    print(f"\nGTT pools: {n} | records "
          f"{min(rec_span) if rec_span else '-'}..{max(rec_span) if rec_span else '-'}")
    print("needle hits:", hits or "none")


if __name__ == "__main__":
    main()
