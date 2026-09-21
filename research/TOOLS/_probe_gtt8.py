"""Probe: what are `a` and `b`?  (the two unidentified u16 per GTT line)

Earlier I read them as pointers into the pool, because they land inside the
English strings -- but that is just a coincidence of magnitude: pool offsets
and frame numbers are both small integers.  The observation that kills the
pointer idea is `b = 324` in a block whose pool is 312 B: an offset cannot
point past its own pool.

So: measure them across every block and test the competing hypotheses.

    H1 offsets      -> must always be < len(pool)
    H2 LZ77 (dist,len) -> distance must be <= the current position
    H3 timing       -> monotonic, and a[i+1] >= b[i] with a small gap;
                       (b-a) should grow with the line's length

Usage:  python _probe_gtt8.py [--limit 0]
"""
import argparse
import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pwsf import gtt                   # noqa: E402

GROUP = gtt.GROUP
PREFIX = gtt.PREFIX


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    n_pool = seen = 0
    over_a = over_b = 0
    gaps = []
    ratios = []
    not_monotonic = 0
    pools = 0

    for _rec, eid, blob in gtt.pool_blobs():
        pools += 1
        for b in gtt.parse(blob):
            body = b.array[PREFIX:]
            groups = [body[GROUP * i:GROUP * i + GROUP]
                      for i in range(max(b.n - 1, 0))]
            pairs = []
            for i, g in enumerate(groups):
                if len(g) < 4 or not g[3]:
                    continue
                pairs.append((g[0], g[1], i + 1))       # (a, b, line index)
            if not pairs:
                continue
            n_pool += 1
            for a, bb, li in pairs:
                seen += 1
                if a >= len(b.pool):
                    over_a += 1
                if bb >= len(b.pool):
                    over_b += 1
                if li < len(b.starts):
                    ln = len(b.line(li))
                    if ln:
                        ratios.append((bb - a) / ln)
            for i in range(len(pairs) - 1):
                gap = pairs[i + 1][0] - pairs[i][1]
                gaps.append(gap)
                if gap < 0:
                    not_monotonic += 1
        if args.limit and pools >= args.limit:
            break

    print(f"pools {pools} | blocks with groups {n_pool} | (a,b) pairs {seen}")
    print(f"H1 offsets:  a >= len(pool) {over_a}x, b >= len(pool) {over_b}x "
          f"-- a real offset can never do that")
    print(f"H3 timing:   a[i+1] - b[i] gaps: "
          f"{Counter(gaps).most_common(8)}")
    print(f"             negative gaps (not monotonic): {not_monotonic}")
    if gaps:
        gaps.sort()
        print(f"             gap min {gaps[0]} median "
              f"{gaps[len(gaps) // 2]} max {gaps[-1]}")
    if ratios:
        ratios.sort()
        print(f"             (b-a) / line length: min {ratios[0]:.2f} "
              f"median {ratios[len(ratios) // 2]:.2f} max {ratios[-1]:.2f}")
    print("\nsample blocks (a, b, line text length):")
    shown = 0
    for _rec, eid, blob in gtt.pool_blobs():
        for b in gtt.parse(blob):
            body = b.array[PREFIX:]
            rows = []
            for i in range(max(b.n - 1, 0)):
                g = body[GROUP * i:GROUP * i + GROUP]
                if len(g) < 4 or not g[3]:
                    continue
                li = i + 1
                rows.append((g[0], g[1], len(b.line(li)) if li < len(b.starts)
                             else 0, b.line(li)[:34]))
            if len(rows) >= 3:
                print(f"  pool {eid:#010x} block @{b.off:#x} pool={len(b.pool)}B")
                for a, bb, ln, txt in rows:
                    print(f"    a={a:4d} b={bb:4d} dur={bb - a:4d} "
                          f"len={ln:3d}  {txt.decode('latin-1')!r}")
                shown += 1
            if shown >= 3:
                return
        if shown >= 3:
            return


if __name__ == "__main__":
    main()
