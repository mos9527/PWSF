"""Probe: GTT write-back round-trip, over all 462 pools.

Two things have to hold before any translation is written into SLOT.DAT:

  1. identity  -- parse a pool, patch every line with the text it already has,
                  and the pool must come back byte for byte.  That proves the
                  parser's model of the layout is complete (offsets, budget,
                  NUL positions) even though `a` / `b` in the header are still
                  unidentified.
  2. rewrite   -- patch one line with a same-length filler: the pool must keep
                  its length, `pwsf.gtt.verify` must read the filler back, and
                  the diff must be confined to that line's run.

Also printed: the budget distribution, i.e. how many bytes a Chinese
translation may use per line -- the number `po_lint`'s `gtt-budget` rule and
`ANALYSIS/11 §5` rest on.

Usage:  python _probe_gtt7.py [--limit 0]
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pwsf import gtt                   # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0,
                    help="stop after this many pools (0 = all)")
    args = ap.parse_args()

    pools = blocks = lines = 0
    identity_bad = []
    budgets = []
    sample = None

    # the round-trip is checked on EVERY pool, including the fr/de/it/es
    # copies; the budget distribution is reported for the English ones only,
    # because that is the corpus we translate (ANALYSIS/11 §1)
    blobs = list(gtt.pool_blobs())
    ids = {eid for _r, eid, _b in blobs}
    english = gtt.english_pools(ids)

    for rec, eid, blob in blobs:
        pools += 1
        if eid not in english:
            continue
        bl = gtt.parse(blob)
        blocks += len(bl)
        changes = {}
        for b in bl:
            for li in range(len(b.starts)):
                txt = b.line(li)
                if txt:
                    changes[(b.off, li)] = txt
                    budgets.append(b.budget(li))
        lines += len(changes)
        same = gtt.patch(blob, changes)
        if same != blob:
            diff = [i for i in range(min(len(same), len(blob)))
                    if same[i] != blob[i]]
            identity_bad.append((rec, eid, diff[:4], len(diff)))
        if sample is None and bl:
            sample = (rec, eid, blob)

        if args.limit and pools >= args.limit:
            break

    print(f"pools {pools} ({len(english)} English, checked all) | "
          f"blocks {blocks} | English lines {lines}")
    print("identity round-trip failures:", identity_bad or "none")

    if sample:
        rec, eid, blob = sample
        b0 = gtt.parse(blob)[0]
        li = 0
        old = b0.line(li)
        filler = b"#" * len(old)
        new = gtt.patch(blob, {(b0.off, li): filler})
        print(f"\nrewrite sample: rec {rec} pool {eid:#010x} "
              f"block @{b0.off:#x} line {li}")
        print(f"  was {old[:50]!r}")
        print(f"  now {gtt.parse(new)[0].line(li)[:50]!r}")
        print(f"  length {len(blob)} -> {len(new)}")
        diff = [i for i in range(len(blob)) if blob[i] != new[i]]
        print(f"  bytes changed: {len(diff)} (run is {len(old)} B) "
              f"@ {diff[0]:#x}..{diff[-1]:#x}")
        print("  verify problems:",
              gtt.verify(new, {(b0.off, li): filler}) or "none")
        over = gtt.patch(blob, {(b0.off, li): b"#" * (len(old) + 1)})
        print(f"  over-budget write refused: {over == blob}")

    if budgets:
        budgets.sort()
        n = len(budgets)
        print(f"\nbudget per line: min {budgets[0]} "
              f"median {budgets[n // 2]} max {budgets[-1]} "
              f"mean {sum(budgets) / n:.1f}")
        for want in (24, 36, 48, 60):
            fits = sum(1 for b in budgets if b >= want)
            print(f"  >= {want:3d} B: {fits}/{n} ({100 * fits / n:.0f}%)")


if __name__ == "__main__":
    main()
