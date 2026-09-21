"""Probe: extract the GTT corpus (first working extractor).

Layout, read off pool 0x1c79f20b / record 84 (_probe_gtt2..4):

    block:  +0x00 "GTT\\x00"
            +0x04 u32 n          lines in the block
            +0x08 u32 pool_off   header size == start of the pool
            +0x0c u32 id
            +0x1c u16 array, length 4 + 10*n:
                      [0..3]   = 4 copies of the offset of line 1
                      then per line i:  [a, b, 1, X, X, X, Y, Y, Y, Y]
                      X = start offset of line i+1, Y = start of line i+2
                      (last group is zero padding)

    pool is SUFFIX-MERGED: one NUL-terminated run holds the head of another
    language immediately followed by a whole line of the primary language,
    e.g. run `Je t\\xe2The signal is unidirectional.` = fr head at 0x40 +
    the English line at 0x45.  So a line is read as pool[start : next NUL].

This extractor takes the primary-language start offsets from the header
(0, then X of every group) and reads to the next NUL.  It is the first cut:
enough to see the corpus and to confirm the missing radio line is in it.

Usage:  python _probe_gtt5.py [--out research/ANALYSIS/_gtt_lines.tsv]
"""
import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pwsf import slotdat as S          # noqa: E402

GTT = b"GTT\x00"


def starts_of(blob: bytes, o: int, pool_off: int, n: int):
    """Primary-language start offsets: 0, then X of every non-empty group."""
    arr = struct.unpack_from("<%dH" % ((pool_off - 0x1C) // 2), blob, o + 0x1C)
    out = [0]
    body = arr[4:]
    for i in range(max(n - 1, 0)):
        g = body[10 * i:10 * i + 10]
        if not g or not g[3]:
            continue
        out.append(g[3])
    return out


def blocks(blob: bytes):
    out, i = [], 0
    while True:
        j = blob.find(GTT, i)
        if j < 0:
            break
        out.append(j)
        i = j + 4
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="research/ANALYSIS/_gtt_lines.tsv")
    args = ap.parse_args()
    out = Path(args.out)
    if not out.is_absolute():
        out = Path(__file__).resolve().parent.parent.parent / out

    recs = S.load_index()
    state, inc = S.lcg_params()
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)

    rows, pools = [], 0
    for rec in recs:
        for eid, _off, blob in S.pools(rec, ks):
            if blob[:4] != GTT:
                continue
            pools += 1
            offs = blocks(blob)
            for k, o in enumerate(offs):
                end = offs[k + 1] if k + 1 < len(offs) else len(blob)
                n, pool_off, ident = struct.unpack_from("<III", blob, o + 4)
                if pool_off <= 0x1C or pool_off > end - o:
                    continue
                pool = blob[o + pool_off:end]
                for li, st in enumerate(starts_of(blob, o, pool_off, n)):
                    if st >= len(pool):
                        continue
                    j = pool.find(b"\x00", st)
                    seg = pool[st:] if j < 0 else pool[st:j]
                    rows.append((rec.index, f"{eid:#010x}", f"{o:#x}",
                                 f"{ident:#x}", li, seg))

    seen, uniq = set(), []
    for r in rows:
        key = r[5]
        if key in seen or not key.strip():
            continue
        seen.add(key)
        uniq.append(r)
    with out.open("w", encoding="utf-8") as fh:
        fh.write("record\tpool\tblock\tid\tline\ttext\n")
        for r in uniq:
            txt = r[5].decode("utf-8", "replace").replace(
                "\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n")
            fh.write("\t".join(str(x) for x in r[:5]) + "\t" + txt + "\n")
    print(f"pools {pools} | blocks->lines {len(rows)} | unique {len(uniq)} "
          f"-> {out}")
    for r in uniq[:12]:
        print(f"  rec{r[0]} {r[1]} blk{r[2]} id{r[3]} L{r[4]}  "
              f"{r[5][:70]!r}")
    for nd_ in (b"shooting practice", b"no one around"):
        hit = [r for r in uniq if nd_ in r[5].lower()]
        print(f"needle {nd_.decode()!r}: {len(hit)}")
        for r in hit[:3]:
            print(f"   rec{r[0]} {r[1]} blk{r[2]}  {r[5][:90]!r}")


if __name__ == "__main__":
    main()
