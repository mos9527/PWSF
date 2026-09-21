"""Probe: FEL structure, studied on the SMALL copies inside SLOT.DAT.

Why here and not in ADEMO/ADEMOHQ (where the payloads are 100 KB .. 500 MB):
`_probe_slot26.py` found the same `FEL\\x07` blocks inside the cutscene records
of SLOT.DAT (181 pools, 208 B .. 7 KB), i.e. the same format in a size we can
read end to end.  ADEMO/ADEMOHQ (35 files each, identical names, 209 MB vs
6.4 GB) is the "install" pair picked by `path_resolve_install` @ 0x140043DA0,
so those are almost certainly media; the SLOT copies are the ones that could be
a script.

Note for the record: the magic is NOT in the binary.  `FEL\\x07` occurs 0 times
in METAL GEAR SOLID PEACE WALKER.exe (the 17 `FEL` hits are the swear-word
table), and no immediate 0x074C4546 exists either -- so nothing in the exe
dispatches on this magic; a FEL blob is handed over as an already-known type.

What this probe prints, for each sample:
  - first 256 bytes as hex
  - the 12 header u32 and a guess at the record table right after it
  - entropy per 256-byte window (a compressed member shows up as ~8.0)
"""
import argparse
import math
import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pwsf import slotdat as S                      # noqa: E402
import pwsf_archive as A                           # noqa: E402
import _probe_pkg_scan as P                        # noqa: E402

FEL = b"FEL\x07"
GAME = P.GAME


def entropy(b: bytes) -> float:
    n = len(b)
    if not n:
        return 0.0
    c = Counter(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def dump(tag: str, blob: bytes, limit: int = 256) -> None:
    print(f"\n=== {tag}: {len(blob)} bytes")
    head = blob[:limit]
    for off in range(0, len(head), 16):
        row = head[off:off + 16]
        print(f"  {off:04x}  {row.hex(' '):<47}  "
              f"{''.join(chr(c) if 32 <= c < 127 else '.' for c in row)}")
    w = struct.unpack_from("<12I", blob, 0)
    print("  hdr u32: " + " ".join(f"{x:#010x}" for x in w))
    print(f"  @0x10={w[4]}  @0x14=(u16 {w[5] & 0xFFFF}, {w[5] >> 16})  "
          f"@0x18={w[6]}  @0x1c={w[7]}  @0x20={w[8]:#x}  @0x24={w[9]}  "
          f"@0x28=(u16 {w[10] & 0xFFFF}, u16 {w[10] >> 16})  @0x2c={w[11]}")
    # u32 table from 0x30 while values increase
    o, prev, tab = 0x30, -1, []
    while o + 4 <= len(blob):
        v, = struct.unpack_from("<I", blob, o)
        if v < prev or v > len(blob):
            break
        tab.append(v)
        prev = v
        o += 4
        if len(tab) > 24:
            break
    print(f"  u32 table @0x30 ({len(tab)} increasing): {tab[:24]}")
    ent = [entropy(blob[i:i + 256]) for i in range(0, min(len(blob), 4096), 256)]
    print("  entropy/256B: " + " ".join(f"{e:.2f}" for e in ent[:16]))


def slot_fels(want: int):
    recs = S.load_index()
    state, inc = S.lcg_params()
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)
    out = []
    for rec in recs:
        if rec.index < 1863:
            continue
        for eid, off, blob in S.pools(rec, ks):
            if blob[:4] == FEL:
                out.append((rec.index, eid, blob))
                if len(out) >= want:
                    return out
    return out


def ademo_fel(want: int = 1):
    p = GAME / "MLG" / "disc0_rel" / "ADEMO" / "0018ef0c.pdt"
    with p.open("rb") as fh:
        arc = A.parse(fh.read(8 << 20), p.stem, str(p), max_entries=200000)
    out = []
    with p.open("rb") as fh:
        for i in range(arc.count):
            e = arc.entries[i]
            fh.seek(e.c)
            plain = P.unmask(arc, fh.read(min(e.a, 1 << 20)))
            if plain[:4] == FEL:
                out.append((i, plain))
                if len(out) >= want:
                    return out
    return out


def all_slot_fels():
    """Every FEL block in SLOT.DAT: does any of them hold text?

    The 181 cutscene FEL pools were only sampled by _probe_slot26.py.  If the
    comic-page script carried its strings inline (instead of pointing into the
    RBX pool) that text would be missing from every corpus we have, so scan
    them all for printable runs.
    """
    import re as _re
    recs = S.load_index()
    state, inc = S.lcg_params()
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)
    n = 0
    best = []
    for rec in recs:
        if rec.index < 1863:
            continue
        for eid, off, blob in S.pools(rec, ks):
            if blob[:4] != FEL:
                continue
            n += 1
            runs = [m.group() for m in _re.finditer(rb"[ -~]{8,}", blob)]
            if runs:
                top = max(runs, key=len)
                best.append((len(top), rec.index, eid, len(blob),
                             top[:70].decode("latin-1")))
    print(f"FEL pools in SLOT.DAT: {n}")
    print(f"with an ASCII run >= 8: {len(best)}")
    for r in sorted(best, reverse=True)[:15]:
        print(f"  {r[0]:4d} chars  rec {r[1]} pool {r[2]:#010x} "
              f"({r[3]} B)  {r[4]!r}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--slot", type=int, default=3)
    ap.add_argument("--slot-all", action="store_true")
    args = ap.parse_args()
    if args.slot_all:
        all_slot_fels()
        return
    for rec, eid, blob in slot_fels(args.slot):
        dump(f"SLOT rec {rec} pool {eid:#010x}", blob)
    for i, blob in ademo_fel(1):
        dump(f"ADEMO 0018ef0c.pdt entry {i} (first 1 MB)", blob)


if __name__ == "__main__":
    main()
