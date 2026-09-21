"""Probe: what is a `FEL\x07` payload?  (ADEMO / ADEMOHQ mission packages)

`_probe_pkg_scan.py` classified 462 of them as "raw" and stopped there; the
mission packages are 6.6 GB and 60% of their bytes were never even searched
(`_probe_fel_cover.py`).  Before sweeping gigabytes for a needle we have to
know whether a FEL payload is plaintext-searchable at all, or whether its
members are compressed.

This probe dumps the structure of a few FEL payloads:

  - first 128 bytes, as hex and as little-endian u32 (a u32 count / size /
    offset table is the usual shape)
  - every `78 da` (zlib) hit with its offset and whether it inflates
  - printable ratio, and the longest ASCII runs (a name table would show up)

Usage:  python _probe_fel1.py [container_rel] [max_entries]
"""
import re
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pwsf_archive as A                # noqa: E402
import _probe_pkg_scan as S             # noqa: E402

DEFAULT = r"MLG\disc0_rel\ADEMO\0018ef0c.pdt"


def describe(plain: bytes, tag: str, limit: int = 6) -> None:
    print(f"\n--- {tag}: {len(plain)} bytes  magic={plain[:4].hex()}"
          f" ({plain[:4]!r})")
    u32 = [struct.unpack_from("<I", plain, i)[0] for i in
           range(0, min(64, len(plain) - 3), 4)]
    print("    u32[0..15]:", " ".join(f"{v:#010x}" for v in u32[:16]))
    print("    u32[16..31]:", " ".join(f"{v:#010x}" for v in u32[16:32]))
    nz = [c for c in plain] or [0]
    good = sum(1 for c in nz if 32 <= c < 127)
    print(f"    printable (non-zero only): {good / len(nz):.2f}")

    hits = [m.start() for m in re.finditer(rb"\x78\xda", plain)]
    print(f"    zlib sigs: {len(hits)} -> {hits[:8]}")
    ok = 0
    for off in hits[:limit]:
        try:
            body = zlib.decompressobj().decompress(plain[off:])
        except zlib.error as ex:
            print(f"      @{off:#x} fail {ex}")
            continue
        print(f"      @{off:#x} -> {len(body)} B  {bytes(body[:40])!r}")
        ok += 1
    print(f"    inflated {ok}/{min(len(hits), limit)} tried")

    runs = [m.group() for m in re.finditer(rb"[ -~]{6,}", plain)]
    runs.sort(key=len, reverse=True)
    for r in runs[:5]:
        print(f"    ascii: {r[:70]!r}")


def main() -> None:
    rel = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    p = S.GAME / rel
    size = p.stat().st_size
    with p.open("rb") as fh:
        arc = A.parse(fh.read(min(size, S.HEAD_CAP)), p.stem, str(p),
                      max_entries=200000)
    probs = A.verify(arc, size)
    print(f"{rel}: mode={arc.mode:#x} count={arc.count} "
          f"{'ok' if not probs else probs[:1]}")
    shown = 0
    with p.open("rb") as fh:
        for i in range(arc.count):
            e = arc.entries[i]
            fh.seek(e.c)
            plain = S.unmask(arc, fh.read(min(e.a, 4 << 20)))
            if plain[:4] != b"FEL\x07":
                print(f"\n--- entry {i}: not FEL ({plain[:4].hex()})")
                continue
            describe(plain, f"entry {i} (first {min(e.a, 4 << 20)} B "
                            f"of {e.a})")
            shown += 1
            if shown >= n:
                break


if __name__ == "__main__":
    main()
