"""Probe: decrypt the Steam save file `STW000000ac1d01`.

Why: the load/save screen still prints "Opening / Investigate the Supply
Facility" in English although the installed SLOT.DAT carries the Chinese string
(`_probe_slot_installed.py`).  The other candidate is that the title is a COPY
inside the save, written when the save was made.

Format, read off the binary (no guessing):

  systemdat_state_machine @ 0x1401BBC80, case 4
      systemdat_decrypt_and_build(a1)              0x1401BE8F0
        -> 12 x u32 LCG state words into v1[0..11]
        -> *v1      = idx ^ (v1[1] | 0xAD47DE8F)     idx = ((x>>8) % 5)
        -> v1[idx+2] = s0 ^ 0x1327DE73
        -> v1[idx+3] = s1 ^ 0x2D71D26C
        -> v1[idx+7] = s2 ^ 0xBC4DEFA2
        -> sub_14010DE00(s0, s1, s2)               0x14010DE00
              v3 = s1 ^ s0
              state = v3 | ((v3 ^ 0x6576) << 16)
              inc   = s2 * v3
        -> sub_14010DDC0(v1 + 16, len)             0x14010DDC0
              for each dword: *p ^= state; state = inc + 48828125 * state

  i.e. the very same LCG as the archive layer (04_archive.md §6.2 /
  ANALYSIS/09 §2), seeded from three words hidden in the 64-byte header.
  Data starts at offset 64 (v1 + 16).

Usage:  python _probe_savedata3.py [--file PATH] [--dump PATH]
"""
import argparse
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pwsf_archive as A                # noqa: E402

SAVE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW"
            r"\mgspw_savedata_win\76561199148085959\ww\STW000000ac1d01")
MASK32 = 0xFFFFFFFF
NEEDLES = [b"Investigate the Supply", b"supply facility", b"Opening",
           b"shooting practice", b"no one around"]


def unmask(buf: bytes, state: int, inc: int) -> bytes:
    mv = memoryview(bytearray(buf))
    n = len(mv) & ~3
    A._unmask_lcg(mv[:n], state, inc)
    return bytes(mv)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=str(SAVE))
    ap.add_argument("--dump", default="")
    args = ap.parse_args()
    data = Path(args.file).read_bytes()
    w = list(struct.unpack_from("<16I", data, 0))
    print("header u32:", " ".join(f"{v:#010x}" for v in w))

    idx = (w[0] ^ (w[1] | 0xAD47DE8F)) & MASK32
    print(f"recovered idx = {idx}  (valid range 0..4)")
    if idx > 4:
        print("  -> header does not match the observed layout; stop")
        return
    s0 = w[idx + 2] ^ 0x1327DE73
    s1 = w[idx + 3] ^ 0x2D71D26C
    s2 = w[idx + 7] ^ 0xBC4DEFA2
    v3 = (s1 ^ s0) & MASK32
    state = (v3 | ((v3 ^ 0x6576) << 16)) & MASK32
    inc = (s2 * v3) & MASK32
    print(f"seeds s0={s0:#010x} s1={s1:#010x} s2={s2:#010x} "
          f"-> state={state:#010x} inc={inc:#010x}")

    plain = data[:64] + unmask(data[64:], state, inc)
    nz = [c for c in plain[64:]] or [0]
    good = sum(1 for c in nz if 32 <= c < 127) / len(nz)
    print(f"decrypted {len(plain)} B, printable of payload = {good:.3f}")
    print("first 48 B of payload:", plain[64:112].hex())

    low = plain.lower()
    for nd in NEEDLES:
        i = low.find(nd.lower())
        print(f"  needle {nd!r}: {'@ %#x' % i if i >= 0 else 'not found'}")
        if i >= 0:
            print("     ", plain[max(0, i - 60):i + len(nd) + 60])

    runs = [m for m in re.finditer(rb"[ -~]{16,}", plain)]
    runs.sort(key=lambda m: -len(m.group()))
    print(f"\nlongest ASCII runs ({len(runs)} total):")
    for m in runs[:15]:
        print(f"  @{m.start():#x} {m.group()[:90]!r}")

    if args.dump:
        Path(args.dump).write_bytes(plain)
        print(f"\nwrote {args.dump}")


if __name__ == "__main__":
    main()
