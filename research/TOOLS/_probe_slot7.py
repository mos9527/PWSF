"""SLOT.DAT sector 0: the record table starts at sector 1, so sector 0 is a
container header.  Dump it raw and under name_hash("002aba34").

Also re-derive the keystream the probe actually used, so 08_cutscene_text.md
can quote it as evidence rather than a claim.
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config as C
from pwsf.crypto import buffer_xor_decrypt, name_hash

SECTOR = 4096
KEY = name_hash("002aba34")


def main() -> None:
    root = C.require_game() / "MLG" / "disc0_rel"
    dat = C.pristine(root / "002aba34.DAT")
    print(f"SLOT.DAT {dat}  size={dat.stat().st_size:#x}  key={KEY:#010x}")

    with open(dat, "rb") as fh:
        s0 = fh.read(SECTOR)
    print(f"\nsector 0 raw[0:64]      {s0[:64].hex(' ')}")
    buf = bytearray(s0)
    buffer_xor_decrypt(buf, KEY)
    print(f"sector 0 xor[0:64]      {bytes(buf[:64]).hex(' ')}")

    ks = bytes(a ^ b for a, b in zip(s0[:32], buf[:32]))
    print(f"keystream[0:32]         {ks.hex(' ')}")
    print(f"sector 0 as u32 (xor)   "
          f"{[hex(v) for v in struct.unpack('<8I', bytes(buf[:32]))]}")

    # printable / entropy feel of sector 0 under both views
    for label, blob in (("raw", s0), ("xor", bytes(buf))):
        runs, cur = [], 0
        for c in blob:
            if 32 <= c < 127:
                cur += 1
            else:
                if cur:
                    runs.append(cur)
                cur = 0
        if cur:
            runs.append(cur)
        print(f"  {label}: printable runs={len(runs)} longest={max(runs) if runs else 0}")


if __name__ == "__main__":
    main()
