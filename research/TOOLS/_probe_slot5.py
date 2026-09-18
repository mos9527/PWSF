"""SLOT.KEY record layout: 20-byte bit-packed records, with self-consistency.

Supersedes the field split guessed in _probe_slot2 (four u16s).  Sector numbers
run to 132,948, past u16, so start/end are 20-bit fields sharing their dword
with a 12-bit counter:

    +0x00  u32  start sector (low 20) | A (high 12)
    +0x04  u32  end   sector (low 20) | B (high 12)
    +0x08  u32  hash
    +0x0c  u32  A, again as a full dword
    +0x10  u32  B, again as a full dword

Checks printed below are what 08_cutscene_text.md section 4 quotes.
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config as C
from pwsf.crypto import buffer_xor_decrypt, name_hash

SECTOR = 4096
HDR, REC = 12, 20
MASK20 = (1 << 20) - 1


def load(path: Path):
    buf = bytearray(path.read_bytes())
    buffer_xor_decrypt(buf, name_hash(path.stem))
    n, rem = divmod(len(buf) - HDR, REC)
    recs = []
    for i in range(n):
        w0, w1, h, a, b = struct.unpack_from("<IIIII", buf, HDR + REC * i)
        recs.append((w0 & MASK20, w0 >> 20, w1 & MASK20, w1 >> 20, h, a, b))
    return bytes(buf[:HDR]), recs, rem


def main() -> None:
    root = C.require_game() / "MLG" / "disc0_rel"
    hdr, recs, rem = load(C.pristine(root / "002aba34.KEY"))
    n = len(recs)
    dat = C.pristine(root / "002aba34.DAT")
    sectors = dat.stat().st_size // SECTOR if dat.is_file() else 0

    print(f"SLOT.KEY header {hdr.hex(' ')}  records={n}  leftover={rem}")
    print(f"  start[i+1] == end[i]           "
          f"{sum(1 for x, y in zip(recs, recs[1:]) if y[0] == x[2])} / {n - 1}")
    print(f"  end[last] = {recs[-1][2]}   SLOT.DAT sectors = {sectors}")
    print(f"  +0x0c == high12(+0x00)         "
          f"{sum(1 for r in recs if r[5] == r[1])} / {n}")
    print(f"  +0x10 == high12(+0x04)         "
          f"{sum(1 for r in recs if r[6] == r[3])} / {n}")
    print(f"  A >= B                         "
          f"{sum(1 for r in recs if r[1] >= r[3])} / {n}")
    print(f"  B == end - start               "
          f"{sum(1 for r in recs if r[3] == r[2] - r[0])} / {n}")
    a, b = sum(r[1] for r in recs), sum(r[3] for r in recs)
    print(f"  sum A = {a} sectors ({a * SECTOR / 2**20:.0f} MiB)")
    print(f"  sum B = {b} sectors ({b * SECTOR / 2**20:.0f} MiB)   ratio {a / b:.2f}")
    print("  first records (start, A, end, B, hash):")
    for r in recs[:6]:
        print(f"    {r[0]:>7} {r[1]:>5} {r[2]:>7} {r[3]:>5} {r[4]:#010x}")


if __name__ == "__main__":
    main()
