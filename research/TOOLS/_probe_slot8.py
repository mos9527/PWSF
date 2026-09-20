"""Grid-search the SLOT.DAT record payload: key x sector-offset.

slotdat_load_and_verify @ 0x1400A6290 gives the record header layout:

    +0x00  u16  ?            (sub_140119EB0 reads +0x02)
    +0x02  u16  header size
    +0x04  u32  ?
    +0x08  u32  compressed size     (sub_14002A530)
    +0x0c  u32  uncompressed size   (sub_140037CB0; compared with the
                                     byte count zlib uncompress produced,
                                     sub_140119EC0 -> sub_14045B490)

so a correctly decrypted record must satisfy
    u16@+2  in a sane range
    u32@+8  <= B * 4096
    u32@+12 == A * 4096        (A is the record's high-12-bit field)

This probe tries every (key, sector delta) pair over a sample of records and
reports how many satisfy the check.  A real hit must score near 100%.
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
SAMPLE = range(0, 2137, 17)


def load_key(path: Path):
    buf = bytearray(path.read_bytes())
    buffer_xor_decrypt(buf, name_hash(path.stem))
    n = (len(buf) - HDR) // REC
    out = []
    for i in range(n):
        w0, w1, h, a, b = struct.unpack_from("<IIIII", buf, HDR + REC * i)
        out.append((w0 & MASK20, w0 >> 20, w1 & MASK20, w1 >> 20, h, a, b))
    return bytes(buf[:HDR]), out


def sane(blob: bytes, A: int, B: int) -> bool:
    if len(blob) < 16:
        return False
    hdr = struct.unpack_from("<H", blob, 2)[0]
    comp, raw = struct.unpack_from("<II", blob, 8)
    return 8 <= hdr <= 512 and 0 < comp <= B * SECTOR and raw == A * SECTOR


def main() -> None:
    root = C.require_game() / "MLG" / "disc0_rel"
    khdr, recs = load_key(C.pristine(root / "002aba34.KEY"))
    dat = C.pristine(root / "002aba34.DAT")
    size = dat.stat().st_size

    keys = {
        "name_hash(002aba34)": name_hash("002aba34"),
        "SLOT.KEY hdr[0]": struct.unpack_from("<I", khdr, 0)[0],
        "SLOT.KEY hdr[1]": struct.unpack_from("<I", khdr, 4)[0],
        "SLOT.KEY hdr[2]": struct.unpack_from("<I", khdr, 8)[0],
        "0 (no xor)": 0,
    }

    fh = open(dat, "rb")
    for label, key in keys.items():
        for delta in (-1, 0, 1):
            hit = tot = 0
            for idx in SAMPLE:
                start, A, _end, B, h, _a, _b = recs[idx]
                off = (start + delta) * SECTOR
                if off < 0 or off + 64 > size:
                    continue
                fh.seek(off)
                blob = bytearray(fh.read(64))
                buffer_xor_decrypt(blob, key)
                tot += 1
                if sane(bytes(blob), A, B):
                    hit += 1
            print(f"{label:<22} delta={delta:+d}  header ok {hit:>4}/{tot}")
    fh.close()


if __name__ == "__main__":
    main()
