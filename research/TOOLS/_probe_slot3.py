"""SLOT.DAT (002aba34.DAT, 544 MB): decrypt via the SLOT.KEY index and grep it.

Mount table @ 0x140e9d6e0 (208 B per slot, base pointer off_140EA4220):
slot 1 = 002aba34.DAT = SLOT.DAT, slot 13 = 002aba34.KEY = SLOT.KEY.
bigdat_load_and_verify @ 0x1400A6290 pins the stride: name_hash(base + 208).

_probe_slot2 cracked SLOT.KEY: plain buffer_xor_decrypt with
key = name_hash("002aba34"), then 12 B header + 2137 x 20 B records with
  +0x00 u16 start sector   +0x04 u16 end sector   +0x10 u32 sector count
and start[i+1] == end[i] on 2136/2136 consecutive pairs.

Every candidate decryption model here reuses ONE keystream: buffer_xor_decrypt
always seeds from the same key, so the first N bytes of its keystream are
identical for every call.  Generating it once turns 544 MB of MT19937 into a
single bulk xor.
"""

import re
import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config as C
from pwsf.crypto import buffer_xor_decrypt, name_hash

SECTOR = 4096
REC = 20
HDR = 12
NEEDLES = (b"offshore", b"OFFSHORE", b"SOME ROOTS", b"some roots", b"PUT DOWN")
PRINTABLE = re.compile(rb"[ -~]{6,}")


def keystream(key: int, nbytes: int) -> bytes:
    buf = bytearray(nbytes)
    buffer_xor_decrypt(buf, key)      # 0 ^ ks == ks
    return bytes(buf)


def xor(data: bytes, pad: bytes) -> bytes:
    n = len(data)
    return (int.from_bytes(data, "little")
            ^ int.from_bytes(pad[:n], "little")).to_bytes(n, "little")


def load_key(path: Path):
    buf = bytearray(path.read_bytes())
    buffer_xor_decrypt(buf, name_hash(path.stem))
    n = (len(buf) - HDR) // REC
    return [struct.unpack_from("<HHHHIII", buf, HDR + REC * i) for i in range(n)]


def score(blob: bytes) -> tuple:
    head = blob[:0x1000]
    printable = sum(1 for c in head if 32 <= c < 127) / len(head)
    return round(printable, 3), head.count(0), len(PRINTABLE.findall(head))


def main() -> None:
    root = C.require_game() / "MLG" / "disc0_rel"
    recs = load_key(C.pristine(root / "002aba34.KEY"))
    max_sec = max(r[6] for r in recs)
    total = sum(r[6] for r in recs)
    print(f"SLOT.KEY: {len(recs)} records, max {max_sec} sectors/record, "
          f"{total} sectors total")

    dat = C.pristine(root / "002aba34.DAT")
    size = dat.stat().st_size
    print(f"SLOT.DAT: {size} bytes = {size // SECTOR} sectors")

    key = name_hash(dat.stem)
    pad = keystream(key, max_sec * SECTOR)
    sector_pad = pad[:SECTOR] * max_sec

    with open(dat, "rb") as fh:
        # model A/B decision on the first few records
        for i in (0, 1, 2):
            start, _, _, _, h, _, nsec = recs[i]
            fh.seek(start * SECTOR)
            raw = fh.read(nsec * SECTOR)
            a = xor(raw, sector_pad)
            b = xor(raw, pad)
            print(f"  rec {i} sector={start} n={nsec} hash={h:#010x}")
            print(f"    raw        {score(raw)}  {raw[:24].hex(' ')}")
            print(f"    per-sector {score(a)}  {a[:24].hex(' ')}")
            print(f"    per-record {score(b)}  {b[:24].hex(' ')}")

        hits = 0
        magic_a, magic_b = Counter(), Counter()
        for i, r in enumerate(recs):
            start, _, _, _, h, _, nsec = r
            fh.seek(start * SECTOR)
            raw = fh.read(nsec * SECTOR)
            if len(raw) < nsec * SECTOR:
                print(f"  rec {i}: short read at sector {start}")
                continue
            for tag, blob, mag in (("sector", xor(raw, sector_pad), magic_a),
                                   ("record", xor(raw, pad), magic_b)):
                mag[blob[:4]] += 1
                for needle in NEEDLES:
                    at = blob.find(needle)
                    if at >= 0:
                        hits += 1
                        print(f"  HIT[{tag}] rec={i} sector={start} n={nsec} "
                              f"hash={h:#010x} at={at:#x}")
                        print("      " + repr(blob[max(0, at - 160):at + 260]))
                        break
        print(f"  magics per-sector: {magic_a.most_common(6)}")
        print(f"  magics per-record: {magic_b.most_common(6)}")
        print(f"  hits: {hits}")


if __name__ == "__main__":
    main()
