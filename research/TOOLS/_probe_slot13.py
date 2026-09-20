"""Is the SLOT.DAT payload double-XORed?

The fingerprint from _probe_slot12 nails the record header:

    +0x00 u16  constant        bytes 00..07 all have exactly 1 distinct value
    +0x02 u16  header size     (constant)
    +0x04 u32  constant
    +0x08 u32  compressed size  byte 08 varies fully, byte 0b is constant
    +0x0c u32  uncompressed size byte 0c has only 16 distinct values
                                (raw is always a multiple of 16)
    +0x10      zlib stream      bytes 10..11 constant == 78 9c territory

but name_hash("002aba34") alone does not produce it, and neither does any
phase/xor-constant variant of the same MT stream (_probe_slot12).  The next
possibility is a second XOR layer with its own name_hash key -- the big
containers in this game carry an extra transform (04_archive.md section 6,
"mode 0x40", entry_payload_transform @ 0x140123E90).

So: for every string in the binary, test on-disk ^ KS(base) ^ KS(candidate).
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config as C
from pwsf.crypto import MT19937, XOR_CONST, buffer_xor_decrypt, name_hash

SECTOR = 4096
HDR, REC = 12, 20
MASK20 = (1 << 20) - 1
STRINGS = Path(__file__).resolve().parents[1] / "ANALYSIS" / "_strings.tsv"


def load_key(path: Path):
    buf = bytearray(path.read_bytes())
    buffer_xor_decrypt(buf, name_hash(path.stem))
    n = (len(buf) - HDR) // REC
    out = []
    for i in range(n):
        w0, w1, h, a, b = struct.unpack_from("<IIIII", buf, HDR + REC * i)
        out.append((w0 & MASK20, w0 >> 20, w1 & MASK20, w1 >> 20, h, a, b))
    return out


def ks16(key: int, skip: int) -> bytes:
    mt = MT19937(key)
    for _ in range(skip):
        mt.next()
    v = 0
    for d in range(4):
        v |= ((mt.next() ^ XOR_CONST) & 0xFFFFFFFF) << (32 * d)
    return v.to_bytes(16, "little")


def main() -> None:
    root = C.require_game() / "MLG" / "disc0_rel"
    recs = load_key(C.pristine(root / "002aba34.KEY"))
    dat = C.pristine(root / "002aba34.DAT")

    with open(dat, "rb") as fh:
        head = []
        for start, _A, _e, _B, _h, _a, _b in recs:
            fh.seek(start * SECTOR)
            head.append(fh.read(16))
    base = name_hash("002aba34")
    ks1 = ks16(base, 5)
    dec = [bytes(x ^ y for x, y in zip(h, ks1)) for h in head]

    strings = set()
    for line in STRINGS.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            try:
                raw = bytes.fromhex(parts[-1].strip())
            except ValueError:
                continue
            if raw:
                strings.add(raw.decode("latin-1"))
    game = C.require_game()
    for p in game.rglob("*"):
        if p.is_file():
            strings.add(p.stem)
            strings.add(p.name)
    for extra in ("002aba34", "SLOT", "SLOT.DAT", "SLOT.KEY", "slot",
                  "USRDIR", "PSP_GAME", "disc0", "host0"):
        strings.add(extra)
    strings = sorted(strings)
    print(f"candidates={len(strings)}")

    probe_idx = [0, 1, 2, 500, 1000, 2136]
    hits = []
    for s in strings:
        key2 = name_hash(s)
        for skip in (0, 5):
            ks2 = ks16(key2, skip)
            ok = 0
            for i in probe_idx:
                _st, A, _e, B, _h, _a, _b = recs[i]
                v = bytes(x ^ y for x, y in zip(dec[i], ks2))
                hdr = struct.unpack_from("<H", v, 2)[0]
                comp, rawsz = struct.unpack_from("<II", v, 8)
                if (8 <= hdr <= 512 and 0 < comp <= B * SECTOR
                        and (A - 1) * SECTOR < rawsz <= A * SECTOR):
                    ok += 1
            if ok == len(probe_idx):
                hits.append((s, skip, key2))
    print(f"hits: {len(hits)}")
    for s, skip, key2 in hits[:20]:
        print(f"  {s!r} skip={skip} key2={key2:#010x}")


if __name__ == "__main__":
    main()
