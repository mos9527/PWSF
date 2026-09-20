"""Fingerprint the SLOT.DAT record header key-free, then sweep key candidates.

Part 1 -- key-free.  Every record is XORed with the *same* keystream starting
at record offset 0 (proved by the 8 constant leading ciphertext bytes), so for
any two records i, j and byte p:

    plain_i[p] ^ plain_j[p] == cipher_i[p] ^ cipher_j[p]

Whatever the key is, that relation holds.  So we can test structural claims
about the header without knowing the key:

  * byte 0x0e should be (raw >> 16) with raw in the sector bucket A
    -> dec[0x0e] ^ (A >> 4) must be a constant across all 2,137 records
  * byte 0x0a should be (comp >> 16) with comp <= B * 4096
    -> dec[0x0a] ^ ((B * 4096 - 16) >> 16) must be a constant

Part 2 -- sweep candidate keys with the full header test
    u16@+2 in [8,512];  u32@+8 <= B*4096;  (A-1)*4096 < u32@+12 <= A*4096
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


def load_key(path: Path):
    buf = bytearray(path.read_bytes())
    buffer_xor_decrypt(buf, name_hash(path.stem))
    n = (len(buf) - HDR) // REC
    out = []
    for i in range(n):
        w0, w1, h, a, b = struct.unpack_from("<IIIII", buf, HDR + REC * i)
        out.append((w0 & MASK20, w0 >> 20, w1 & MASK20, w1 >> 20, h, a, b))
    return out


def main() -> None:
    root = C.require_game() / "MLG" / "disc0_rel"
    recs = load_key(C.pristine(root / "002aba34.KEY"))
    dat = C.pristine(root / "002aba34.DAT")
    n = len(recs)

    with open(dat, "rb") as fh:
        raw16 = []
        for start, _A, _e, _B, _h, _a, _b in recs:
            fh.seek(start * SECTOR)
            raw16.append(fh.read(16))
    dec16 = []
    for blob in raw16:
        b = bytearray(blob)
        buffer_xor_decrypt(b, name_hash("002aba34"))
        dec16.append(bytes(b))

    print(f"== part 1: key-free fingerprint over {n} records")
    for p, label, fn in ((0x0e, "raw>>16  vs A>>4", lambda r: r[1] >> 4),
                         (0x0a, "comp>>16 vs (B*4096-16)>>16",
                          lambda r: ((r[3] * SECTOR - 16) >> 16) & 0xFF),
                         (0x0a, "comp>>16 vs (B*4096)>>16",
                          lambda r: (r[3] * SECTOR >> 16) & 0xFF)):
        vals = {dec16[i][p] ^ (fn(recs[i]) & 0xFF) for i in range(n)}
        print(f"  byte {p:#04x} {label:<32} distinct={len(vals)} "
              f"{sorted(hex(v) for v in vals)[:6]}")

    print("  per-byte distinct value counts (first 32 bytes):")
    print("    " + " ".join(f"{p:02x}:{len({d[p] for d in dec16}):<4}"
                            for p in range(32)))

    print("\n== part 2: key sweep")
    names = ("002aba34", "SLOT", "SLOT.DAT", "SLOT.KEY", "slot", "slot.dat",
             "STAGEDAT", "BGM", "VOICEBF", "VOICERT", "VOICEPS", "BRIEFING",
             "0076531d", "009645fa", "0001112d", "00b2b2a8", "00b2b4b6",
             "00b2b475", "USRDIR", "PSP_GAME", "disc0", "host0", "prx",
             "dlc", "mpg", "modules", "CAMO", "ADEMO", "ADEMOHQ", "stage",
             "MGSPW", "PW", "PEACE", "WALKER", "METAL", "packfile", "pack",
             "data", "disc0_rel")
    cands = {f"name_hash({s})": name_hash(s) for s in names}
    cands["0"] = 0
    cands["1"] = 1
    cands["~key"] = name_hash("002aba34") ^ 0xFFFFFFFF
    cands["key+1"] = (name_hash("002aba34") + 1) & 0xFFFFFFFF
    cands["XOR_CONST"] = 0xB9D3018F

    sample = range(0, n, 37)
    for label, key in cands.items():
        hit = tot = 0
        for i in sample:
            _s, A, _e, B, _h, _a, _b = recs[i]
            b = bytearray(raw16[i][:16])
            buffer_xor_decrypt(b, key)
            v = bytes(b)
            hdr = struct.unpack_from("<H", v, 2)[0]
            comp, rawsz = struct.unpack_from("<II", v, 8)
            tot += 1
            if (8 <= hdr <= 512 and 0 < comp <= B * SECTOR
                    and (A - 1) * SECTOR < rawsz <= A * SECTOR):
                hit += 1
        if hit:
            print(f"  {label:<24} {key:#010x}  {hit}/{tot}")


if __name__ == "__main__":
    main()
