"""Last structural attack on the SLOT.DAT payload keystream.

Proven key-free by _probe_slot10 (all 2,137 records):

    dec[0x0a] ^ (((B*4096) - 16) >> 16) == 0x1f      (one value, all records)
    dec[0x0e] ^ (A >> 4)                 == 0xba      (records with A & 0xf != 0)
    dec[0x0b]                            == 0x6f      (comp >> 24 == 0)
    dec[0x0f]                            == 0xe6      (raw  >> 24 == 0)

where dec = on-disk bytes XOR pwsf keystream(name_hash("002aba34")).

Since buffer_xor_decrypt @ 0x14010F4C0 == mt_seed(key) + mt_advance(20) +
(mt_next() ^ 0xB9D3018F), and sub_14010F8B0 (the split path) is the very same
seed+advance, the only freedom left is *which* output the stream starts at and
*which* constant is XORed.  This probe searches

    keystream'[d] = outs[s + d] ^ C

for s in [0, 2^20) and C unknown: the four known plaintext bytes pin the top
half of C for every s, and the two independent estimates must agree (16-bit
test), after which the recovered C gives the header size at +0x02 -- a third,
independent check.
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
LIMIT = 1 << 20
NDEEP = 64


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
        head = []
        for start, _A, _e, _B, _h, _a, _b in recs:
            fh.seek(start * SECTOR)
            head.append(fh.read(NDEEP))
    dec = []
    for blob in head:
        b = bytearray(blob)
        buffer_xor_decrypt(b, name_hash("002aba34"))
        dec.append(bytes(b))

    print(f"== fingerprint: distinct values per byte over {n} records")
    for lo in range(0, NDEEP, 16):
        print("   " + " ".join(f"{p:02x}:{len({d[p] for d in dec})}"
                               for p in range(lo, lo + 16)))

    # recovered constants
    print("\n== recovered keystream corrections")
    c14 = {dec[i][0x0e] ^ (recs[i][1] >> 4) for i in range(n) if recs[i][1] & 0xF}
    c10 = {dec[i][0x0a] ^ (((recs[i][3] * SECTOR) - 16) >> 16 & 0xFF)
           for i in range(n)}
    c11 = {dec[i][0x0b] for i in range(n)}
    c15 = {dec[i][0x0f] for i in range(n)}
    for name, s in (("c[0x0a]", c10), ("c[0x0b]", c11),
                    ("c[0x0e]", c14), ("c[0x0f]", c15)):
        print(f"   {name}: {[hex(v) for v in sorted(s)]}")
    if len(c10) != 1 or len(c14) != 1:
        print("   -> not constant, aborting")
        return
    K2, K3 = c10.pop(), c11.pop()
    K2b, K3b = c14.pop(), c15.pop()

    mt = MT19937(name_hash("002aba34"))
    outs = [mt.next() for _ in range(LIMIT + 8)]

    def b2(v):
        return (v >> 16) & 0xFF

    def b3(v):
        return (v >> 24) & 0xFF

    t2 = (K3 ^ b3(outs[7] ^ XOR_CONST)) << 8 | (K2 ^ b2(outs[7] ^ XOR_CONST))
    t3 = (K3b ^ b3(outs[8] ^ XOR_CONST)) << 8 | (K2b ^ b2(outs[8] ^ XOR_CONST))

    d0 = [struct.unpack_from("<I", dec[i], 0)[0] for i in range(8)]
    hits = []
    for s in range(LIMIT):
        hc_a = (outs[s + 2] >> 16) ^ t2
        hc_b = (outs[s + 3] >> 16) ^ t3
        if hc_a != hc_b:
            continue
        hc = hc_a & 0xFFFF
        hdr = ((d0[0] ^ outs[5] ^ XOR_CONST ^ outs[s]) >> 16) ^ hc
        if 8 <= hdr <= 512:
            hits.append((s, hc, hdr))
    print(f"\n== phase/constant search: {len(hits)} candidate(s)")
    for s, hc, hdr in hits[:20]:
        print(f"   s={s}  hi16(C)={hc:#06x}  hdr={hdr}")


if __name__ == "__main__":
    main()
