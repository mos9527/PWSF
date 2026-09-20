"""SLOT.DAT payload XOR: re-measure the correction and test the shift hypotheses.

Everything here is key-free where it can be.  All 2,137 records start with the
same 8 ciphertext bytes, i.e. every record is XORed with the *same* keystream
from record offset 0, so for any two records i, j and byte p:

    plain_i[p] ^ plain_j[p] == cipher_i[p] ^ cipher_j[p]

The "guess" keystream is buffer_xor_decrypt's, key = name_hash("002aba34"),
the key slotdat_load_and_verify @ 0x1400A6290 literally passes.  Under it the
record header does not make sense, so define the correction

    delta[p] = real_ks[p] ^ guess_ks[p]

Four bytes of it are pinned by _probe_slot10 / _probe_slot12 (2,137 records):

    delta[0x0a] = 0x1f   (+0x08 comp size, high byte of byte 2)
    delta[0x0b] = 0x6f   (comp >> 24 == 0)
    delta[0x0e] = 0xba   (+0x0c raw size, tracks A)
    delta[0x0f] = 0xe6   (raw >> 24 == 0)

Bytes 0x10/0x11 are constant across all records (the zlib stream starts there),
so delta[0x10] = dec[0x10] ^ 0x78 and delta[0x11] = dec[0x11] ^ FLG.

Hypotheses tested here:
  H0  no XOR at all (the IO layer already cancelled the verify layer)
  H1  a second pass over the same stream at a byte shift s:
          delta[p] == guess_ks[p + s] ^ guess_ks[p]
  H2  a second pass over the same stream at a *dword* shift (covered by H1)
  H3  the tail of a block is zero padding -> ciphertext there == real keystream
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
KEY = name_hash("002aba34")
ZSIG = (b"\x78\x9c", b"\x78\xda", b"\x78\x01", b"\x78\x5e")
SHIFT_LIMIT = 8 << 20          # 8 MiB of keystream to search the shift over


def load_key(path: Path):
    buf = bytearray(path.read_bytes())
    buffer_xor_decrypt(buf, name_hash(path.stem))
    n = (len(buf) - HDR) // REC
    out = []
    for i in range(n):
        w0, w1, h, a, b = struct.unpack_from("<IIIII", buf, HDR + REC * i)
        out.append((w0 & MASK20, w0 >> 20, w1 & MASK20, w1 >> 20, h, a, b))
    return out


def guess_stream(nbytes: int) -> bytes:
    nd = nbytes >> 2
    mt = MT19937(KEY)
    mt.advance(20)
    return struct.pack("<%dI" % nd, *[(mt.next() ^ XOR_CONST) for _ in range(nd)])


def main() -> None:
    root = C.require_game() / "MLG" / "disc0_rel"
    recs = load_key(C.pristine(root / "002aba34.KEY"))
    dat = C.pristine(root / "002aba34.DAT")
    n = len(recs)
    print(f"key={KEY:#010x}  records={n}  size={dat.stat().st_size:#x}")
    print(f"first: {[(s, A, e, B) for s, A, e, B, _h, _a, _b in recs[:4]]}")
    print(f"last : {[(s, A, e, B) for s, A, e, B, _h, _a, _b in recs[-2:]]}")

    with open(dat, "rb") as fh:
        head = []
        for s, _A, _e, _B, _h, _a, _b in recs:
            fh.seek(s * SECTOR)
            head.append(fh.read(32))
        tails = {}
        for i in (0, 1, 2, 3, 100, 500, 1000, 2000, n - 1):
            s, _A, _e, B, _h, _a, _b = recs[i]
            fh.seek((s + B) * SECTOR - 32)
            tails[i] = fh.read(32)

    ks = guess_stream(max(SHIFT_LIMIT + 64, 64))

    dec = []
    for blob in head:
        b = bytearray(blob)
        buffer_xor_decrypt(b, KEY)
        dec.append(bytes(b))

    print("\n== sample records: raw / guess-decrypted head")
    for i in (0, 1, 2, 100, 1000, n - 1):
        s, A, e, B, _h, _a, _b = recs[i]
        print(f"  rec {i:<5} start={s} end={e} A={A} B={B}")
        print(f"    raw {head[i][:32].hex(' ')}")
        print(f"    dec {dec[i][:32].hex(' ')}")

    print("\n== H0: is the block already plaintext?")
    for i in (0, 1, 100, 1000):
        sigs = [o for o in range(0, 24) if head[i][o:o + 2] in ZSIG]
        print(f"  rec {i:<5} zlib magic in raw head at {sigs}")

    print("\n== pinned correction bytes")
    c10 = {dec[i][0x0a] ^ (((recs[i][3] * SECTOR - 16) >> 16) & 0xFF) for i in range(n)}
    c11 = {dec[i][0x0b] for i in range(n)}
    c14 = {dec[i][0x0e] ^ (recs[i][1] >> 4) for i in range(n) if recs[i][1] & 0xF}
    c15 = {dec[i][0x0f] for i in range(n)}
    for name, s_ in (("delta[0x0a]", c10), ("delta[0x0b]", c11),
                     ("delta[0x0e]", c14), ("delta[0x0f]", c15)):
        print(f"  {name}: {sorted(hex(v) for v in s_)}")
    d16 = {d[0x10] for d in dec}
    d17 = {d[0x11] for d in dec}
    print(f"  dec[0x10] candidates: {sorted(hex(v) for v in d16)}"
          f"  -> delta[0x10] = {[hex(v ^ 0x78) for v in sorted(d16)]}")
    print(f"  dec[0x11] candidates: {sorted(hex(v) for v in d17)}"
          f"  -> delta[0x11] = "
          f"{[(hex(v), hex(v ^ f)) for v in sorted(d17) for f in (0x9c,)]}")

    print("\n== H1: delta[p] == ks[p+s] ^ ks[p]  (byte shift search)")
    try:
        import numpy as np
    except ImportError:
        np = None
    if np is None:
        print("  numpy missing, skipping")
        return
    k = np.frombuffer(ks, dtype=np.uint8)
    lim = len(k) - 20
    tgt = {10: 0x1f, 11: 0x6f, 14: 0xba, 15: 0xe6}
    mask = np.ones(lim, dtype=bool)
    for p, v in tgt.items():
        mask &= (k[p:p + lim] ^ k[p + 1:p + 1 + lim]) == v
    hits = np.nonzero(mask)[0] + 1
    print(f"  shift candidates: {len(hits)}  {hits[:16].tolist()}")

    print("\n== H3: block tails (raw / dec), looking for zero padding")
    for i, blob in tails.items():
        s, A, e, B, _h, _a, _b = recs[i]
        b = bytearray(blob)
        buffer_xor_decrypt(b, KEY)
        print(f"  rec {i:<5} B={B}")
        print(f"    raw {blob.hex(' ')}")
        print(f"    dec {bytes(b).hex(' ')}")


if __name__ == "__main__":
    main()
