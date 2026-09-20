"""Solve the second (LCG) layer of the SLOT.DAT payload from the data itself.

Evidence (IDA):
  io_cmd_dispatch @ 0x14045D600 case 0x10 copies 8 bytes from the ctx handed
  in by slotdat_stream_load @ 0x1400A6560 (sub_14008AE50()) into file+204 /
  file+212 and then sets file+8 flags to 0x40 when *(file+208) != 0, else
  0x100.  Those are exactly the two modes of

      entry_payload_transform @ 0x140123E90

  whose 0x40 branch is a per-dword LCG

      s <- 48828125 * s + inc        (48828125 == 5**11)
      *(u32*)p ^= s;  p += 4

  and whose 0x100 branch XORs every byte with one byte.  The 0x100 branch
  would make the correction identical at every byte position -- it is not
  (delta[0x0a]=0x1f vs delta[0x0b]=0x6f), so if a second layer exists it is
  the LCG.

What the data pins (2,137 records, key-free, see _probe_slot10/12/14):
  s2 >> 16 == 0x6f1f        (+0x08 comp size)
  s3 >> 16 == 0xe6ba        (+0x0c raw size)
  s4 & 0xffff == delta[0x10] | delta[0x11] << 8   (+0x10 zlib magic 78 9c)

With s4 = (M+1)*s3 - M*s2 this is a linear congruence mod 2**16 in the two
unknown low halves, so every H = s3 & 0xffff gives exactly one
L = s2 & 0xffff -- 65,536 candidates, each checked against the real records.
"""

import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config as C
from pwsf.crypto import buffer_xor_decrypt, name_hash

SECTOR = 4096
HDR, REC = 12, 20
MASK20 = (1 << 20) - 1
KEY = name_hash("002aba34")
M = 48828125                       # 5**11, from entry_payload_transform
M32 = (1 << 32) - 1
FLGS = (0x9C, 0x01, 0xDA, 0x5E)    # zlib FLG with (0x78, FLG) a valid header


def load_key(path: Path):
    buf = bytearray(path.read_bytes())
    buffer_xor_decrypt(buf, name_hash(path.stem))
    n = (len(buf) - HDR) // REC
    out = []
    for i in range(n):
        w0, w1, h, a, b = struct.unpack_from("<IIIII", buf, HDR + REC * i)
        out.append((w0 & MASK20, w0 >> 20, w1 & MASK20, w1 >> 20, h, a, b))
    return out


def inv_mod(a, m=1 << 32):
    return pow(a, -1, m)


def main() -> None:
    root = C.require_game() / "MLG" / "disc0_rel"
    recs = load_key(C.pristine(root / "002aba34.KEY"))
    dat = C.pristine(root / "002aba34.DAT")

    picks = [0, 1, 2, 3, 100, 1000, 2000, len(recs) - 1]
    with open(dat, "rb") as fh:
        blobs = {}
        for i in picks:
            s, _A, _e, B, _h, _a, _b = recs[i]
            fh.seek(s * SECTOR)
            blobs[i] = bytearray(fh.read(B * SECTOR))
    dec = {}
    for i, b in blobs.items():
        buf = bytearray(b[:64])
        buffer_xor_decrypt(buf, KEY)
        dec[i] = bytes(buf)

    # correction at +0x10/+0x11 (constant over all 2,137 records)
    d16 = dec[0][0x10]
    d17 = dec[0][0x11]
    print(f"dec[0x10]={d16:#04x} dec[0x11]={d17:#04x}")
    print(f"delta[0x0a..0x0b]=1f 6f   delta[0x0e..0x0f]=ba e6")

    inv_m = inv_mod(M)
    const = ((M + 1) * 0xE6BA0000 - M * 0x6F1F0000) & M32
    a_coef = (M + 1) & 0xFFFF
    b_inv = inv_mod(M & 0xFFFF, 1 << 16)

    hits = []
    for flg in FLGS:
        want = ((d16 ^ 0x78) | ((d17 ^ flg) << 8)) & 0xFFFF
        t = (want - const) & 0xFFFF
        for H in range(1 << 16):
            L = ((a_coef * H - t) * b_inv) & 0xFFFF
            s2 = 0x6F1F0000 | L
            s3 = 0xE6BA0000 | H
            inc = (s3 - M * s2) & M32
            if ((M * s3 + inc) & 0xFFFF) != want:
                continue
            s1 = ((s2 - inc) * inv_m) & M32
            s0 = ((s1 - inc) * inv_m) & M32
            ok = 0
            for i in picks:
                _s, A, _e, B, _h, _a, _b = recs[i]
                w = struct.unpack_from("<5I", dec[i], 0)
                out = [w[k] ^ s for k, s in
                       enumerate((s0, s1, s2, s3, (M * s3 + inc) & M32))]
                hdr = out[0] >> 16
                comp, raw, z0 = out[2], out[3], out[4] & 0xFFFF
                if (hdr == 16 and z0 in (0x9C78, 0x0178, 0xDA78, 0x5E78)
                        and B * SECTOR - 4200 < comp <= B * SECTOR - 16
                        and (A - 1) * SECTOR < raw <= A * SECTOR):
                    ok += 1
            if ok == len(picks):
                hits.append((flg, s0, s1, s2, s3, inc))
                print(f"  HIT flg={flg:#04x} s0={s0:#010x} s1={s1:#010x} "
                      f"s2={s2:#010x} s3={s3:#010x} inc={inc:#010x}")

    print(f"\n{len(hits)} candidate(s)")
    for flg, s0, s1, s2, s3, inc in hits:
        i = picks[0]
        s, A, e, B, _h, _a, _b = recs[i]
        w = struct.unpack_from("<5I", dec[i], 0)
        out = [w[k] ^ v for k, v in
               enumerate((s0, s1, s2, s3, (M * s3 + inc) & M32))]
        print(f"  rec {i}: dwords {[hex(v) for v in out]}")
        # full stream and inflate test
        st = s0
        buf = bytearray(blobs[i])
        nd = len(buf) >> 2
        ks = []
        for _ in range(nd):
            ks.append(st)
            st = (M * st + inc) & M32
        merged = int.from_bytes(bytes(buf[:4 * nd]), "little") ^ \
            int.from_bytes(b"".join(struct.pack("<I", v) for v in
                                    (a ^ b for a, b in zip(ks, [0] * nd)))
                           if False else
                           struct.pack("<%dI" % nd, *ks), "little")
        buf[:4 * nd] = merged.to_bytes(4 * nd, "little")
        buf = bytearray(bytes(buf))
        buffer_xor_decrypt(buf, KEY)
        hdr_size = struct.unpack_from("<H", bytes(buf), 2)[0]
        comp, raw = struct.unpack_from("<II", bytes(buf), 8)
        try:
            d = zlib.decompressobj()
            out = d.decompress(bytes(buf[hdr_size:hdr_size + comp]))
            print(f"  inflate: {len(out)} bytes (raw says {raw}, A*4096="
                  f"{A * SECTOR}) head={out[:32].hex(' ')}")
        except zlib.error as exc:
            print(f"  inflate failed: {exc}")


if __name__ == "__main__":
    main()
