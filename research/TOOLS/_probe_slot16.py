"""The second layer's parameters live in the SLOT.KEY file header.

Chain (IDA):
  slotdat_stream_load @ 0x1400A6560 state 1
      -> io_submit_slot_read(..., v17 = sub_14008AE50(), ...)
  sub_14008AE50 @ 0x14008AE50
      return (char *)&xmmword_1410C7A10 + 12;
  io_cmd_dispatch @ 0x14045D600 case 0x10
      v28 = *(a2 + 40);                    // that same pointer
      *(v29 + 204) = *v28;                 // 8 bytes -> state (+204), inc (+208)
      *(v29 + 212) = v28[2];               // 4 bytes
      *(v21 + 8) |= *(v21 + 208) ? 0x40 : 0x100;

  Those are the two modes of entry_payload_transform @ 0x140123E90:
      0x40   per-dword LCG     s <- 48828125 * s + inc   (48828125 == 5**11)
      0x100  per-byte XOR with one byte

  And xmmword_1410C7A10 + 12 is exactly where sub_14008B330 (the SLOT.KEY
  loader) reads the 12-byte .KEY file header and decrypts it with
  name_hash("002aba34").  So the LCG state and increment are the first two
  dwords of the decrypted SLOT.KEY header.

This probe decrypts those 12 bytes, builds the LCG stream and checks it
against the correction that _probe_slot10/12/14 measured from the payload
itself (delta[0x0a..0x0b] = 1f 6f, delta[0x0e..0x0f] = ba e6).
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
M = 48828125                     # 5**11
M32 = (1 << 32) - 1


def load_key(path: Path):
    buf = bytearray(path.read_bytes())
    buffer_xor_decrypt(buf, name_hash(path.stem))
    n = (len(buf) - HDR) // REC
    out = []
    for i in range(n):
        w0, w1, h, a, b = struct.unpack_from("<IIIII", buf, HDR + REC * i)
        out.append((w0 & MASK20, w0 >> 20, w1 & MASK20, w1 >> 20, h, a, b))
    return out


def lcg(s0: int, inc: int, n: int):
    s = s0
    out = []
    for _ in range(n):
        out.append(s)
        s = (M * s + inc) & M32
    return out


def main() -> None:
    root = C.require_game() / "MLG" / "disc0_rel"
    keypath = C.pristine(root / "002aba34.KEY")
    datpath = C.pristine(root / "002aba34.DAT")
    recs = load_key(keypath)

    raw_hdr = keypath.read_bytes()[:12]
    hdr = bytearray(raw_hdr)
    buffer_xor_decrypt(hdr, KEY)
    w = struct.unpack("<3I", bytes(hdr))
    print(f"KEY header cipher : {raw_hdr.hex(' ')}")
    print(f"KEY header plain  : {bytes(hdr).hex(' ')}")
    print(f"  state(+204) = {w[0]:#010x}   inc(+208) = {w[1]:#010x}   "
          f"+212 = {w[2]:#010x}")
    print(f"  mode = {'LCG 0x40' if w[1] else 'byte-xor 0x100'}")

    with open(datpath, "rb") as fh:
        blob = {}
        for i in (0, 1, 2, 100, 1000, len(recs) - 1):
            s, _A, _e, B, _h, _a, _b = recs[i]
            fh.seek(s * SECTOR)
            blob[i] = fh.read(64)

    print("\n== predicted vs measured correction")
    for k0 in range(0, 4):
        st = lcg(w[0], w[1], 8 + k0)
        pred = st[k0:]
        ks = b"".join(struct.pack("<I", v) for v in pred)
        print(f"  phase k0={k0}: bytes[8..17] = {ks[:10].hex(' ')}")

    # measured: delta[0x0a]=0x1f delta[0x0b]=0x6f delta[0x0e]=0xba
    #           delta[0x0f]=0xe6 delta[0x10]=dec^0x78 delta[0x11]=dec^FLG
    st = lcg(w[0], w[1], 8)
    ks = b"".join(struct.pack("<I", v) for v in st)
    dec0 = bytearray(blob[0][:32])
    buffer_xor_decrypt(dec0, KEY)
    dec0 = bytes(dec0)
    print(f"  measured delta[0x0a..0x0b] = 1f 6f  -> LCG gives "
          f"{ks[0x0a]:#04x} {ks[0x0b]:#04x}")
    print(f"  measured delta[0x0e..0x0f] = ba e6  -> LCG gives "
          f"{ks[0x0e]:#04x} {ks[0x0f]:#04x}")
    print(f"  dec[0x10..0x11] = {dec0[0x10]:#04x} {dec0[0x11]:#04x} -> "
          f"plain = {dec0[0x10] ^ ks[0x10]:#04x} {dec0[0x11] ^ ks[0x11]:#04x}"
          f"   (zlib magic is 78 9c / 78 01 / 78 da / 78 5e)")

    print("\n== apply LCG + MT to whole records and inflate")
    for i in sorted(blob):
        s, A, e, B, _h, _a, _b = recs[i]
        with open(datpath, "rb") as fh:
            fh.seek(s * SECTOR)
            buf = bytearray(fh.read(B * SECTOR))
        nd = len(buf) >> 2
        st = lcg(w[0], w[1], nd)
        merged = int.from_bytes(bytes(buf[:4 * nd]), "little") ^ \
            int.from_bytes(struct.pack("<%dI" % nd, *st), "little")
        buf[:4 * nd] = merged.to_bytes(4 * nd, "little")
        buffer_xor_decrypt(buf, KEY)
        b = bytes(buf)
        magic, hdr_size = struct.unpack_from("<HH", b, 0)
        comp, raw = struct.unpack_from("<II", b, 8)
        print(f"  rec {i:<5} A={A} B={B} magic={magic:#06x} hdr={hdr_size} "
              f"comp={comp} raw={raw} (A*4096={A * SECTOR}) "
              f"zlib={b[hdr_size:hdr_size + 2].hex()}")
        if hdr_size == 16 and 0 < comp <= B * SECTOR:
            try:
                d = zlib.decompressobj()
                out = d.decompress(b[hdr_size:hdr_size + comp])
                print(f"          inflate -> {len(out)} bytes, "
                      f"head={out[:48].hex(' ')}")
            except zlib.error as exc:
                print(f"          inflate failed: {exc}")


if __name__ == "__main__":
    main()
