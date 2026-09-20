"""Where does the second layer's LCG state come from?  Test every candidate.

Established by now:
  * io_cmd_dispatch @ 0x14045D600 case 0x10 copies 8 bytes from
    sub_14008AE50() into file+204 (and 4 more into file+212) and sets the
    file flags to 0x40 when *(file+208) != 0 -- the LCG mode of
    entry_payload_transform @ 0x140123E90.
  * sub_14008AE50 @ 0x14008AE50 is `lea rax, xmmword_1410C7A10+0Ch`, and
    sub_14008B330 (the SLOT.KEY loader) reads the 12-byte .KEY header into
    exactly that address and decrypts it there with name_hash("002aba34").
    So (state, inc) = dword0, dword1 of the DECRYPTED SLOT.KEY header.
  * sub_140123DB0 @ 0x140123DB0 derives key material from a 40-byte packfile
    header:  v = d1 ^ d0;  state = v | ((v ^ 0x6576) << 16);  inc = d2 * v.
    sub_14008B7E0 uses it on the .DAT's own 40-byte header (sector 0).

The raw pair fails (predicts delta[0x0a..0x0b] = 4c 33, the payload says
1f 6f), so this probe sweeps every raw / derived combination from both
headers, at every dword phase, against the four correction bytes that the
payload itself pins:

    delta[0x0a..0x0b] = 1f 6f      delta[0x0e..0x0f] = ba e6

and, for survivors, the zlib magic at +0x10 (78 9c / 78 01 / 78 da / 78 5e).
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config as C
from pwsf.crypto import buffer_xor_decrypt, name_hash

SECTOR = 4096
KEY = name_hash("002aba34")
M = 48828125                # 5**11
M32 = (1 << 32) - 1
MEASURED = (0x1F, 0x6F, 0xBA, 0xE6)
MAGIC = (0x78, 0x9C)        # checked separately


def words(blob: bytes, n: int):
    return struct.unpack_from("<%dI" % n, blob, 0)


def candidate_pairs(ws, tag):
    """raw and sub_140123DB0-derived (state, inc) from three dwords."""
    out = []
    if len(ws) < 3:
        return out
    d0, d1, d2 = ws[0], ws[1], ws[2]
    out.append((tag + " raw(d0,d1)", d0, d1))
    out.append((tag + " raw(d1,d0)", d1, d0))
    out.append((tag + " raw(d0,d2)", d0, d2))
    out.append((tag + " raw(d2,d1)", d2, d1))
    out.append((tag + " raw(d1,d2)", d1, d2))
    out.append((tag + " raw(d2,d0)", d2, d0))
    v = (d1 ^ d0) & M32
    st = (v | ((v ^ 0x6576) << 16)) & M32
    inc = (d2 * v) & M32
    out.append((tag + " derived(state,inc)", st, inc))
    out.append((tag + " derived(inc,state)", inc, st))
    out.append((tag + " derived(v,inc)", v, inc))
    out.append((tag + " derived(v,d2)", v, d2))
    return out


def main() -> None:
    root = C.require_game() / "MLG" / "disc0_rel"
    keypath = C.pristine(root / "002aba34.KEY")
    datpath = C.pristine(root / "002aba34.DAT")

    keyhdr = bytearray(keypath.read_bytes()[:12])
    buffer_xor_decrypt(keyhdr, KEY)
    kw = words(bytes(keyhdr), 3)

    with open(datpath, "rb") as fh:
        s0 = bytearray(fh.read(64))
    buffer_xor_decrypt(s0, KEY)
    dw = words(bytes(s0[:40]), 10)

    print(f"SLOT.KEY header decrypted : {bytes(keyhdr).hex(' ')}")
    print(f"  d0={kw[0]:#010x} d1={kw[1]:#010x} d2={kw[2]:#010x}")
    print(f"SLOT.DAT sector 0 decrypted[0:40]: {bytes(s0[:40]).hex(' ')}")
    print(f"  h0={dw[0]:#010x} h1={dw[1]:#010x} h2={dw[2]:#010x} "
          f"h3={dw[3]:#010x} ...")
    print(f"DAT sector 0 raw[0:16]    : {bytes(s0[:16]).hex(' ')}")

    cands = candidate_pairs(kw, "KEY") + candidate_pairs(dw, "DAT")
    print(f"\n{len(cands)} (state, inc) candidates x phase 0..7")

    for tag, st0, inc in cands:
        for k0 in range(8):
            s = st0
            for _ in range(k0):
                s = (M * s + inc) & M32
            seq = []
            for _ in range(6):
                seq.append(s)
                s = (M * s + inc) & M32
            ks = b"".join(struct.pack("<I", v) for v in seq)
            if (ks[0x0a], ks[0x0b], ks[0x0e], ks[0x0f]) == MEASURED:
                print(f"  MATCH {tag:<24} phase={k0} state={st0:#010x} "
                      f"inc={inc:#010x}")
                print(f"        bytes[8..17] = {ks[8:18].hex(' ')}")

    print("\n(done)")


if __name__ == "__main__":
    main()
