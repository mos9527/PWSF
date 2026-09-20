"""SLOT.DAT end to end: LCG unmask -> MT XOR -> zlib inflate.

The second layer (this is what 08_cutscene_text.md §5.5 was missing):

    d0, d1, d2 = the three dwords of the DECRYPTED SLOT.KEY 12-byte header
                 (sub_14008B330 reads it into sub_14008AE50()'s buffer and
                  decrypts it there with name_hash("002aba34"))
    v     = d1 ^ d0
    state = v | ((v ^ 0x6576) << 16)        <- sub_140123DB0 @ 0x140123DB0
    inc   = d2 * v

    io_cmd_dispatch @ 0x14045D600 case 0x10 hands those 12 bytes to the file
    object (+204 = state, +208 = inc, +212 = d2) and raises flag 0x40, which
    is the LCG branch of entry_payload_transform @ 0x140123E90:

        for each dword:  *p ^= state;  state = 48828125*state + inc

The first layer is buffer_xor_decrypt(v5, B << 12, name_hash("002aba34"))
from slotdat_load_and_verify @ 0x1400A6290.  Both are plain XOR, so they
commute and can be folded into one keystream; every record uses the same
keystream from record offset 0, so it is generated once and sliced.

Result: 16-byte record header, then a zlib stream (78 da), inflated into a
resource table (slotdat_find_res_entry @ 0x1400A61F0).

usage: _probe_slot18.py [--all] [--grep]
"""

import argparse
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config as C
from pwsf.crypto import MT19937, XOR_CONST, name_hash

SECTOR = 4096
HDR, REC = 12, 20
MASK20 = (1 << 20) - 1
KEY = name_hash("002aba34")
M = 48828125                 # 5**11
M32 = (1 << 32) - 1

try:
    import numpy as np
except ImportError:
    np = None


def load_key(path: Path):
    buf = bytearray(path.read_bytes())
    from pwsf.crypto import buffer_xor_decrypt
    buffer_xor_decrypt(buf, name_hash(path.stem))
    n = (len(buf) - HDR) // REC
    out = []
    for i in range(n):
        w0, w1, h, a, b = struct.unpack_from("<IIIII", buf, HDR + REC * i)
        out.append((w0 & MASK20, w0 >> 20, w1 & MASK20, w1 >> 20, h, a, b))
    return out


def second_layer(keypath: Path):
    """(state, inc) of the LCG, from the decrypted SLOT.KEY header."""
    hdr = bytearray(keypath.read_bytes()[:12])
    from pwsf.crypto import buffer_xor_decrypt
    buffer_xor_decrypt(hdr, KEY)
    d0, d1, d2 = struct.unpack("<3I", bytes(hdr))
    v = (d1 ^ d0) & M32
    state = (v | ((v ^ 0x6576) << 16)) & M32
    inc = (d2 * v) & M32
    return state, inc, (d0, d1, d2)


def keystreams(state: int, inc: int, nd: int):
    """LCG stream and MT stream, nd dwords each."""
    if np is not None:
        a = np.empty(nd, dtype=np.uint64)
        s = state
        # sequential, but only once for the whole file
        for i in range(nd):
            a[i] = s
            s = (M * s + inc) & M32
        lcg = a.astype(np.uint32)
    else:
        lcg = []
        s = state
        for _ in range(nd):
            lcg.append(s)
            s = (M * s + inc) & M32
        import array
        lcg = array.array("I", lcg)
    mt = MT19937(KEY)
    mt.advance(20)
    words = [(mt.next() ^ XOR_CONST) & M32 for _ in range(nd)]
    if np is not None:
        mtk = np.array(words, dtype=np.uint32)
    else:
        import array
        mtk = array.array("I", words)
    return lcg, mtk


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="every record")
    ap.add_argument("--grep", action="store_true", help="hunt the cutscene line")
    ap.add_argument("--needle", action="append", default=[],
                    help="extra needle (repeatable); implies --grep")
    args = ap.parse_args()
    if args.needle:
        args.grep = True

    root = C.require_game() / "MLG" / "disc0_rel"
    keypath = C.pristine(root / "002aba34.KEY")
    datpath = C.pristine(root / "002aba34.DAT")
    recs = load_key(keypath)
    state, inc, (d0, d1, d2) = second_layer(keypath)
    print(f"SLOT.KEY header d0={d0:#010x} d1={d1:#010x} d2={d2:#010x}")
    print(f"LCG state={state:#010x} inc={inc:#010x}  (M = 48828125 = 5**11)")

    nd = max(r[3] for r in recs) * SECTOR // 4 + 16
    lcg, mtk = keystreams(state, inc, nd)
    print(f"keystream {nd} dwords ({nd * 4 / 1048576:.1f} MiB)")

    picks = range(len(recs)) if args.all else \
        [0, 1, 2, 3, 4, 100, 500, 1000, 1500, 2000, len(recs) - 1]

    ok = bad = 0
    hits = []
    with open(datpath, "rb") as fh:
        for i in picks:
            s, A, e, B, h, _a, _b = recs[i]
            fh.seek(s * SECTOR)
            blob = fh.read(B * SECTOR)
            n = len(blob) >> 2
            if np is not None:
                arr = np.frombuffer(blob[:4 * n], dtype=np.uint32) \
                    ^ lcg[:n] ^ mtk[:n]
                plain = arr.tobytes()
            else:
                plain = bytes(x ^ y ^ z for x, y, z in
                              zip(struct.unpack("<%dI" % n, blob[:4 * n]),
                                  lcg[:n], mtk[:n]))
            magic, hdr_size = struct.unpack_from("<HH", plain, 0)
            comp, raw = struct.unpack_from("<II", plain, 8)
            good = (hdr_size == 16 and plain[16:18] == b"\x78\xda"
                    and 0 < comp <= B * SECTOR
                    and (A - 1) * SECTOR < raw <= A * SECTOR)
            if good:
                ok += 1
            else:
                bad += 1
            if not args.all or i in (0, 1, len(recs) - 1) or not good:
                print(f"  rec {i:<5} start={s:<7} A={A:<4} B={B:<4} "
                      f"magic={magic:#06x} hdr={hdr_size} comp={comp} "
                      f"raw={raw} z={plain[16:18].hex()} "
                      f"{'OK' if good else 'BAD'}")
            if not good:
                continue
            try:
                out = zlib.decompress(plain[hdr_size:hdr_size + comp])
            except zlib.error as exc:
                print(f"          inflate failed: {exc}")
                bad += 1
                ok -= 1
                continue
            if not args.all:
                cnt = struct.unpack_from("<I", out, 0)[0]
                print(f"          inflate {len(out)} bytes "
                      f"(raw={raw}) res_count={cnt}")
                print(f"          head {out[:48].hex(' ')}")
            if args.grep:
                low = out.lower()
                for needle in ([n.encode() for n in args.needle]
                               if args.needle else
                               [b"willing to give", b"offshore", b"roots",
                                b"peace walker", b"miller"]):
                    p = low.find(needle)
                    if p >= 0:
                        hits.append((i, needle.decode(), p,
                                     out[max(0, p - 40):p + 80]))

    print(f"\n{ok} good / {bad} bad")
    if args.grep:
        print(f"{len(hits)} text hit(s)")
        for i, needle, p, snip in hits[:40]:
            print(f"  rec {i} {needle!r} @{p:#x}: {snip!r}")


if __name__ == "__main__":
    main()
