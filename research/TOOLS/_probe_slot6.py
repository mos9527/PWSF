"""SLOT.DAT payload: XOR(container key) then zlib inflate -- try it.

slotdat_load_and_verify @ 0x1400A6290 reads one SLOT.KEY record, calls
buffer_xor_decrypt(v5, B << 12, name_hash(g_mount_table_ptr + 208)) on the
first B sectors, then -- for the remaining (end - start - B) sectors --
buffer_xor_decrypt again with the SAME key and hands the result to
sub_140119F10, whose state comes from sub_14011A030, i.e.
sub_14045B030(v, "1.2.3.f_pw", 88) -> windowBits 15, alloc 9544, window at
+1352 = zlib inflate.  So the payload is XOR-encrypted zlib.

This probe decrypts a handful of whole records with name_hash("002aba34")
and looks for (a) a record header and (b) an inflateable stream.
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
ZSIG = (b"\x78\x9c", b"\x78\xda", b"\x78\x01", b"\x78\x5e")


def load_key(path: Path):
    buf = bytearray(path.read_bytes())
    buffer_xor_decrypt(buf, name_hash(path.stem))
    n = (len(buf) - HDR) // REC
    out = []
    for i in range(n):
        w0, w1, h, a, b = struct.unpack_from("<IIIII", buf, HDR + REC * i)
        out.append((w0 & MASK20, w0 >> 20, w1 & MASK20, w1 >> 20, h, a, b))
    return bytes(buf[:HDR]), out


def main() -> None:
    root = C.require_game() / "MLG" / "disc0_rel"
    _hdr, recs = load_key(C.pristine(root / "002aba34.KEY"))
    dat = C.pristine(root / "002aba34.DAT")
    print(f"key={KEY:#010x}  records={len(recs)}")

    picks = [0, 1, 2, 3, 100, 500, 1000, 1500, 2000, len(recs) - 1]
    with open(dat, "rb") as fh:
        for idx in picks:
            start, _A, end, B, h, _a, _b = recs[idx]
            nsec = end - start
            fh.seek(start * SECTOR)
            buf = bytearray(fh.read(nsec * SECTOR))
            buffer_xor_decrypt(buf, KEY)
            blob = bytes(buf)
            print(f"\n--- rec {idx}: start={start} end={end} nsec={nsec} A={_A} B={B} "
                  f"hash={h:#010x}")
            print(f"    head[0:48] {blob[:48].hex(' ')}")
            print(f"    at B      {blob[B * SECTOR:B * SECTOR + 32].hex(' ')}")

            sigs = [o for o in range(0, 256)
                    if blob[o:o + 2] in ZSIG]
            print(f"    zlib magic in head: {sigs[:8]}")
            tail = blob[B * SECTOR:]
            tsig = [o for o in range(0, 256) if tail[o:o + 2] in ZSIG]
            print(f"    zlib magic at tail: {tsig[:8]}")

            for label, off in [("head+0", 0), ("head+16", 16), ("head+32", 32),
                               ("tail+0", B * SECTOR), ("tail+16", B * SECTOR + 16),
                               ("tail+32", B * SECTOR + 32)] + \
                              [(f"head+{o}", o) for o in sigs[:4]]:
                try:
                    d = zlib.decompressobj()
                    out = d.decompress(blob[off:off + 4 << 20])
                    ok = len(out)
                except zlib.error as exc:
                    print(f"    inflate {label:<10} -> error {exc}")
                    continue
                print(f"    inflate {label:<10} -> {ok} bytes, "
                      f"unused={len(d.unused_data)}")


if __name__ == "__main__":
    main()
