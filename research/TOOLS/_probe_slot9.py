"""Find the SLOT.DAT payload keystream phase -- without knowing the key.

Two observations make this possible even though name_hash("002aba34") does not
decrypt the payload:

1. The keystream is per-record (reseeded), because the first 8 ciphertext
   bytes are identical across all 2,137 records yet the decrypted header
   fields still line up with A/B (see below).  So for any two records
       plain_i[p] ^ plain_j[p] == cipher_i[p] ^ cipher_j[p]

2. Header layout from slotdat_load_and_verify @ 0x1400A6290:
       u16 @ +0x02  header size      (sub_140119EB0)
       u32 @ +0x08  compressed size  (sub_14002A530, source length of
                                      zlib uncompress via sub_140119EC0)
       u32 @ +0x0c  uncompressed size (sub_140037CB0, compared with the
                                      byte count uncompress produced)
   So the decrypted +0x0c must land in the sector bucket given by A, i.e.
       (A-1)*4096 < raw <= A*4096
   and +0x08 must fit in the B sectors on disk.

_probe_slot8 showed name_hash("002aba34") fails all of that, but the byte at
+0x0a (raw >> 16) and +0x0e (comp >> 16) each differ from the value the
keystream produces by a *constant* -- 0xba and 0x1f -- which means the layout
is right and only the keystream is off.  The most likely cause is a different
mt_advance: buffer_xor_decrypt hard-wires advance(20) = skip 5 outputs, while
the archive path (sub_14010F8B0/sub_14010F5C0) takes the skip as an argument.

So: sweep the output index the keystream starts at and score each by how many
records get a self-consistent header.
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config as C
from pwsf.crypto import MT19937, XOR_CONST, name_hash

SECTOR = 4096
HDR, REC = 12, 20
MASK20 = (1 << 20) - 1
MAX_SKIP = 300000

SAMPLE = list(range(0, 2137, 91))[:24]


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


def main() -> None:
    root = C.require_game() / "MLG" / "disc0_rel"
    recs = load_key(C.pristine(root / "002aba34.KEY"))
    dat = C.pristine(root / "002aba34.DAT")

    picks = [(i, *recs[i][:2], recs[i][3]) for i in SAMPLE]  # idx, start, A, B
    with open(dat, "rb") as fh:
        ciph = []
        for idx, start, _A, _B in picks:
            fh.seek(start * SECTOR)
            ciph.append(fh.read(16))

    # MT output stream for the container key, no advance applied
    mt = MT19937(name_hash("002aba34"))
    outs = [mt.next() for _ in range(MAX_SKIP + 8)]
    print(f"key={name_hash('002aba34'):#010x}  outs={len(outs)}  sample={len(picks)}")

    ci = [int.from_bytes(c, "little") for c in ciph]
    best = []
    for s in range(0, MAX_SKIP):
        probe = 0
        for d in range(4):
            probe |= ((outs[s + d] ^ XOR_CONST) & 0xFFFFFFFF) << (32 * d)
        hit = 0
        for k, (_idx, _st, A, B) in enumerate(picks):
            v = ci[k] ^ probe
            hdr = (v >> 16) & 0xFFFF
            comp = (v >> 64) & 0xFFFFFFFF
            raw = (v >> 96) & 0xFFFFFFFF
            if (8 <= hdr <= 512 and 0 < comp <= B * SECTOR
                    and (A - 1) * SECTOR < raw <= A * SECTOR):
                hit += 1
        if hit:
            best.append((hit, s))
    best.sort(reverse=True)
    print(f"candidate start indices (hits, index): {best[:10]}")
    for hit, s in best[:5]:
        probe = 0
        for d in range(4):
            probe |= ((outs[s + d] ^ XOR_CONST) & 0xFFFFFFFF) << (32 * d)
        print(f"\n  start index {s}  ({hit}/{len(picks)} records)")
        for k, (idx, _st, A, B) in enumerate(picks):
            v = (ci[k] ^ probe).to_bytes(16, "little")
            print(f"    rec{idx:<5} A={A:<5} B={B:<5} "
                  f"{v.hex(' ')}  hdr={struct.unpack_from('<H', v, 2)[0]} "
                  f"comp={struct.unpack_from('<I', v, 8)[0]} "
                  f"raw={struct.unpack_from('<I', v, 12)[0]}")


if __name__ == "__main__":
    main()
