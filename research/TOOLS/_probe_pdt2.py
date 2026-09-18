"""Probe: decrypt PDT archive header + index + name table, check self-consistency."""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash, MT19937, XOR_CONST

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw\MLG\disc0_rel")


def xor_seq(buf: bytearray, mt: MT19937) -> None:
    n = len(buf)
    for i in range(n >> 2):
        cur = int.from_bytes(buf[4 * i:4 * i + 4], "little")
        buf[4 * i:4 * i + 4] = ((cur ^ mt.next() ^ XOR_CONST) & 0xFFFFFFFF).to_bytes(4, "little")
    rem = n & 3
    if rem:
        k = mt.next() ^ XOR_CONST
        off = n & ~3
        for j in range(rem):
            buf[off + j] ^= k & 0xFF
            k >>= 8


def probe(name: str, maxn: int = 200000) -> None:
    f = GAME / name
    raw = bytearray(f.read_bytes())
    key = name_hash(f.stem)
    mt = MT19937(key)
    mt.advance(20)
    hdr = bytearray(raw[:40])
    xor_seq(hdr, mt)
    lo, hi = struct.unpack_from("<II", hdr, 0)
    d8, d12, d16, d20 = struct.unpack_from("<4I", hdr, 8)
    cnt = struct.unpack_from("<H", hdr, 24)[0]
    print(f"\n=== {name} size={len(raw):#x} key={key:#010x}")
    print(f"    hdr: [0]={lo:#x}/{hi:#x} [8]={d8:#x} [12]={d12:#x} [16]={d16:#x} [20]={d20:#x} cnt@24={cnt}")
    if not (0 < cnt <= maxn):
        print("    -> count out of range, abort")
        return
    idx_n = 12 * cnt
    nam_n = 24 * cnt
    if 40 + idx_n + nam_n > len(raw):
        print(f"    -> 40+{idx_n:#x}+{nam_n:#x} exceeds file ({len(raw):#x})")
        return
    idx = bytearray(raw[40:40 + idx_n])
    xor_seq(idx, mt)
    nam = bytearray(raw[40 + idx_n:40 + idx_n + nam_n])
    xor_seq(nam, mt)
    print(f"    index[0..3]: " + ", ".join(
        str(struct.unpack_from("<3I", idx, 12 * i)) for i in range(min(4, cnt))))
    print(f"    names[0..3]: " + ", ".join(
        str(struct.unpack_from("<3Q", nam, 24 * i)) for i in range(min(4, cnt))))
    first = [struct.unpack_from("<Q", nam, 24 * i)[0] for i in range(cnt)]
    print(f"    names[0].q0 sorted ascending: {all(first[i] <= first[i+1] for i in range(cnt-1))}")


for n in ["00b2b475.PDT", "0001112d.PDT", "0076531d.DAT", "00b2b4b6.PDT"]:
    probe(n)
