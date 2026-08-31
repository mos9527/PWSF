"""Probe: decrypt PDT/DAT archive headers with key = name_hash(basename)."""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash, MT19937, XOR_CONST

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw\MLG\disc0_rel")

FILES = ["00b2b475.PDT", "0076531d.DAT", "0001112d.PDT", "00b2b4b6.PDT", "002aba34.KEY"]


def hd(buf: bytes, n: int = 48) -> str:
    out = []
    for off in range(0, min(n, len(buf)), 16):
        c = buf[off:off + 16]
        out.append(f"    {off:04x}  {' '.join(f'{b:02x}' for b in c):<47}  "
                   + "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in c))
    return "\n".join(out)


for name in FILES:
    f = GAME / name
    if not f.exists():
        print(f"MISSING {f}")
        continue
    raw = bytearray(f.read_bytes())
    key = name_hash(f.stem)
    mt = MT19937(key)
    mt.advance(20)
    hdr = bytearray(raw[:40])
    for i in range(10):
        cur = int.from_bytes(hdr[4 * i:4 * i + 4], "little")
        hdr[4 * i:4 * i + 4] = ((cur ^ mt.next() ^ XOR_CONST) & 0xFFFFFFFF).to_bytes(4, "little")
    a, b = struct.unpack_from("<II", hdr, 0)
    c = struct.unpack_from("<I", hdr, 8)[0]
    cnt = struct.unpack_from("<H", hdr, 24)[0]
    print(f"\n=== {name} len={len(raw):#x} key=name_hash({f.stem!r})={key:#010x}")
    print(f"    hdr[0].lo={a:#x} hdr[0].hi={b:#x} dword@8={c:#x} entry_count@24={cnt}")
    print(hd(bytes(hdr)))
