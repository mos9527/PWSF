"""Probe: find the payload decryption chain for one archive entry.

Target: DLCBGM DBMINFO (0xd4 bytes) and DLCTEX TEXT, small enough to eyeball,
and the checksum field entry.b is available as an oracle via
entry_payload_unmask (0x140124000).
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pwsf_archive as A
from pwsf_crypto import MT19937, XOR_CONST, name_hash, buffer_xor_decrypt

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
TBL = [int(l, 16) for l in
       (Path(__file__).resolve().parent.parent / "ANALYSIS" / "_crc_table.txt")
       .read_text().split()]


def crc(state: int, buf: bytes) -> int:
    v = (~state) & 0xFFFFFFFF
    for i in range(len(buf) & ~3):
        v = (TBL[(v ^ buf[i]) & 0xFF] ^ (v >> 8) ^ 0x3FC47CDA) & 0xFFFFFFFF
    return (~v) & 0xFFFFFFFF


def score(b: bytes) -> float:
    if not b:
        return 0.0
    good = sum(1 for c in b if 0x20 <= c < 0x7F or c in (0, 9, 10, 13))
    return good / len(b)


def mt_xor(blob: bytes, key: int) -> bytes:
    b = bytearray(blob)
    buffer_xor_decrypt(b, key)
    return bytes(b)


def byte_xor(blob: bytes, k: int) -> bytes:
    return bytes(c ^ (k & 0xFF) for c in blob)


def try_all(tag: str, blob: bytes, cands: dict):
    print(f"\n### {tag}  size={len(blob):#x}  raw head={blob[:16].hex(' ')}")
    best = []
    for label, fn in [
        ("raw", lambda d: d),
        ("byte(lo)", lambda d: byte_xor(d, cands["lo"])),
        ("mt(key)", lambda d: mt_xor(d, cands["key"])),
        ("mt(e.b)", lambda d: mt_xor(d, cands["b"])),
        ("byte(lo)+mt(key)", lambda d: mt_xor(byte_xor(d, cands["lo"]), cands["key"])),
        ("mt(key)+byte(lo)", lambda d: byte_xor(mt_xor(d, cands["key"]), cands["lo"])),
        ("byte(lo)+mt(e.b)", lambda d: mt_xor(byte_xor(d, cands["lo"]), cands["b"])),
        ("mt(e.b)+byte(lo)", lambda d: byte_xor(mt_xor(d, cands["b"]), cands["lo"])),
    ]:
        out = fn(blob)
        s = score(out)
        best.append((s, label, out))
        print(f"   {label:<18} score={s:.3f} head={out[:24].hex(' ')}")
    best.sort(key=lambda x: -x[0])
    s, label, out = best[0]
    print(f"   -> best {label} score={s:.3f}")
    return out


for rel, entry_off, entry_size in [
    (r"ms0\EU\DLCBGM\e41b91fb.PDT", 0x1000, 0xd4),
    (r"ms0\EU\DLCTEX\ad1af1fb.PDT", 0x1e000, 0x2800),
]:
    p = GAME / rel
    raw = p.read_bytes()
    arc = A.parse(raw, p.stem, str(p))
    blob = raw[entry_off:entry_off + entry_size]
    cands = {"lo": arc.lo, "hi": arc.hi, "b": 0, "key": arc.key}
    for nd in arc.nodes:
        e = arc.entries[nd.slot]
        if e.c == entry_off:
            cands["b"] = e.b
    try_all(f"{rel} @{entry_off:#x}", blob, cands)
