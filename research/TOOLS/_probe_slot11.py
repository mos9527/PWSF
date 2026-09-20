"""Brute-force the SLOT.DAT payload key over every string in the binary.

_probe_slot10 (part 1) proved key-free that the record header really is

    u32 @ +0x08  = compressed size   (its byte 0x0a tracks B)
    u32 @ +0x0c  = uncompressed size (its byte 0x0e tracks A)

and that name_hash("002aba34") is NOT the key (decrypting with it would put
comp >> 16 at 30 for a record that only has 21 sectors on disk).  So the key
is some other name_hash.  Every 32-bit key in this game is name_hash(<string>),
and every string the binary contains is already dumped in
ANALYSIS/_strings.tsv (address, length, hex).  Try them all.
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
STRINGS = Path(__file__).resolve().parents[1] / "ANALYSIS" / "_strings.tsv"


def load_key(path: Path):
    buf = bytearray(path.read_bytes())
    buffer_xor_decrypt(buf, name_hash(path.stem))
    n = (len(buf) - HDR) // REC
    out = []
    for i in range(n):
        w0, w1, h, a, b = struct.unpack_from("<IIIII", buf, HDR + REC * i)
        out.append((w0 & MASK20, w0 >> 20, w1 & MASK20, w1 >> 20, h, a, b))
    return out


def load_strings() -> list:
    out = []
    for line in STRINGS.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        try:
            raw = bytes.fromhex(parts[-1].strip())
        except ValueError:
            continue
        if not raw:
            continue
        out.append(raw.decode("latin-1"))
    return out


def main() -> None:
    root = C.require_game() / "MLG" / "disc0_rel"
    recs = load_key(C.pristine(root / "002aba34.KEY"))
    dat = C.pristine(root / "002aba34.DAT")
    n = len(recs)

    head = []
    with open(dat, "rb") as fh:
        for start, _A, _e, _B, _h, _a, _b in recs:
            fh.seek(start * SECTOR)
            head.append(fh.read(16))

    strings = sorted(set(load_strings()))
    print(f"records={n}  binary strings={len(strings)}")

    # every file basename on disk is a plausible name_hash input too
    game = C.require_game()
    disk = set()
    for p in game.rglob("*"):
        if p.is_file():
            disk.add(p.stem)
            disk.add(p.name)
    strings += sorted(disk)

    base = name_hash("002aba34")
    cands = {}

    def add(s):
        cands.setdefault(s, name_hash(s))

    for s in strings:
        add(s)
    for extra in ("002aba34", "SLOT", "SLOT.DAT", "SLOT.KEY", "slot",
                  "USRDIR", "PSP_GAME", "disc0", "host0", "MGSPW", "PW"):
        add(extra)
    cands["<0>"] = 0
    cands["<base>"] = base
    print(f"candidates={len(cands)}")

    probe_idx = [0, 1, 2, 500, 1000, 2136]
    def check(key: int) -> int:
        mt = MT19937(key)
        mt.advance(20)
        ks = 0
        for d in range(4):
            ks |= ((mt.next() ^ XOR_CONST) & 0xFFFFFFFF) << (32 * d)
        ks = ks.to_bytes(16, "little")
        ok = 0
        for i in probe_idx:
            _s, A, _e, B, _h, _a, _b = recs[i]
            v = bytes(x ^ y for x, y in zip(head[i], ks))
            hdr = struct.unpack_from("<H", v, 2)[0]
            comp, rawsz = struct.unpack_from("<II", v, 8)
            if (hdr and hdr <= 512 and 0 < comp <= B * SECTOR
                    and (A - 1) * SECTOR < rawsz <= A * SECTOR):
                ok += 1
        return ok

    hits = []
    for label, key in cands.items():
        if check(key):
            hits.append((check(key), label, key))
    hits.sort(reverse=True)
    print(f"hits: {len(hits)}")
    for ok, label, key in hits[:20]:
        print(f"  {ok}/{len(probe_idx)}  {label!r}  {key:#010x}")


if __name__ == "__main__":
    main()
