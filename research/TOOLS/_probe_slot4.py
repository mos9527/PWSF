"""Find the key that decrypts SLOT.DAT record payloads.

_probe_slot3 showed every record in 002aba34.DAT starts with the SAME raw
bytes (63 4c 9e 66 24 f4 0f f3 .. 66 74 .. de 55 20 cf 79 76), so the payload
keystream is container-wide, not per record -- but name_hash("002aba34") is
not it (the result has no recognisable structure).

The obvious remaining candidate is the 12-byte SLOT.KEY header itself
(ba be 9e c7 b1 c1 41 df b9 43 6a b0 = three u32), since a file literally
named .KEY holding a key would explain why the pair ships together.

This probe tries those, plus name_hash of every plausible name, and scores
each candidate by how much printable text and how many known magics appear.
"""

import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config as C
from pwsf.crypto import buffer_xor_decrypt, name_hash

SECTOR = 4096
REC, HDR = 20, 12
PRINTABLE = re.compile(rb"[ -~]{6,}")
MAGICS = (b"SP", b"OggS", b"\x89PNG", b"XPR2", b"SP$", b"DAR", b"QAR")


def keystream(key: int, nbytes: int) -> bytes:
    buf = bytearray(nbytes)
    buffer_xor_decrypt(buf, key)
    return bytes(buf)


def xor(data: bytes, pad: bytes) -> bytes:
    return (int.from_bytes(data, "little")
            ^ int.from_bytes(pad[:len(data)], "little")).to_bytes(len(data), "little")


def load_key(path: Path):
    buf = bytearray(path.read_bytes())
    buffer_xor_decrypt(buf, name_hash(path.stem))
    n = (len(buf) - HDR) // REC
    recs = [struct.unpack_from("<HHHHIII", buf, HDR + REC * i) for i in range(n)]
    return bytes(buf[:HDR]), recs


def score(blob: bytes) -> tuple:
    runs = PRINTABLE.findall(blob)
    longest = max((len(r) for r in runs), default=0)
    printable = sum(1 for c in blob if 32 <= c < 127) / len(blob)
    return len(runs), longest, round(printable, 3)


def main() -> None:
    root = C.require_game() / "MLG" / "disc0_rel"
    hdr, recs = load_key(C.pristine(root / "002aba34.KEY"))
    print(f"SLOT.KEY header: {hdr.hex(' ')}")

    with open(C.pristine(root / "002aba34.DAT"), "rb") as fh:
        samples = []
        for i in (0, 1, 500, 1500):
            start, _, _, _, h, _, nsec = recs[i]
            fh.seek(start * SECTOR)
            samples.append((i, h, fh.read(min(nsec, 8) * SECTOR)))

    cands = {}
    for i, v in enumerate(struct.unpack("<III", hdr)):
        cands[f"SLOT.KEY hdr[{i}]"] = v
    for nm in ("002aba34", "002aba34.DAT", "002aba34.KEY", "SLOT", "SLOT.DAT",
               "SLOT.KEY", "slot", "disc0:/PSP_GAME/USRDIR/002aba34.DAT"):
        cands[f"name_hash({nm})"] = name_hash(nm)
    cands["0"] = 0
    for i, h, _ in samples:
        cands[f"rec{i}.hash"] = h

    maxlen = max(len(s[2]) for s in samples)
    print(f"\n{'candidate':<42} {'key':<12} runs/longest/printable per sample")
    for label, key in cands.items():
        pad = keystream(key, maxlen)
        cols, magic = [], []
        for i, _h, raw in samples:
            blob = xor(raw, pad)
            cols.append(score(blob))
            magic += [m.decode("latin1") for m in MAGICS if blob[:8].startswith(m)]
        print(f"{label:<42} {key:#010x}  "
              + "  ".join(f"{c[0]:>4}/{c[1]:>4}/{c[2]:.3f}" for c in cols)
              + ("  magic=" + ",".join(magic) if magic else ""))

    print("\nfirst 32 bytes of sample 0 under each candidate:")
    for label, key in cands.items():
        pad = keystream(key, 64)
        print(f"  {label:<42} {xor(samples[0][2][:32], pad).hex(' ')}")


if __name__ == "__main__":
    main()
