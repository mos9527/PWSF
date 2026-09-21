"""Probe: the Steam version's save directory `mgspw_savedata_win`.

Why: two in-game screenshots still show English where the patch already has
translations --

  1. the save slot list shows "Opening / Investigate the Supply Facility"
     (translated in both src/slot/slot_12.po and src/stage/stage_02.po)
  2. an in-mission radio subtitle (Miller)
     "There's no one around - why not try some shooting practice?"
     which is in NO extracted corpus (09 §1)

Question this probe answers: is #1 static text (a table we can write) or is it
baked into the save file the player just wrote?  If it is in the save file, the
string is a *copy*, not corpus, and no amount of table patching will change an
existing save.

Usage:  python _probe_savedata.py [--dir PATH] [--needle TEXT]...
"""
import argparse
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pwsf_crypto as C

DEFAULT = Path(r"C:\Program Files (x86)\Steam\steamapps\common"
               r"\MGS_PW\mgspw_savedata_win")

NEEDLES = [
    b"Investigate the Supply Facility",
    b"shooting practice",
    b"no one around",
]


def show(data: bytes, low: bytes, tag: str) -> list:
    out = []
    for nd in NEEDLES:
        start = 0
        while True:
            i = low.find(nd, start)
            if i < 0:
                break
            ctx = data[max(0, i - 40):i + len(nd) + 40]
            out.append((tag, nd.decode(), i, ctx))
            start = i + 1
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=str(DEFAULT))
    ap.add_argument("--needle", action="append", default=[])
    ap.add_argument("--max", type=int, default=64 << 20)
    args = ap.parse_args()
    NEEDLES.extend(n.lower().encode() for n in args.needle)

    root = Path(args.dir)
    hits = []
    for p in sorted(p for p in root.rglob("*") if p.is_file()):
        st = p.stat()
        ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime))
        data = p.read_bytes()[:args.max]
        low = data.lower()
        nz = [c for c in data] or [0]
        good = sum(1 for c in nz if 32 <= c < 127) / len(nz)
        runs = [m.group() for m in re.finditer(rb"[ -~]{24,}", data)][:3]
        print(f"{st.st_size:>10}  {ts}  {p.relative_to(root)}  "
              f"printable={good:.2f}  head={data[:4].hex()}  "
              f"{[r.decode('latin-1')[:48] for r in runs]}")
        for tag, blob in (("raw", data),
                          ("xor(name_hash)", bytes(C.buffer_xor_decrypt(
                              bytearray(data), C.name_hash(p.name))))):
            hits += [(str(p.relative_to(root)),) + h[:3]
                     for h in show(blob, blob.lower(), tag)]

    print("\nneedle hits:", hits or "none")
    for loc, tag, nd, off in hits:
        idx = off
        print(f"  {loc} [{tag}] {nd!r} @ {idx:#x}")


if __name__ == "__main__":
    main()
