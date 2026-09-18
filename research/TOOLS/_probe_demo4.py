"""What is inside a disc0 `bgp` (ext id 0x38) package?

_probe_demo3 decrypted all 3,217 of them and found no cutscene text, but that
result only counts if the bgp payload is plaintext rather than a further
compressed/encrypted layer.  This probe hexdumps the head of a few and lists
their printable runs so we can tell which it is.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import archive as A, config as C

PRINTABLE = re.compile(rb"[ -~]{8,}")


def hexdump(blob: bytes, n: int = 128) -> str:
    out = []
    for off in range(0, min(n, len(blob)), 16):
        row = blob[off:off + 16]
        hx = " ".join(f"{b:02x}" for b in row)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        out.append(f"    {off:04x}  {hx:<47}  {asc}")
    return "\n".join(out)


def show(path: Path, slots: int = 2) -> None:
    arc = A.parse(C.pristine(path).read_bytes(), path.stem, str(path),
                  max_entries=100000)
    print(f"== {path.name}  n={arc.count}")
    for key, slot in A.bst_sorted(arc)[:slots]:
        blob = A.read_entry(arc, slot)
        zeros = blob.count(0)
        print(f"  slot={slot} key={key:#010x} size={len(blob)} "
              f"zero_frac={zeros / len(blob):.3f}")
        print(hexdump(blob))
        runs = PRINTABLE.findall(blob[:0x20000])
        print(f"    printable runs in first 128 KiB: {len(runs)}")
        for r in runs[:25]:
            print(f"      {r[:90]!r}")


def main() -> None:
    root = C.require_game() / "MLG" / "disc0_rel"
    show(root / "0001112d.PDT")
    show(root / "00b2b4b6.PDT")


if __name__ == "__main__":
    main()
