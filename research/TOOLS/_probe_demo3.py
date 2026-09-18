"""Grep the disc0 `bgp` packages for the comic-cutscene line.

_probe_demo2 showed the four mode-0x100 disc0 containers hold nothing but
ext id 0x38 = `bgp` (86 + 608 + 219 + 2304 = 3217 of them).  Those are nested
packages -- 04_archive.md section 4 already noted entry 0 of 0001112d decrypts
to "SP$\\0\\0 ... 251922 PW_EN".

This probe decrypts every bgp payload, records its magic, and greps for the
screenshot line ("...give us an offshore plant..." / "PUT DOWN SOME ROOTS").
"""

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import archive as A, config as C

NEEDLES = [b"offshore", b"OFFSHORE", b"SOME ROOTS", b"some roots"]
CONTAINERS = ("0001112d.PDT", "00b2b475.PDT", "00b2b2a8.PDT", "00b2b4b6.PDT")


def scan(path: Path, magics: Counter) -> int:
    try:
        src = C.pristine(path)
        # archive_index_load caps n at 96; these four take another load path
        arc = A.parse(src.read_bytes(), path.stem, str(path), max_entries=100000)
    except (OSError, ValueError) as exc:
        print(f"{path.name}: {exc}")
        return 0
    hits = 0
    for key, slot in A.bst_sorted(arc):
        try:
            blob = A.read_entry(arc, slot)
        except (ValueError, NotImplementedError) as exc:
            print(f"  {path.name}[{slot}]: {exc}")
            continue
        magics[bytes(blob[:4])] += 1
        for needle in NEEDLES:
            at = blob.find(needle)
            if at >= 0:
                hits += 1
                print(f"  HIT {path.name} slot={slot} key={key:#010x} "
                      f"size={len(blob)} at={at:#x} magic={blob[:8]!r}")
                print("      " + repr(blob[max(0, at - 120):at + 200]))
                break
            u16 = needle.decode().encode("utf-16-le")
            at = blob.find(u16)
            if at >= 0:
                hits += 1
                print(f"  HIT-U16 {path.name} slot={slot} key={key:#010x} "
                      f"size={len(blob)} at={at:#x} magic={blob[:8]!r}")
                print("      " + repr(blob[max(0, at - 240):at + 400]))
                break
    return hits


def main() -> None:
    game = C.require_game()
    root = game / "MLG" / "disc0_rel"
    magics = Counter()
    total = 0
    for name in CONTAINERS:
        print(f"== {name}")
        total += scan(root / name, magics)
    print(f"\nmagics: {magics.most_common(20)}")
    print(f"hits: {total}")


if __name__ == "__main__":
    main()
