"""Where does the comic-cutscene text live?

Screenshot evidence (2026-09-18): a drama/comic cutscene shows a balloon reading
"THEY'RE WILLING TO GIVE US AN OFFSHORE PLANT - A PLACE WE CAN FINALLY PUT DOWN
SOME ROOTS." plus a bottom subtitle "They're willing to give us an offshore
plant".  Neither string is in _dump_olang.tsv (137,358 rows) nor in
_briefing_lines.tsv, so the text comes from a container we have not mined.

This probe brute-forces the obvious candidate: MLG/disc0_rel/ADEMO/*.pdt
(the comic scene packages, 35 containers, mode 0x100 so payloads decrypt).
It prints the entry type breakdown (ext id in the key's high byte) and greps
every decrypted payload for the needle, in ASCII and UTF-16LE.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import archive as A, config as C, names as N

NEEDLES = [b"offshore", b"OFFSHORE", b"Offshore"]


def scan_dir(root: Path) -> None:
    files = sorted(root.glob("*.pdt"))
    print(f"== {root}  ({len(files)} containers)")
    ext_hist = {}
    hits = 0
    for f in files:
        try:
            arc = A.load(C.pristine(f))
        except ValueError as exc:
            print(f"  {f.name}: parse failed: {exc}")
            continue
        for key, slot in A.bst_sorted(arc):
            eid = key >> 24
            ext = "/".join(N.ID_EXTS.get(eid, [f"?{eid:#04x}"]))
            ext_hist[ext] = ext_hist.get(ext, 0) + 1
            try:
                blob = A.read_entry(arc, slot)
            except (ValueError, NotImplementedError) as exc:
                print(f"  {f.name}[{slot}] {ext}: {exc}")
                continue
            for needle in NEEDLES:
                at = blob.find(needle)
                if at >= 0:
                    hits += 1
                    print(f"  HIT {f.name} slot={slot} key={key:#010x} ext={ext} "
                          f"size={len(blob)} at={at:#x}")
                    print("      " + repr(blob[max(0, at - 80):at + 120]))
                at = blob.find(needle.decode().encode("utf-16-le"))
                if at >= 0:
                    hits += 1
                    print(f"  HIT-U16 {f.name} slot={slot} key={key:#010x} "
                          f"ext={ext} size={len(blob)} at={at:#x}")
                    print("      " + repr(blob[max(0, at - 160):at + 240]))
    print(f"  entry types: {sorted(ext_hist.items(), key=lambda kv: -kv[1])}")
    print(f"  hits: {hits}")


def main() -> None:
    game = C.require_game()
    scan_dir(game / "MLG" / "disc0_rel" / "ADEMO")


if __name__ == "__main__":
    main()
