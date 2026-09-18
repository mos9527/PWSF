"""Entry-type census over every container, to locate the cutscene text.

The name table (and therefore the ext id in the key's high byte) decodes for
ALL containers, including the mode 0x40 ones whose payloads we cannot decrypt
yet.  So a type histogram tells us which container could hold caption/script
data even where we cannot read the bytes.

Of interest: ext id 0x35 = "cap", 0x02 = "gcx", 0x5d = "olang", 0x01 = "bin".
"""

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import archive as A, config as C, names as N

# archive_index_load enforces n <= 96; the big containers take another path,
# so raise the cap when probing (see 04_archive.md section 6 note 4).
MAX_ENTRIES = 100000


HEAD_CAP = 8 << 20      # tables are at most 36n bytes; 8 MiB covers n = 2304


def census(path: Path) -> None:
    src = C.pristine(path)
    try:
        with open(src, "rb") as fh:
            head = fh.read(HEAD_CAP)
    except OSError as exc:      # the running game holds some of these open
        print(f"{path.name:>16}  open failed: {exc}")
        return
    try:
        arc = A.parse(head, path.stem, str(path), max_entries=MAX_ENTRIES)
    except ValueError as exc:
        print(f"{path.name:>16}  parse failed: {exc}")
        return
    walk = A.bst_sorted(arc)
    hist = Counter()
    for key, _slot in walk:
        eid = key >> 24
        hist[eid] += 1
    label = "/".join(str(p) for p in path.parts[-2:])
    print(f"{label:<28} mode={arc.mode:#05x} n={arc.count:<6} walked={len(walk)}")
    for eid, cnt in hist.most_common():
        ext = "/".join(N.ID_EXTS.get(eid, ["?"]))
        print(f"    {eid:#04x} {ext:<12} {cnt}")


def main() -> None:
    game = C.require_game()
    for d in ("MLG", "EXLANG"):
        root = game / d / "disc0_rel"
        if not root.is_dir():
            continue
        for f in sorted(root.iterdir()):
            if f.is_file() and f.suffix.upper() in (".PDT", ".DAT"):
                census(f)


if __name__ == "__main__":
    main()
