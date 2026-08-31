"""Probe: list the distinct language-key ids present in every shipped .olang."""
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash
from pwsf_olang import load

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")

NAMES = {
    0x0D0E: "en", 0x0D32: "fr", 0x0D45: "de/gr", 0x0D94: "it",
    0x0ED0: "es", 0x0DD2: "?", 0x0DB0: "ja",
}


def main() -> None:
    for sub in ("MLG/Text", "EXLANG/Text"):
        d = GAME / sub.replace("/", "\\")
        if not d.exists():
            continue
        for f in sorted(d.glob("*.olang")):
            tbl = load(f, name_hash(f.stem))
            c = Counter(k[0] for k in tbl.keys)
            desc = " ".join(f"{v:#06x}({NAMES.get(v, '?')})x{n}" for v, n in sorted(c.items()))
            print(f"{sub}/{f.name}  id={tbl.table_id:#x} groups={len(tbl.groups)} "
                  f"entries={len(tbl.entries)} keys={len(tbl.keys)} pool={len(tbl.pool)}")
            print(f"    lang keys: {desc}")


if __name__ == "__main__":
    main()
