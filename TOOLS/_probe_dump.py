"""Probe: export every olang table to a TSV so we can locate UI / CODEC text."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash
from pwsf_olang import load, string_at

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
OUT = Path(r"d:\PWSF\ANALYSIS\_dump_olang.tsv")

LANG = {0x0D0E: "en", 0x0D32: "fr", 0x0D45: "de", 0x0D94: "it", 0x0DB0: "ja", 0x0ED0: "es"}


def esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")


def main() -> None:
    rows = []
    for sub in ("MLG/Text", "EXLANG/Text"):
        d = GAME / sub.replace("/", "\\")
        for f in sorted(d.glob("*.olang")):
            tbl = load(f, name_hash(f.stem))
            for gi, g in enumerate(tbl.groups):
                for ei in range(g.entry_start, g.entry_start + g.entry_count):
                    if ei >= len(tbl.entries):
                        continue
                    e = tbl.entries[ei]
                    for ki in range(e.key_start, e.key_start + e.key_count):
                        if ki >= len(tbl.keys):
                            continue
                        k, off, meta, _pad = tbl.keys[ki]
                        lang = LANG.get(k, f"u{k:#x}")
                        txt = string_at(tbl, off).decode("utf-8", "replace")
                        rows.append(f"{sub}/{f.name}\t{tbl.table_id:#x}\t{g.key:#x}\t{e.key:#x}\t"
                                    f"{lang}\t{meta:#x}\t{esc(txt)}")
    OUT.write_text("\n".join(rows), encoding="utf-8")
    print(f"wrote {len(rows)} rows -> {OUT}")
    for r in rows[:15]:
        print("  " + r[:180])


if __name__ == "__main__":
    main()
