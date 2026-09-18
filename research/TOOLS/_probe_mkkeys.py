"""Probe: collect every distinct group/entry key so we can reverse them via str_hash24."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash
from pwsf_olang import load

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
from pwsf import config
OUT = config.ANALYSIS_DIR / "_keys.txt"

keys = set()
for sub in ("MLG/Text", "EXLANG/Text"):
    for f in sorted((GAME / sub.replace("/", "\\")).glob("*.olang")):
        tbl = load(f, name_hash(f.stem))
        for g in tbl.groups:
            keys.add(g.key)
        for e in tbl.entries:
            keys.add(e.key)
OUT.write_text("\n".join(f"{k}" for k in sorted(keys)), encoding="utf-8")
print(f"{len(keys)} distinct keys -> {OUT}")
