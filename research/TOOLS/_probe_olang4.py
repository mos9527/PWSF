"""Probe: is a line break in olang a real 0x0A, or the two characters '\\' 'n'?

_probe_dump.py escapes real newlines as "\\n" when writing the TSV, and escapes
a literal backslash as "\\\\", so the TSV alone cannot tell the two apart at a
glance.  Check the raw pool bytes instead -- the answer decides what a
translation has to emit.
"""

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash, buffer_xor_decrypt
from pwsf_olang import parse, string_at

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")


def main() -> None:
    total = Counter()
    sample = None
    for sub in ("MLG/Text", "EXLANG/Text"):
        for f in sorted((GAME / sub.replace("/", "\\")).glob("*.olang")):
            tbl = parse(bytes(buffer_xor_decrypt(bytearray(f.read_bytes()),
                                                 name_hash(f.stem))))
            for k in tbl.keys:
                s = string_at(tbl, k[1])
                total["strings"] += 1
                if b"\x0a" in s:
                    total["real LF (0x0A)"] += 1
                    if sample is None:
                        sample = (f.name, s)
                if b"\\n" in s:
                    total["literal backslash-n"] += 1
                if b"\x0d" in s:
                    total["CR (0x0D)"] += 1
                if b"\\" in s:
                    total["any backslash"] += 1

    for k, v in total.items():
        print(f"{k:<24} {v}")
    if sample:
        print(f"\nsample from {sample[0]}:")
        print(f"  {sample[1]!r}")


if __name__ == "__main__":
    main()
