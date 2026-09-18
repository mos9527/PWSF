"""Probe: are FONT/*.xpr and Text/*.txp encrypted with the same name_hash scheme?

Prints the first bytes raw and after buffer_xor_decrypt(name_hash(stem)), so we
can tell by magic which (if either) is the plaintext.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash, buffer_xor_decrypt

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
HEAD = 64


def show(tag: str, b: bytes) -> None:
    hexs = " ".join(f"{x:02x}" for x in b)
    txt = "".join(chr(x) if 32 <= x < 127 else "." for x in b)
    print(f"    {tag:9s} {hexs}")
    print(f"    {'':9s} |{txt}|")


def main() -> None:
    for sub in ("FONT", "Text"):
        for f in sorted((GAME / sub).glob("*")):
            raw = f.read_bytes()[:HEAD]
            key = name_hash(f.stem)
            dec = bytes(buffer_xor_decrypt(bytearray(raw), key))
            print(f"{sub}/{f.name}  size={f.stat().st_size}  key={key:#010x}")
            show("raw", raw[:32])
            show("decrypted", dec[:32])
            print()


if __name__ == "__main__":
    main()
