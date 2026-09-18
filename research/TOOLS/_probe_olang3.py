"""Probe: olang serialiser round-trip, over all 17 shipped tables.

Two levels:
  exact  -- original str_off + pool verbatim, must be BYTE-IDENTICAL
  rebuilt-- freshly laid out deduplicated pool, must be LOGICALLY IDENTICAL
            (same strings for every group/entry/key triple) and must survive
            a re-encrypt / re-decrypt round trip
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash, buffer_xor_decrypt
from pwsf_olang import parse, string_at
from pwsf_olang_build import OlangBuilder

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")


def triples(tbl):
    """(group key, entry key, lang key) -> string, for the whole table."""
    out = {}
    for g in tbl.groups:
        for ei in range(g.entry_start, g.entry_start + g.entry_count):
            e = tbl.entries[ei]
            for ki in range(e.key_start, e.key_start + e.key_count):
                k = tbl.keys[ki]
                out[(g.key, e.key, k[0], ki)] = (string_at(tbl, k[1]), k[2])
    return out


def check(path: Path) -> bool:
    key = name_hash(path.stem)
    plain = bytes(buffer_xor_decrypt(bytearray(path.read_bytes()), key))
    tbl = parse(plain, str(path))
    b = OlangBuilder(tbl)

    exact = b.serialize_exact()
    ok_exact = exact == plain

    rebuilt = b.serialize()
    re_tbl = parse(rebuilt)
    ok_logic = triples(re_tbl) == triples(tbl)

    cipher = bytes(buffer_xor_decrypt(bytearray(rebuilt), key))
    ok_crypto = bytes(buffer_xor_decrypt(bytearray(cipher), key)) == rebuilt

    delta = len(rebuilt) - len(plain)
    status = "OK " if (ok_exact and ok_logic and ok_crypto) else "FAIL"
    print(f"{status} {path.name:<16} {len(plain):>8} -> {len(rebuilt):>8} "
          f"({delta:+7})  exact={'Y' if ok_exact else 'N'} "
          f"logic={'Y' if ok_logic else 'N'} crypto={'Y' if ok_crypto else 'N'} "
          f"strings={len(tbl.keys)}")
    return ok_exact and ok_logic and ok_crypto


def main() -> None:
    results = []
    for sub in ("MLG/Text", "EXLANG/Text"):
        for f in sorted((GAME / sub.replace("/", "\\")).glob("*.olang")):
            results.append(check(f))
    print()
    if not all(results):
        raise SystemExit(f"{results.count(False)}/{len(results)} FAILED")
    print(f"all {len(results)} tables round-trip clean")


if __name__ == "__main__":
    main()
