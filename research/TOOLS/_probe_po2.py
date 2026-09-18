"""Probe: validate the exported .po set against the binary it came from.

Parses every generated file and, for each `#:` reference, resolves the slot back
to the game data and checks the msgid is character-for-character identical.
A syntax check alone would not catch an escaping bug; this does.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash, buffer_xor_decrypt
from pwsf_olang import parse, string_at
from pwsf_po import parse_po
from pwsf import config

GAME = config.GAME_DIR
PO = config.PO_DIR
EN = config.LANG_EN


def olang_slots() -> dict:
    out = {}
    for f in sorted((GAME / "MLG" / "Text").glob("*.olang")):
        # same pristine rule as the exporter -- if this read the installed file
        # instead, both sides would agree on our own translations and the check
        # would pass while the corpus was polluted
        src = config.pristine(f)
        tbl = parse(bytes(buffer_xor_decrypt(bytearray(src.read_bytes()),
                                             name_hash(f.stem))))
        for g in tbl.groups:
            for ei in range(g.entry_start, g.entry_start + g.entry_count):
                e = tbl.entries[ei]
                for ki in range(e.key_start, e.key_start + e.key_count):
                    if tbl.keys[ki][0] != EN:
                        continue
                    out[f"olang/{f.stem}/{g.key:#08x}/{e.key:#08x}"] = \
                        string_at(tbl, tbl.keys[ki][1]).decode("utf-8")
    return out


def codec_slots() -> dict:
    rows = config.BRIEFING_TSV.read_text(encoding="utf-8").splitlines()
    col = {n: i for i, n in enumerate(rows[0].split("\t"))}
    out = {}
    for r in rows[1:]:
        c = r.split("\t")
        if len(c) <= col["text"] or c[col["lang"]] != "en":
            continue
        ref = (f"codec/{c[col['group']]}/{c[col['sector']]}/"
               f"{c[col['off']]}/{c[col['line']]}")
        out[ref] = c[col["text"]].replace("\\n", "\n")
    return out


def main() -> None:
    slots = {}
    slots.update(olang_slots())
    slots.update(codec_slots())
    print(f"resolved {len(slots)} English slots from the game data")

    files = sorted(PO.rglob("*.po")) + [PO / "pwsf.pot"]
    problems, entries, refs, seen_refs = [], 0, 0, set()

    for f in files:
        try:
            parsed = parse_po(f)
        except ValueError as exc:
            problems.append(f"{f.name}: {exc}")
            continue
        if not parsed or parsed[0].msgid != "":
            problems.append(f"{f.name}: missing the empty-msgid header entry")
        for e in parsed[1:]:
            entries += 1
            if not e.msgid:
                problems.append(f"{f.name}:{e.lineno}: empty msgid")
            if not e.refs:
                problems.append(f"{f.name}:{e.lineno}: entry has no reference")
            for r in e.refs:
                refs += 1
                if f.suffix == ".po":
                    seen_refs.add(r)
                if r not in slots:
                    problems.append(f"{f.name}:{e.lineno}: unknown ref {r}")
                elif slots[r] != e.msgid:
                    problems.append(
                        f"{f.name}:{e.lineno}: msgid != source for {r}\n"
                        f"      po  {e.msgid!r}\n      bin {slots[r]!r}")

    print(f"parsed {len(files)} files, {entries} entries, {refs} references")

    non_empty = {k for k, v in slots.items() if v.strip()}
    missed = non_empty - seen_refs
    if missed:
        problems.append(f"{len(missed)} non-empty slots are in no .po, e.g. "
                        + ", ".join(sorted(missed)[:3]))
    print(f"coverage: {len(seen_refs)}/{len(non_empty)} non-empty slots exported")

    if problems:
        print(f"\n{len(problems)} PROBLEMS:")
        for p in problems[:15]:
            print("  " + p)
        raise SystemExit(1)
    print("all msgids match the source byte for byte")


if __name__ == "__main__":
    main()
