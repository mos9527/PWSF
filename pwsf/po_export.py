r"""Export the PWSF English corpus to gettext .po files for translation.

Source selection (measured by _probe_po1.py):

  MLG/Text/*.olang   14 tables, 2,789 non-empty English slots, 1,517 distinct
                     (46% duplicate rate -- merging by msgid saves real work)
  _briefing_lines.tsv  CODEC, 4,839 English lines, 4,746 distinct

  EXLANG/Text/*.olang is NOT a source: its English slots are all empty
  (it only carries Portuguese, written into the Spanish slot).

Entries are merged by msgid within each corpus, so one translation covers every
slot that shares the same English text; every slot is still listed as a `#:`
reference so the importer knows where to write back and the translator can see
the context.  Use --no-merge to get one entry per slot instead.

Output layout:

    PO/pwsf.pot            template, all entries, untranslated
    PO/olang/olang_NN.po   UI + in-game subtitles, chunked
    PO/codec/codec_NN.po   CODEC / BRIEFING dialogue, chunked
    PO/MANIFEST.tsv        chunk index with entry and character counts

Reference syntax, parseable back to a binary slot:

    olang/<table_id>/<group>/<entry>
    codec/<group>/<sector>/<off>/<line>

Newlines are REAL 0x0A in the source data (_probe_olang4.py), and .po escapes
them as \n in the usual way, so a translator sees and types normal line breaks.
"""

import argparse
from collections import OrderedDict
from pathlib import Path

from . import config
from .crypto import name_hash, buffer_xor_decrypt
from .olang import parse, string_at

LANG = config.LANG_KEYS
EN = config.LANG_EN

# Reference translations in the other shipped languages. Empty by default: they
# roughly triple the size of a .po and an LLM translator burns context on them
# without needing them. Pass --ref-langs fr,de,it,es to bring them back.
REF_LANGS = ()

HEADER = """\
msgid ""
msgstr ""
"Project-Id-Version: PWSF {part}\\n"
"Language: zh_CN\\n"
"MIME-Version: 1.0\\n"
"Content-Type: text/plain; charset=UTF-8\\n"
"Content-Transfer-Encoding: 8bit\\n"
"X-PWSF-Source: {source}\\n"
"X-PWSF-Entries: {count}\\n"
"""


# ------------------------------------------------------------------ po writing

def po_escape(s: str) -> str:
    return (s.replace("\\", "\\\\").replace('"', '\\"')
             .replace("\t", "\\t").replace("\r", "\\r"))


def po_string(s: str) -> str:
    """Render a python string as a .po string literal, split on newlines."""
    if "\n" not in s:
        return f'"{po_escape(s)}"'
    parts = s.split("\n")
    # a trailing newline leaves an empty last part; fold it into the previous
    # line rather than emitting a bare ""
    if parts and parts[-1] == "":
        parts.pop()
        parts[-1] += "\n"
    out = ['""']
    for i, p in enumerate(parts):
        nl = "\\n" if (i < len(parts) - 1 or p.endswith("\n")) else ""
        out.append(f'"{po_escape(p.rstrip(chr(10)))}{nl}"')
    return "\n".join(out)


def po_comment(tag: str, text: str) -> str:
    """A .po comment is line-oriented; every physical line needs the prefix.

    Split with splitlines() rather than on "\\n": 181 source strings contain a
    bare 0x0D (_probe_olang4.py), and a lone CR is still a line break to any
    reader, so splitting on "\\n" alone would emit an unprefixed line.
    """
    return "\n".join(f"{tag} {line}" for line in text.splitlines() or [""])


def write_po(path: Path, entries: list, part: str, source: str,
             translations: dict = None) -> None:
    translations = translations or {}
    lines = [HEADER.format(part=part, source=source, count=len(entries))]
    for e in entries:
        block = []
        for c in e["comments"]:
            block.append(po_comment("#.", c))
        for r in e["refs"]:
            block.append(f"#: {r}")
        if e["flags"]:
            block.append("#, " + ", ".join(e["flags"]))
        block.append("msgid " + po_string(e["msgid"]))
        msgstr = translations.get(e["msgid"], "")
        block.append("msgstr " + (po_string(msgstr) if msgstr else '""'))
        lines.append("\n".join(block))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n\n".join(lines) + "\n", encoding="utf-8")


# ------------------------------------------------------------------ collection

def collect_olang(ref_langs=REF_LANGS) -> list:
    """One record per English slot.

    Reads through config.pristine() so an installed build never leaks back in
    as source: the installers overwrite game files in place, and exporting the
    live copy would re-import our own translations as English.
    """
    out = []
    for f in sorted(config.TEXT_DIR.glob("*.olang")):
        src = config.pristine(f)
        tbl = parse(bytes(buffer_xor_decrypt(bytearray(src.read_bytes()),
                                             name_hash(f.stem))))
        for g in tbl.groups:
            for ei in range(g.entry_start, g.entry_start + g.entry_count):
                e = tbl.entries[ei]
                by_lang = {}
                for ki in range(e.key_start, e.key_start + e.key_count):
                    k = tbl.keys[ki]
                    by_lang[LANG.get(k[0], f"u{k[0]:#x}")] = \
                        string_at(tbl, k[1]).decode("utf-8")
                en = by_lang.get("en", "")
                if not en:
                    continue
                comments = [f"{lang}: {by_lang[lang]}"
                            for lang in ref_langs
                            if by_lang.get(lang) and by_lang[lang] != en]
                out.append(dict(
                    ref=f"olang/{f.stem}/{g.key:#08x}/{e.key:#08x}",
                    msgid=en, comments=comments,
                    sort=(f.stem, g.key, e.key)))
    return out


def collect_codec() -> list:
    rows = config.BRIEFING_TSV.read_text(encoding="utf-8").splitlines()
    head = rows[0].split("\t")
    col = {n: i for i, n in enumerate(head)}
    # No cross-language reference comments here: each language lives in its own
    # sector range and the alignment key between them is still unsolved
    # (03 号文档, 跨语言对齐), so there is no reliable way to pair an English
    # line with its French/German/Italian/Spanish counterpart.
    out = []
    seen = set()
    for r in rows[1:]:
        c = r.split("\t")
        if len(c) <= col["text"] or c[col["lang"]] != "en":
            continue
        if not c[col["text"]].strip():
            continue
        ref = (f"codec/{c[col['group']]}/{c[col['sector']]}/"
               f"{c[col['off']]}/{c[col['line']]}")
        if ref in seen:
            raise SystemExit(f"codec reference is not unique: {ref}")
        seen.add(ref)

        comments = []
        if c[col["speaker"]]:
            comments.append(f"speaker {c[col['speaker']]} "
                            f"voice {c[col['voice_ids']]}")
        if c[col["t_start"]]:
            comments.append(f"timeline {c[col['t_start']]}..{c[col['t_end']]}")
        out.append(dict(
            ref=ref, msgid=c[col["text"]].replace("\\n", "\n"),
            comments=comments,
            sort=(int(c[col["group"]]), int(c[col["sector"]]),
                  int(c[col["off"]], 0), int(c[col["line"]]))))
    out.sort(key=lambda e: e["sort"])
    return out


def collect_slot(ref_langs=REF_LANGS, only=None) -> list:
    """The olang tables embedded in SLOT.DAT (ANALYSIS/08 §5.7).

    Source is `_slot_olang_lines.tsv`, the product of
    research/TOOLS/_probe_slot25.py -- re-scanning the 544 MB container here
    would cost a minute every run and produce exactly the same rows.

    `only` = "cutscene" keeps just the comic-cutscene tables.

    There is no write-back for these yet (`pwsf.slotdat_build` does not
    exist), so this corpus is opt-in via --slot: exporting it into the default
    run would produce entries the installer cannot apply.
    """
    from . import slotdat
    unescape = slotdat.unescape

    path = config.SLOT_OLANG_TSV
    if not path.is_file():
        raise SystemExit(f"{path} is missing; run "
                         f"research/TOOLS/_probe_slot25.py first")
    rows = path.read_text(encoding="utf-8").splitlines()
    col = {n: i for i, n in enumerate(rows[0].split("\t"))}

    agg = {}
    order = []
    for r in rows[1:]:
        c = r.split("\t")
        if len(c) <= col["text"]:
            continue
        tid = int(c[col["table_id"]], 0)
        if only == "cutscene" and not slotdat.is_cutscene(tid):
            continue
        key = (tid, int(c[col["group"]], 0), int(c[col["entry"]], 0))
        if key not in agg:
            agg[key] = {}
            order.append(key)
        agg[key][c[col["lang"]]] = c[col["text"]]

    out = []
    for key in order:
        by_lang = agg[key]
        en = by_lang.get("en", "")
        if not en.strip():
            continue
        comments = [f"{lang}: {by_lang[lang]}"
                    for lang in ref_langs
                    if by_lang.get(lang) and by_lang[lang] != en]
        if slotdat.is_cutscene(key[0]):
            comments.append("comic cutscene")
        out.append(dict(
            ref=f"slot/{key[0]:#010x}/{key[1]:#08x}/{key[2]:#08x}",
            msgid=unescape(en), comments=comments, sort=key))
    out.sort(key=lambda e: e["sort"])
    return out


def merge(records: list, do_merge: bool) -> list:
    """Collapse records that share an msgid, keeping every reference."""
    merged = OrderedDict()
    for r in records:
        k = r["msgid"] if do_merge else (r["msgid"], r["ref"])
        if k not in merged:
            merged[k] = dict(msgid=r["msgid"], refs=[], comments=[],
                             flags=["c-format"] if "%" in r["msgid"] else [])
        m = merged[k]
        m["refs"].append(r["ref"])
        for c in r["comments"]:
            if c not in m["comments"]:
                m["comments"].append(c)
    return list(merged.values())


# ------------------------------------------------------------------ main

def chunk(entries: list, size: int) -> list:
    return [entries[i:i + size] for i in range(0, len(entries), size)]


def existing_translations(outdir: Path) -> dict:
    """msgid -> msgstr from every .po already under `outdir`.

    Re-exporting regenerates the whole tree, so without this every round
    would throw away whatever has been translated so far.  Keyed on msgid
    only: the exporter merges slots by msgid, and a source string that changed
    simply misses and comes back empty, which is the safe failure.
    """
    from .po import parse_po

    out = {}
    if not outdir.is_dir():
        return out
    for p in sorted(outdir.rglob("*.po")):
        for e in parse_po(p):
            if e.msgid and e.msgstr and e.msgid not in out:
                out[e.msgid] = e.msgstr
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--outdir", type=Path, default=config.PO_DIR)
    ap.add_argument("--chunk", type=int, default=config.PO_CHUNK,
                    help=f"entries per .po file (default {config.PO_CHUNK})")
    ap.add_argument("--no-merge", action="store_true",
                    help="one entry per slot instead of merging by msgid")
    ap.add_argument("--ref-langs", default="",
                    help="comma separated languages to include as #. reference "
                         "translations (default none, to keep files small)")
    ap.add_argument("--slot", choices=("all", "cutscene", "none"),
                    default="all",
                    help="export the olang tables embedded in SLOT.DAT "
                         "(default all; pwsf cannot install them yet, see "
                         "ANALYSIS/08 §8.1)")
    ap.add_argument("--fresh", action="store_true",
                    help="do not carry over msgstr from the existing .po files")
    args = ap.parse_args()
    config.require_game()

    backups = config.installed_backups()
    if backups:
        print(f"note: {len(backups)} game file(s) currently hold an installed "
              f"build; reading the .orig originals instead:")
        for b in backups:
            print(f"      {b.relative_to(config.GAME_DIR)}")

    ref_langs = tuple(x.strip() for x in args.ref_langs.split(",") if x.strip())
    do_merge = not args.no_merge
    corpora = [("olang", collect_olang(ref_langs)), ("codec", collect_codec())]
    if args.slot != "none":
        corpora.append(("slot", collect_slot(ref_langs, args.slot)))

    carry = {} if args.fresh else existing_translations(args.outdir)
    if carry:
        print(f"carrying over {len(carry)} existing translation(s)")

    manifest = ["file\tsource\tentries\trefs\tchars"]
    all_entries = []
    for name, records in corpora:
        entries = merge(records, do_merge)
        all_entries += entries
        parts = chunk(entries, args.chunk)
        print(f"{name}: {len(records)} slots -> {len(entries)} entries"
              f"{' (merged)' if do_merge else ''} -> {len(parts)} files")
        for i, part in enumerate(parts, 1):
            fn = args.outdir / name / f"{name}_{i:02d}.po"
            write_po(fn, part, f"{name} {i}/{len(parts)}", name, carry)
            refs = sum(len(e["refs"]) for e in part)
            chars = sum(len(e["msgid"]) for e in part)
            manifest.append(f"{fn.relative_to(args.outdir)}\t{name}\t"
                            f"{len(part)}\t{refs}\t{chars}")
            print(f"  {fn.relative_to(args.outdir)}  {len(part):>4} entries, "
                  f"{refs:>4} slots, {chars:>6} chars")

    pot = args.outdir / "pwsf.pot"
    write_po(pot, all_entries, "template", "+".join(n for n, _ in corpora))
    (args.outdir / "MANIFEST.tsv").write_text("\n".join(manifest) + "\n",
                                              encoding="utf-8")

    total_refs = sum(len(e["refs"]) for e in all_entries)
    total_chars = sum(len(e["msgid"]) for e in all_entries)
    print(f"\ntemplate {pot} ({len(all_entries)} entries)")
    print(f"total: {len(all_entries)} entries covering {total_refs} slots, "
          f"{total_chars} source characters")


if __name__ == "__main__":
    main()
