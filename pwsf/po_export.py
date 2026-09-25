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

Output layout (these are the files you translate in):

    PO/olang/olang_NN.po   UI + in-game subtitles, chunked
    PO/codec/codec_NN.po   CODEC / BRIEFING dialogue, chunked
    PO/slot/slot_NN.po     olang tables embedded in SLOT.DAT, chunked
    PO/MANIFEST.tsv        chunk index with entry and character counts

    PO/pwsf.pot            only with --pot: every corpus merged into one file
                           with empty msgstr, for import into a translation
                           platform.  Off by default because it duplicates
                           every entry above, and neither po_lint nor
                           po_import reads it -- translating in it does
                           nothing.

Reference syntax, parseable back to a binary slot:

    olang/<table_id>/<group>/<entry>
    codec/<group>/<sector>/<off>/<line>
    slot/<table_id>/<group>/<entry>

Newlines are REAL 0x0A in the source data (_probe_olang4.py), and .po escapes
them as \n in the usual way, so a translator sees and types normal line breaks.
"""

import argparse
from collections import OrderedDict
from pathlib import Path

from . import config, slots
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


# One remark per corpus, written once at the top of its files.  Anything that
# applies to every single entry belongs here, not in the per-entry `#.` lines:
# those are repeated once per slot and drown the file.
NOTES = {
    "gtt": """\
GTT: in-mission radio and hint lines, from the GTT pools of SLOT.DAT
(ANALYSIS/11).  Rules for every entry here:
  - the block is re-laid-out when it is written back, so a translation may be
    LONGER than the English line -- it can grow into the bytes the suffix-merged
    fragments used to occupy.  `budget N B` is this line's share of that slack
    (English length + slack/n), and `po_lint` fails the build with
    `gtt-budget` when it is exceeded;
  - the game stores a line break as a two-character `\\n`, so keep the same
    number of lines as the source.
""",
}


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
             translations: dict = None, note: str = None) -> None:
    translations = translations or {}
    lines = [HEADER.format(part=part, source=source, count=len(entries))]
    if note:
        # one corpus-level remark, instead of repeating it on all N entries
        lines[0] += "\n".join(f"# {t}" for t in note.strip().splitlines()) + "\n"
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

def collect_olang(ref_langs=REF_LANGS, pixel: bool = False) -> list:
    """One record per English slot.

    Reads through config.pristine() so an installed build never leaks back in
    as source: the installers overwrite game files in place, and exporting the
    live copy would re-import our own translations as English.

    `pixel` keeps the slots whose key.meta == 1: those are drawn with the
    512x512 pixel atlas in Text/*.txp, which has no CJK glyphs, so they stay
    English by default (ANALYSIS/05_font.md §15).
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
                en_meta = None
                for ki in range(e.key_start, e.key_start + e.key_count):
                    k = tbl.keys[ki]
                    by_lang[LANG.get(k[0], f"u{k[0]:#x}")] = \
                        string_at(tbl, k[1]).decode("utf-8")
                    if k[0] == config.LANG_EN:
                        en_meta = k[2]
                en = by_lang.get("en", "")
                if not en:
                    continue
                if en_meta == slots.META_PIXEL_FONT and not pixel:
                    continue
                comments = [f"{lang}: {by_lang[lang]}"
                            for lang in ref_langs
                            if by_lang.get(lang) and by_lang[lang] != en]
                out.append(dict(
                    ref=f"olang/{f.stem}/{g.key:#08x}/{e.key:#08x}",
                    msgid=en, comments=comments,
                    sort=(f.stem, g.key, e.key)))
    return out


#: 英语台词里基本不会出现的重音/标点（é è 剔除：英文里 "coup d'état" 就有）
_FOREIGN_ACCENT = set("àâçêëîïôùûœñáíóúäöüß¿¡")

#: 2026-09-25 退役：曾用来给 `_codec_junk` 放行印刷体标点，而 `_codec_junk`
#: 本身已被 `n_text` 判据取代（03_codec.md §10.6）。


def _codec_wrong_lang(rows, col) -> set:
    """{(group, off)}：位置判据标成 en、实际是别种语言的 codec 记录。

    第二种记录格式（03 号文档 §10）的语言块边界和 LANG_BLOCKS 不完全重合：
    0x11f960 / 0x39a800 / 0x39b540 落在 en 的扇区范围里，台词却是法语
    （那里是法语副本）。按位置导出就会把法语当英文语料，译出来会写进法语
    槽位。判据：整条记录的停用词判据（`briefing.judge_lang`）明确指向非
    en（千分比 >= 400 且高于 en），**并且**至少含 2 个英语里不出现的重音
    字符 —— 两道门槛一起才判错标，实测 444 条 en 记录里命中 3 条、0 误伤。
    """
    import collections
    from pwsf import briefing as B

    by_rec = collections.defaultdict(list)
    for r in rows:
        c = r.split("\t")
        if len(c) > col["text"] and c[col["lang"]] == "en":
            by_rec[(c[col["group"]], c[col["off"]])].append(c[col["text"]])
    bad = set()
    for key, texts in by_rec.items():
        sc = collections.Counter()
        acc = 0
        for t in texts:
            lang, s = B.judge_lang(t)
            for k, v in s.items():
                sc[k] += v
            acc += sum(1 for ch in t if ch in _FOREIGN_ACCENT)
        tot = sum(sc.values()) or 1
        top = max(sc, key=lambda k: sc[k])
        if top != "en" and sc[top] * 1000 // tot >= 400 \
                and sc[top] > sc["en"] and acc >= 2:
            bad.add(key)
    return bad


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
    skip_rec = _codec_wrong_lang(rows[1:], col)
    for r in rows[1:]:
        c = r.split("\t")
        if len(c) <= col["text"] or c[col["lang"]] != "en":
            continue
        if (c[col["group"]], c[col["off"]]) in skip_rec:
            continue      # 位置判据标成 en、实际是别的语种，译了会写坏该槽
        if not c[col["text"]].strip():
            continue
        # 是不是台词由池的排布规则说了算，不靠「像不像台词」的启发式：
        # 池里的串 back-to-back 紧挨着，真表项满足
        # table[i+1] == table[i] + len + 1、末项不越出 off3；第一个破坏它的
        # 位置就是 `n_text`，其后的表项指进池后的二进制块
        # （03_codec.md §10.6，_probe_bri58.py：2062 条干净记录 0 例外）。
        # 这取代了原先的 U+FFFD / _codec_junk 两道猜测。
        if int(c[col["line"]]) >= int(c[col["n_text"]]):
            continue
        # 真台词里若夹着非法 UTF-8，写回时无法无损还原（U+FFFD 会被编码成
        # EF BF BD，改掉原本的字节）—— 这不是「不像台词」，是写不了，
        # 保持英文。全库 en 只 3 条，见 03_codec.md §10.6。
        if "\ufffd" in c[col["text"]]:
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


def collect_slot(ref_langs=REF_LANGS, only=None, pixel: bool = False) -> list:
    """The olang tables embedded in SLOT.DAT (ANALYSIS/08 §5.7).

    Source is `_slot_olang_lines.tsv`, the product of
    research/TOOLS/_probe_slot25.py -- re-scanning the 544 MB container here
    would cost a minute every run and produce exactly the same rows.

    `only` = "cutscene" keeps just the comic-cutscene tables.

    WRITE-BACK EXISTS: `pwsf.slotdat_build` rebuilds SLOT.DAT with the
    translations (ANALYSIS/08 §7), so these references are applied like any
    other and the corpus is on by default.
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
    meta_of = {}
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
        if c[col["lang"]] == "en":
            meta_of[key] = int(c[col["meta"]], 0)

    out = []
    for key in order:
        by_lang = agg[key]
        en = by_lang.get("en", "")
        if not en.strip():
            continue
        if meta_of.get(key) == slots.META_PIXEL_FONT and not pixel:
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


def collect_stage(ref_langs=REF_LANGS, pixel: bool = False) -> list:
    """The olang tables packed inside STAGEDAT (ANALYSIS/09 §4).

    Source is `_stage_olang_lines.tsv`, the product of `pwsf.stage` -- reading
    the 487 MB container here would mean decrypting and inflating every payload
    on each run.

    WRITE-BACK EXISTS: `pwsf.stage_build` rebuilds `009645fa.PDT` with the
    translations written into the `*_en.olang` members, so these references are
    applied like any other (ANALYSIS/09 §11).  The corpus is real player-facing
    text (mission info, stage telops, Mother Base staff comments, item and
    weapon text) and 10,570 of its strings exist nowhere else.
    """
    path = config.STAGE_OLANG_TSV
    if not path.is_file():
        raise SystemExit(f"{path} is missing; run `python -m pwsf.stage` first")
    rows = path.read_text(encoding="utf-8").splitlines()
    col = {n: i for i, n in enumerate(rows[0].split("\t"))}

    agg, meta_of, order = {}, {}, []
    for r in rows[1:]:
        c = r.split("\t")
        if len(c) <= col["text"]:
            continue
        key = (int(c[col["rec"]]), c[col["file"]],
               int(c[col["group"]], 0), int(c[col["entry"]], 0))
        if key not in agg:
            agg[key] = {}
            order.append(key)
        agg[key][c[col["lang"]]] = c[col["text"]]
        if c[col["lang"]] == "en":
            meta_of[key] = int(c[col["meta"]], 0)

    out = []
    for key in order:
        by_lang = agg[key]
        en = by_lang.get("en", "")
        if not en.strip():
            continue
        if meta_of.get(key) == slots.META_PIXEL_FONT and not pixel:
            continue
        comments = [f"{lang}: {by_lang[lang]}"
                    for lang in ref_langs
                    if by_lang.get(lang) and by_lang[lang] != en]
        comments.append(f"STAGEDAT entry {key[0]}, {key[1]} -- written back by "
                        f"pwsf.stage_build into 009645fa.PDT")
        out.append(dict(
            ref=str(slots.StageRef(*key)),
            msgid=en.replace("\\n", "\n"), comments=comments, sort=key))
    out.sort(key=lambda e: e["sort"])
    return out


def collect_gtt() -> list:
    """The GTT pools of SLOT.DAT (ANALYSIS/11): in-mission radio / hint lines.

    462 pools in records 0..365 -- text no other corpus has: the briefing,
    radio and advice lines that play while you are in a mission.  It only came
    to light because `slotdat_find_res_entry` @ 0x1400A61F0 filters resource
    ids to the 0x20000000 class and these pools are 0x1c??????.

    Source is `_gtt_lines.tsv`, the product of `python -m pwsf.gtt`.

    WRITABLE: `pwsf.gtt` re-lays the block out when it writes back, so a
    translation MAY be longer in bytes than the English line -- it grows into
    the slack the suffix-merged fragments used to occupy (ANALYSIS/11 §5.2).
    `budget` is this line's share of that slack; see `po_lint`'s `gtt-budget`.
    """
    from . import gtt
    from .slotdat import unescape

    path = config.GTT_TSV
    if not path.is_file():
        raise SystemExit(f"{path} is missing; run `python -m pwsf.gtt` first")
    rows = path.read_text(encoding="utf-8").splitlines()
    col = {n: i for i, n in enumerate(rows[0].split("\t"))}

    out, seen = [], set()
    for r in rows[1:]:
        c = r.split("\t")
        if len(c) <= col["text"]:
            continue
        key = (int(c[col["pool"]], 0), int(c[col["block"]], 0),
               int(c[col["line"]]))
        if key in seen:
            continue
        seen.add(key)
        en = unescape(c[col["text"]]).replace("\\n", "\n")
        if not en.strip():
            continue
        budget = int(c[col["budget"]])
        comments = [f"GTT pool {key[0]:#010x} block {key[1]:#x} "
                    f"(id {c[col['ident']]}, record {c[col['record']]}), "
                    f"budget {budget} B"]
        out.append(dict(ref=str(slots.GttRef(*key)), msgid=en, budget=budget,
                        comments=comments, sort=key))
    out.sort(key=lambda e: e["sort"])
    # msgid -> budget, so main() can refuse to carry a translation the line's
    # share of the block cannot hold (ANALYSIS/11 §5.2)
    # one text can sit at several addresses with different budgets: keep the
    # tightest, so a carried-over translation is never accepted for a line it
    # would not fit
    collect_gtt.budgets = {}
    for e in out:
        if "budget" not in e:
            continue
        b = e["budget"]
        if e["msgid"] not in collect_gtt.budgets or b < collect_gtt.budgets[e["msgid"]]:
            collect_gtt.budgets[e["msgid"]] = b
    return out


collect_gtt.budgets = {}


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


def existing_translations(outdir: Path) -> tuple:
    """(msgid -> msgstr, corpus -> {msgid: msgstr}) from the .po files there.

    Re-exporting regenerates the whole tree, so without this every round
    would throw away whatever has been translated so far.  Keyed on msgid
    only: the exporter merges slots by msgid, and a source string that changed
    simply misses and comes back empty, which is the safe failure.

    The second map is the same thing per corpus, and it wins over the first:
    one English line often lives in two corpora (a CODEC call and a slot
    hint, say) and the two are rarely translated alike.  Taking only the
    global map lets whichever corpus sorts first silently overwrite the other
    -- seen 2026-09-22, "And one Snake..." came back from `codec/` and
    replaced the `slot/` wording, which was the better of the two.
    """
    from .po import parse_po

    out, by_corpus = {}, {}
    if not outdir.is_dir():
        return out, by_corpus
    for p in sorted(outdir.rglob("*.po")):
        corpus = p.parent.name
        for e in parse_po(p):
            if not (e.msgid and e.msgstr):
                continue
            out.setdefault(e.msgid, e.msgstr)
            by_corpus.setdefault(corpus, {}).setdefault(e.msgid, e.msgstr)
    return out, by_corpus


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
    ap.add_argument("--stage", choices=("all", "none"), default="all",
                    help="export the olang tables packed inside STAGEDAT "
                         "(default all; written back by pwsf.stage_build into "
                         "009645fa.PDT, see ANALYSIS/09 §11)")
    ap.add_argument("--gtt", choices=("all", "none"), default="all",
                    help="export the GTT pools of SLOT.DAT: in-mission radio "
                         "and hint lines, ANALYSIS/11 (default all; the block "
                         "is re-laid-out, so a translation may be longer than "
                         "the English line)")
    ap.add_argument("--fresh", action="store_true",
                    help="do not carry over msgstr from the existing .po files")
    ap.add_argument("--pixel-font", action="store_true",
                    help="also export the slots whose key.meta == 1: those are "
                         "drawn with the 512x512 pixel atlas inside Text/*.txp, "
                         "which has no CJK glyphs, so they are left out by "
                         "default and stay English (ANALYSIS/05_font.md §15)")
    ap.add_argument("--pot", action="store_true",
                    help="also write pwsf.pot, everything merged into one "
                         "file with empty msgstr, for import into a "
                         "translation platform. Off by default: it duplicates "
                         "every entry in the chunked files, and neither "
                         "po_lint nor po_import reads it -- translating in it "
                         "has no effect")
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
    corpora = [("olang", collect_olang(ref_langs, args.pixel_font)),
               ("codec", collect_codec())]
    if args.slot != "none":
        corpora.append(("slot", collect_slot(ref_langs, args.slot,
                                             args.pixel_font)))
    if args.stage != "none":
        corpora.append(("stage", collect_stage(ref_langs, args.pixel_font)))
    if args.gtt != "none":
        corpora.append(("gtt", collect_gtt()))
    if not args.pixel_font:
        print(f"left out {len(slots.pixel_font_refs())} pixel-font slot(s) "
              f"(key.meta == 1: drawn with the ASCII-only 512x512 atlas in "
              f"Text/*.txp); --pixel-font to export them anyway")

    if args.fresh:
        carry, carry_by_corpus = {}, {}
    else:
        carry, carry_by_corpus = existing_translations(args.outdir)
    if carry:
        print(f"carrying over {len(carry)} existing translation(s)")

    manifest = ["file\tsource\tentries\trefs\tchars"]
    all_entries = []
    written = set()
    for name, records in corpora:
        # A GTT line may grow into the block's slack but not past its share,
        # so a carried-over translation that overshoots is dropped instead of
        # being re-created on every export.  A corpus's own wording wins over
        # another corpus's for a shared line (see existing_translations).
        use = dict(carry)
        use.update(carry_by_corpus.get(name, {}))
        if name == "gtt" and carry:
            from . import gtt as _gtt
            budget = getattr(collect_gtt, "budgets", {})
            use = {k: v for k, v in carry.items()
                   if k not in budget
                   or len(_gtt.to_game_text(v)) <= budget[k]}
            dropped = len(carry) - len(use)
            if dropped:
                print(f"gtt: {dropped} carried translation(s) dropped: they "
                      f"do not fit the line's budget (ANALYSIS/11 §5)")
        entries = merge(records, do_merge)
        all_entries += entries
        parts = chunk(entries, args.chunk)
        print(f"{name}: {len(records)} slots -> {len(entries)} entries"
              f"{' (merged)' if do_merge else ''} -> {len(parts)} files")
        for i, part in enumerate(parts, 1):
            fn = args.outdir / name / f"{name}_{i:02d}.po"
            write_po(fn, part, f"{name} {i}/{len(parts)}", name, use,
                     note=NOTES.get(name))
            written.add(fn)
            refs = sum(len(e["refs"]) for e in part)
            chars = sum(len(e["msgid"]) for e in part)
            manifest.append(f"{fn.relative_to(args.outdir)}\t{name}\t"
                            f"{len(part)}\t{refs}\t{chars}")
            print(f"  {fn.relative_to(args.outdir)}  {len(part):>4} entries, "
                  f"{refs:>4} slots, {chars:>6} chars")

    # a chunk count that shrank (smaller --chunk, or slots that stopped being
    # exported) leaves the tail files behind, and their entries then conflict
    # with the same references in the regenerated ones
    for d in {p.parent for p in written}:
        for old in sorted(d.glob("*.po")):
            if old not in written:
                old.unlink()
                print(f"  removed stale {old.relative_to(args.outdir)}")

    if args.pot:
        pot = args.outdir / "pwsf.pot"
        write_po(pot, all_entries, "template", "+".join(n for n, _ in corpora))
        print(f"template {pot} ({len(all_entries)} entries) -- not read by "
              f"po_lint / po_import")
    (args.outdir / "MANIFEST.tsv").write_text("\n".join(manifest) + "\n",
                                              encoding="utf-8")

    total_refs = sum(len(e["refs"]) for e in all_entries)
    total_chars = sum(len(e["msgid"]) for e in all_entries)
    print(f"total: {len(all_entries)} entries covering {total_refs} slots, "
          f"{total_chars} source characters")


if __name__ == "__main__":
    main()
