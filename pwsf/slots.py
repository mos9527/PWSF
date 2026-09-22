"""Resolve a `.po` reference back to the binary slot it was exported from.

`po_lint` (is this msgid still the source text?) and `po_import` (where does
this translation go?) both go through here, so the two can never disagree about
what a reference means.

Reference syntax is fixed by po_export:

    olang/<table_stem>/<group_key>/<entry_key>   olang/009c9ea4/0x9b86ab/0x0198da
    codec/<group>/<sector>/<off>/<line>          codec/1/0/0/0
    slot/<table_id>/<group_key>/<entry_key>      slot/0x003af54d/0x9b86ab/0x0198da
    stage/<rec>/<file>/<group_key>/<entry_key>   stage/15/lang_mission_info_en.olang/0x215635/0x4936c0

`stage` is the STAGEDAT corpus (ANALYSIS/09): the olang tables packed inside
009645fa.PDT (mission info, stage telops, Mother Base staff comments, item and
weapon text).  `pwsf.stage` extracts it and `pwsf.stage_build` writes the
translations back into a rebuilt `009645fa.PDT` (ANALYSIS/09 §4).

Group and entry keys are written with `#08x`, but anything `int(x, 0)` accepts
is parsed, so hand-written references work too.

Everything is read through `config.pristine()`, the same rule the exporter
follows: an installed build must never be read back as source (PLANS/06 §8.1).
"""

import functools
from dataclasses import dataclass
from pathlib import Path

from . import config
from .crypto import name_hash, buffer_xor_decrypt
from .slotdat import unescape
from .olang import OlangTable, parse, string_at
from .olang_build import OlangBuilder

OLANG = "olang"
CODEC = "codec"
SLOT = "slot"          # olang tables embedded in SLOT.DAT, ANALYSIS/08 §5.7
STAGE = "stage"        # olang tables embedded in STAGEDAT, ANALYSIS/09 §4
                       # written back by pwsf.stage_build (rebuilt container)
GTT = "gtt"            # the GTT pools of SLOT.DAT, ANALYSIS/11
                       # in-mission radio / hint lines; the block is re-laid-out
                       # on write-back, so a translation may be longer than the
                       # English string (ANALYSIS/11 §5.2)


@dataclass(frozen=True)
class OlangRef:
    table: str
    group: int
    entry: int

    kind = OLANG

    def __str__(self) -> str:
        return f"{OLANG}/{self.table}/{self.group:#08x}/{self.entry:#08x}"


@dataclass(frozen=True)
class CodecRef:
    group: int
    sector: int
    off: int
    line: int

    kind = CODEC

    def __str__(self) -> str:
        return f"{CODEC}/{self.group}/{self.sector}/{self.off:#x}/{self.line}"


@dataclass(frozen=True)
class SlotRef:
    """A string inside one of the olang tables embedded in SLOT.DAT.

    `table_id` is the RBX table id (e.g. 0x003af54d for the offshore-plant
    cutscene); the same table is stored in several records and every copy was
    verified identical, so write-back patches all of them.
    """
    table: int
    group: int
    entry: int

    kind = SLOT

    def __str__(self) -> str:
        return f"{SLOT}/{self.table:#010x}/{self.group:#08x}/{self.entry:#08x}"


@dataclass(frozen=True)
class StageRef:
    """A string in one of the olang tables packed inside STAGEDAT.

    `rec` is the container entry index, `file` the inner file name -- the same
    logical table (table_id) is stored per language in several entries, so the
    address has to name the copy.  Written back by `pwsf.stage_build`
    (ANALYSIS/09 §11).
    """
    rec: int
    file: str
    group: int
    entry: int

    kind = STAGE

    def __str__(self) -> str:
        return f"{STAGE}/{self.rec}/{self.file}/{self.group:#08x}/" \
               f"{self.entry:#08x}"


@dataclass(frozen=True)
class GttRef:
    """A line of a GTT pool in SLOT.DAT (ANALYSIS/11).

    `pool` is the resource-entry id (0x1c?????? -- outside the 0x20000000 class
    slotdat_find_res_entry @ 0x1400A61F0 accepts, which is why these pools were
    never extracted before), `block` the offset of the `GTT\\x00` block inside
    the pool, `line` the index within that block.

    The same pool id is stored in several records (region copies, one per build)
    and every copy was verified identical, so write-back patches all of them --
    same contract as SlotRef.
    """
    pool: int
    block: int
    line: int

    kind = GTT

    def __str__(self) -> str:
        return f"{GTT}/{self.pool:#010x}/{self.block:#x}/{self.line}"


def parse_ref(ref: str):
    """OlangRef / CodecRef / SlotRef / StageRef / GttRef for a `#:` reference."""
    parts = ref.split("/")
    try:
        if parts[0] == OLANG and len(parts) == 4:
            return OlangRef(parts[1], int(parts[2], 0), int(parts[3], 0))
        if parts[0] == CODEC and len(parts) == 5:
            return CodecRef(*(int(p, 0) for p in parts[1:]))
        if parts[0] == SLOT and len(parts) == 4:
            return SlotRef(int(parts[1], 0), int(parts[2], 0), int(parts[3], 0))
        if parts[0] == STAGE and len(parts) == 5:
            return StageRef(int(parts[1], 0), parts[2],
                            int(parts[3], 0), int(parts[4], 0))
        if parts[0] == GTT and len(parts) == 4:
            return GttRef(int(parts[1], 0), int(parts[2], 0), int(parts[3], 0))
    except ValueError:
        pass
    raise ValueError(f"unparseable reference: {ref!r}")


# ------------------------------------------------------------------ olang side

def olang_paths() -> list:
    """The shipped text tables, EXLANG excluded (its English slots are empty)."""
    return sorted(config.TEXT_DIR.glob("*.olang"))


def olang_source_path(stem: str) -> Path:
    return config.pristine(config.TEXT_DIR / f"{stem}.olang")


@functools.lru_cache(maxsize=None)
def _table_bytes(stem: str) -> bytes:
    raw = bytearray(olang_source_path(stem).read_bytes())
    # the cipher is a keystream XOR, so decrypt and encrypt are the same call;
    # name_hash stops at the first '.', so a *.orig backup keys identically
    return bytes(buffer_xor_decrypt(raw, name_hash(stem)))


@functools.lru_cache(maxsize=None)
def table(stem: str) -> OlangTable:
    """Parsed pristine table. Shared and cached -- treat it as read-only."""
    return parse(_table_bytes(stem), str(olang_source_path(stem)))


def builder(stem: str) -> OlangBuilder:
    """A fresh editable builder over the pristine table."""
    return OlangBuilder(parse(_table_bytes(stem), str(olang_source_path(stem))))


def encrypt(stem: str, blob: bytes) -> bytes:
    """Apply the table's keystream. Symmetric, hence the alias below."""
    return bytes(buffer_xor_decrypt(bytearray(blob), name_hash(stem)))


decrypt = encrypt


def olang_sources(lang: int = config.LANG_EN) -> dict:
    """reference -> source string, for every slot that has one in `lang`."""
    out = {}
    for path in olang_paths():
        stem = path.stem
        tbl = table(stem)
        for g in tbl.groups:
            for ei in range(g.entry_start, g.entry_start + g.entry_count):
                e = tbl.entries[ei]
                for ki in range(e.key_start, e.key_start + e.key_count):
                    if tbl.keys[ki][0] != lang:
                        continue
                    ref = f"{OLANG}/{stem}/{g.key:#08x}/{e.key:#08x}"
                    out[ref] = string_at(tbl, tbl.keys[ki][1]).decode("utf-8")
    return out


# ------------------------------------------------------------------ codec side

def codec_sources() -> dict:
    """reference -> English line, out of the extracted BRIEFING corpus.

    The TSV is the source of record because re-scanning the container would
    mean decrypting and walking it for every lint run.  The old note blamed
    the `case 0x10 / 0x20` length rules; those are solved now (ANALYSIS/03
    §5.1.2) and were never the blocker -- no translatable text lives in the
    bytecode.  What write-back has to respect is that a record may not change
    size (ANALYSIS/03 §9), which `briefing_build` enforces as a pool budget.
    """
    rows = config.BRIEFING_TSV.read_text(encoding="utf-8").splitlines()
    col = {n: i for i, n in enumerate(rows[0].split("\t"))}
    out = {}
    for r in rows[1:]:
        c = r.split("\t")
        if len(c) <= col["text"] or c[col["lang"]] != "en":
            continue
        ref = (f"{CODEC}/{c[col['group']]}/{c[col['sector']]}/"
               f"{c[col['off']]}/{c[col['line']]}")
        out[ref] = c[col["text"]].replace("\\n", "\n")
    return out


def slot_sources(lang: int = config.LANG_EN) -> dict:
    """reference -> English line, for the olang tables inside SLOT.DAT.

    Read from `_slot_olang_lines.tsv` rather than re-scanning the 544 MB
    container: the TSV is the extraction product and holds the same rows plus
    the record/pool location of every copy.

    """
    path = config.SLOT_OLANG_TSV
    if not path.is_file():
        return {}
    rows = path.read_text(encoding="utf-8").splitlines()
    col = {n: i for i, n in enumerate(rows[0].split("\t"))}
    out = {}
    for r in rows[1:]:
        c = r.split("\t")
        if len(c) <= col["text"] or c[col["lang"]] != \
                config.LANG_KEYS.get(lang, "en"):
            continue
        ref = str(SlotRef(int(c[col["table_id"]], 0), int(c[col["group"]], 0),
                          int(c[col["entry"]], 0)))
        out[ref] = unescape(c[col["text"]])
    return out


def stage_sources(lang: int = config.LANG_EN) -> dict:
    """reference -> line, for the olang tables inside STAGEDAT (ANALYSIS/09).

    Same shape as slot_sources: the TSV written by `pwsf.stage` is the source
    of record, because re-reading the 487 MB container means decrypting and
    inflating every payload on every lint run.
    """
    path = config.STAGE_OLANG_TSV
    if not path.is_file():
        return {}
    rows = path.read_text(encoding="utf-8").splitlines()
    col = {n: i for i, n in enumerate(rows[0].split("\t"))}
    want = config.LANG_KEYS.get(lang, "en")
    out = {}
    for r in rows[1:]:
        c = r.split("\t")
        if len(c) <= col["text"] or c[col["lang"]] != want:
            continue
        out[str(StageRef(int(c[col["rec"]]), c[col["file"]],
                         int(c[col["group"]], 0), int(c[col["entry"]], 0)))] = \
            c[col["text"]].replace("\\n", "\n")
    return out


def stage_pixel_refs() -> frozenset:
    """stage references drawn with the ASCII-only pixel atlas (meta == 1)."""
    path = config.STAGE_OLANG_TSV
    if not path.is_file():
        return frozenset()
    rows = path.read_text(encoding="utf-8").splitlines()
    col = {n: i for i, n in enumerate(rows[0].split("\t"))}
    out = set()
    for r in rows[1:]:
        c = r.split("\t")
        if len(c) <= col["text"] or c[col["lang"]] != "en":
            continue
        if int(c[col["meta"]], 0) != META_PIXEL_FONT:
            continue
        out.add(str(StageRef(int(c[col["rec"]]), c[col["file"]],
                             int(c[col["group"]], 0), int(c[col["entry"]], 0))))
    return frozenset(out)


# olang key.meta is the font selector (ANALYSIS/05_font.md §15, proven by
# RenderDoc: the title screen's "PRESS START BUTTON" is meta 0x1 and every
# quad of it samples the 512x512 BC3 atlas inside Text/*.txp, which has no
# CJK glyphs at all).
META_PIXEL_FONT = 0x1


@functools.lru_cache(maxsize=1)
def pixel_font_refs() -> frozenset:
    """Slots drawn with the pixel font: ASCII / Latin-1 only, never translate.

    English key decides: the reference names a (group, entry) pair, and while
    a group can mix both metas (ANALYSIS/01 §7) each language key carries its
    own, and we only ever overwrite the English one.
    """
    out = set()
    for path in olang_paths():
        stem = path.stem
        tbl = table(stem)
        for g in tbl.groups:
            for ei in range(g.entry_start, g.entry_start + g.entry_count):
                e = tbl.entries[ei]
                for ki in range(e.key_start, e.key_start + e.key_count):
                    k, _so, meta, _pad = tbl.keys[ki]
                    if k == config.LANG_EN and meta == META_PIXEL_FONT:
                        out.add(f"{OLANG}/{stem}/{g.key:#08x}/{e.key:#08x}")

    path = config.SLOT_OLANG_TSV
    if path.is_file():
        rows = path.read_text(encoding="utf-8").splitlines()
        col = {n: i for i, n in enumerate(rows[0].split("\t"))}
        for r in rows[1:]:
            c = r.split("\t")
            if len(c) <= col["text"] or c[col["lang"]] != "en":
                continue
            if int(c[col["meta"]], 0) != META_PIXEL_FONT:
                continue
            out.add(str(SlotRef(int(c[col["table_id"]], 0),
                                int(c[col["group"]], 0),
                                int(c[col["entry"]], 0))))
    return frozenset(out | set(stage_pixel_refs()))


def gtt_sources() -> dict:
    """reference -> English line, for the GTT pools of SLOT.DAT (ANALYSIS/11).

    Read from `_gtt_lines.tsv`, the product of `python -m pwsf.gtt`, like the
    other corpora do -- walking the 544 MB container on every lint run would
    cost a minute and give the same rows.
    """
    path = config.GTT_TSV
    if not path.is_file():
        return {}
    rows = path.read_text(encoding="utf-8").splitlines()
    col = {n: i for i, n in enumerate(rows[0].split("\t"))}
    out = {}
    for r in rows[1:]:
        c = r.split("\t")
        if len(c) <= col["text"]:
            continue
        # the game stores a line break as a two-character `\n` escape; the .po
        # and the CODEC corpus both carry a real newline instead
        out[str(GttRef(int(c[col["pool"]], 0), int(c[col["block"]], 0),
                       int(c[col["line"]])))] = \
            unescape(c[col["text"]]).replace("\\n", "\n")
    return out


def gtt_budgets() -> dict:
    """reference -> bytes a translation may use.

    GTT write-back re-lays the block out (ANALYSIS/11 §5.2), so a line may be
    longer than its English -- up to its share of the block's slack.  That share
    is what `po_lint`'s `gtt-budget` reports on.
    """
    path = config.GTT_TSV
    if not path.is_file():
        return {}
    rows = path.read_text(encoding="utf-8").splitlines()
    col = {n: i for i, n in enumerate(rows[0].split("\t"))}
    out = {}
    for r in rows[1:]:
        c = r.split("\t")
        if len(c) <= col["budget"]:
            continue
        out[str(GttRef(int(c[col["pool"]], 0), int(c[col["block"]], 0),
                       int(c[col["line"]])))] = int(c[col["budget"]])
    return out


@functools.lru_cache(maxsize=1)
def sources() -> dict:
    """Every exportable slot, all corpora, keyed by reference."""
    out = olang_sources()
    out.update(codec_sources())
    out.update(slot_sources())
    out.update(stage_sources())
    out.update(gtt_sources())
    return out
