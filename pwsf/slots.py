"""Resolve a `.po` reference back to the binary slot it was exported from.

`po_lint` (is this msgid still the source text?) and `po_import` (where does
this translation go?) both go through here, so the two can never disagree about
what a reference means.

Reference syntax is fixed by po_export:

    olang/<table_stem>/<group_key>/<entry_key>   olang/009c9ea4/0x9b86ab/0x0198da
    codec/<group>/<sector>/<off>/<line>          codec/1/0/0/0

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
from .olang import OlangTable, parse, string_at
from .olang_build import OlangBuilder

OLANG = "olang"
CODEC = "codec"


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


def parse_ref(ref: str):
    """OlangRef / CodecRef for a `#:` reference, or ValueError."""
    parts = ref.split("/")
    try:
        if parts[0] == OLANG and len(parts) == 4:
            return OlangRef(parts[1], int(parts[2], 0), int(parts[3], 0))
        if parts[0] == CODEC and len(parts) == 5:
            return CodecRef(*(int(p, 0) for p in parts[1:]))
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

    The TSV is the source of record here because there is no `briefing_build`
    yet.  The old note blamed the `case 0x10 / 0x20` length rules; those are
    solved now (ANALYSIS/03 §5.1.2) and were never the blocker -- no
    translatable text lives in the bytecode.  What write-back has to respect
    is that a record may not change size (ANALYSIS/03 §9).
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


@functools.lru_cache(maxsize=1)
def sources() -> dict:
    """Every exportable slot, both corpora, keyed by reference."""
    out = olang_sources()
    out.update(codec_sources())
    return out
