"""PWSF .olang (RBX) serialiser -- the inverse of pwsf_olang.parse.

Layout invariants, measured across all 17 shipped tables (_probe_olang2.py):

    header 0x20 bytes, then group / entry / key / pool, CONTIGUOUS,
    zero padding between sections, pool runs to end of file
    header +0x08 u32 and +0x0C u16 are always 0
    table_id always equals the numeric part of the file name
    key.meta is only ever 1 or 0x402; key.pad is always 0
    the string pool is deduplicated (identical strings share one str_off)
    some pool bytes are unreachable from any key -- dead slack, safe to drop

text_lookup @ 0x1400E6EB0 walks all three levels with a LINEAR scan
(group key, then entry key within [entry_start, +entry_count), then key id
within [key_start, +key_count)), so no level has to be sorted.  Entries may be
added or reordered freely as long as the start/count ranges stay consistent.

str_off is relative to the pool base: the lookup returns
    table + *(u32*)(table + 28) + *(u32*)(key + 4)
"""

import struct

from pwsf_olang import MAGIC, HEADER_SIZE, OlangTable, string_at


class OlangBuilder:
    """Editable view of a parsed table plus the two serialisation modes."""

    def __init__(self, tbl: OlangTable):
        self.tbl = tbl
        # one entry per key record, in key-table order
        self.texts = [string_at(tbl, k[1]) for k in tbl.keys]

    # ---------------------------------------------------------------- helpers

    def _header(self, off_grp, off_ent, off_key, off_pool) -> bytes:
        return (MAGIC
                + struct.pack("<II", self.tbl.table_id, 0)
                + struct.pack("<HH", 0, len(self.tbl.groups))
                + struct.pack("<4I", off_grp, off_ent, off_key, off_pool))

    def _tables(self, key_offsets) -> tuple:
        grp = b"".join(struct.pack("<IHH", g.key, g.entry_start, g.entry_count)
                       for g in self.tbl.groups)
        ent = b"".join(struct.pack("<IHH", e.key, e.key_start, e.key_count)
                       for e in self.tbl.entries)
        key = b"".join(struct.pack("<IIHH", k[0], off, k[2], k[3])
                       for k, off in zip(self.tbl.keys, key_offsets))
        return grp, ent, key

    # ---------------------------------------------------------------- output

    def serialize_exact(self) -> bytes:
        """Re-emit with the original str_off values and the pool verbatim.

        Used as the round-trip oracle: this must reproduce the source file
        byte for byte before any rebuild can be trusted.
        """
        grp, ent, key = self._tables([k[1] for k in self.tbl.keys])
        off_grp = HEADER_SIZE
        off_ent = off_grp + len(grp)
        off_key = off_ent + len(ent)
        off_pool = off_key + len(key)
        return (self._header(off_grp, off_ent, off_key, off_pool)
                + grp + ent + key + self.tbl.pool)

    def serialize(self) -> bytes:
        """Re-emit with a freshly laid out, deduplicated string pool.

        Drops the dead slack the shipped files carry, so the result is usually
        a little smaller than the original even when nothing was translated.
        """
        pool = bytearray()
        seen = {}
        offsets = []
        for text in self.texts:
            off = seen.get(text)
            if off is None:
                off = len(pool)
                seen[text] = off
                pool += text + b"\x00"
            offsets.append(off)

        grp, ent, key = self._tables(offsets)
        off_grp = HEADER_SIZE
        off_ent = off_grp + len(grp)
        off_key = off_ent + len(ent)
        off_pool = off_key + len(key)
        return (self._header(off_grp, off_ent, off_key, off_pool)
                + grp + ent + key + bytes(pool))

    # ---------------------------------------------------------------- editing

    def index(self, group_key: int, entry_key: int, lang_key: int) -> int:
        """Key-table index for a (group, entry, language) triple."""
        for g in self.tbl.groups:
            if g.key != group_key:
                continue
            for ei in range(g.entry_start, g.entry_start + g.entry_count):
                e = self.tbl.entries[ei]
                if e.key != entry_key:
                    continue
                for ki in range(e.key_start, e.key_start + e.key_count):
                    if self.tbl.keys[ki][0] == lang_key:
                        return ki
        raise KeyError(f"group {group_key:#x} / entry {entry_key:#x} / "
                       f"lang {lang_key:#x} not found")

    def set_text(self, group_key: int, entry_key: int, lang_key: int,
                 text: str) -> int:
        ki = self.index(group_key, entry_key, lang_key)
        self.texts[ki] = text.encode("utf-8")
        return ki

    def get_text(self, group_key: int, entry_key: int, lang_key: int) -> str:
        return self.texts[self.index(group_key, entry_key, lang_key)].decode("utf-8")
