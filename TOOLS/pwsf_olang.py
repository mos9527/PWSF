"""PWSF .olang (RBX) text-table parser.

Container layout, confirmed against text_lookup (0x1400E6EB0) / text_get (0x1400E6990):

    u32  magic      'RBX\\0'
    u32  table_id   == the numeric part of the file's base name (e.g. 0x009C9EA4)
    u32  zero
    u16  zero
    u16  group_count
    u32  off_group_table      (header size = 0x20, groups follow immediately)
    u32  off_entry_table
    u32  off_key_table
    u32  off_string_pool

    group[i] : u32 key; u16 entry_start; u16 entry_count    (8 bytes)
    entry[i] : u32 key; u16 key_start;   u16 key_count      (8 bytes)
    key[i]   : u32 key; u32 str_off;     u16 meta; u16 pad  (12 bytes)

Lookup order: group key -> entry key -> key id -> pool_base + str_off
"""

import struct
from dataclasses import dataclass, field
from pathlib import Path

from pwsf_crypto import buffer_xor_decrypt

MAGIC = b"RBX\x00"
HEADER_SIZE = 0x20


@dataclass
class OlangGroup:
    key: int
    entry_start: int
    entry_count: int


@dataclass
class OlangEntry:
    key: int
    key_start: int
    key_count: int


@dataclass
class OlangString:
    group: int
    entry: int
    key: int
    offset: int
    meta: int
    data: bytes


@dataclass
class OlangTable:
    table_id: int
    groups: list = field(default_factory=list)
    entries: list = field(default_factory=list)
    keys: list = field(default_factory=list)
    pool: bytes = b""
    path: str = ""

    def strings(self):
        """Yield OlangString in table order, resolving group/entry keys."""
        ent_of_group = []
        for g in self.groups:
            ent_of_group.extend(range(g.entry_start, g.entry_start + g.entry_count))

        key_of_entry = []
        for e in self.entries:
            key_of_entry.extend(range(e.key_start, e.key_start + e.key_count))

        for gi, g in enumerate(self.groups):
            for ei in range(g.entry_start, g.entry_start + g.entry_count):
                if ei >= len(self.entries):
                    continue
                e = self.entries[ei]
                for ki in range(e.key_start, e.key_start + e.key_count):
                    if ki >= len(self.keys):
                        continue
                    k = self.keys[ki]
                    yield OlangString(g.key, e.key, k[0], k[1], k[2], b"")


def load(path, key: int) -> OlangTable:
    raw = bytearray(Path(path).read_bytes())
    data = bytes(buffer_xor_decrypt(raw, key))
    return parse(data, str(path))


def parse(data: bytes, path: str = "") -> OlangTable:
    if data[:4] != MAGIC:
        raise ValueError(f"bad RBX magic: {data[:4]!r}")
    table_id, z0 = struct.unpack_from("<II", data, 4)
    group_count, = struct.unpack_from("<H", data, 0x0E)
    off_grp, off_ent, off_key, off_pool = struct.unpack_from("<4I", data, 0x10)

    tbl = OlangTable(table_id=table_id, pool=data[off_pool:], path=path)

    for i in range(group_count):
        o = off_grp + 8 * i
        k, s, c = struct.unpack_from("<IHH", data, o)
        tbl.groups.append(OlangGroup(k, s, c))

    max_ent = max((g.entry_start + g.entry_count for g in tbl.groups), default=0)
    for i in range(max_ent):
        o = off_ent + 8 * i
        if o + 8 > len(data):
            break
        k, s, c = struct.unpack_from("<IHH", data, o)
        tbl.entries.append(OlangEntry(k, s, c))

    max_key = max((e.key_start + e.key_count for e in tbl.entries), default=0)
    for i in range(max_key):
        o = off_key + 12 * i
        if o + 12 > len(data):
            break
        k, so, meta, _pad = struct.unpack_from("<IIHH", data, o)
        tbl.keys.append((k, so, meta, _pad))

    return tbl


def string_at(tbl: OlangTable, offset: int) -> bytes:
    """NUL-terminated string out of the pool."""
    end = tbl.pool.find(b"\x00", offset)
    if end < 0:
        end = len(tbl.pool)
    return tbl.pool[offset:end]
