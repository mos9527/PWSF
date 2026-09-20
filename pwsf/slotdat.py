"""SLOT.DAT (`MLG/disc0_rel/002aba34.DAT`) -- the container that holds the
comic cutscene text, opened in ANALYSIS/08_cutscene_text.md §5.

Layout
------
`002aba34.KEY` is the index: a 12-byte header followed by 20-byte records,
all XORed with `name_hash("002aba34")`.  Record fields are bit-packed:

    +0x00  u32   low 20 = start sector, high 12 = A (inflated sectors)
    +0x04  u32   low 20 = end sector,   high 12 = B (stored sectors)
    +0x08  u32   record id hash
    +0x0C  u32   A, again
    +0x10  u32   B, again

`002aba34.DAT` holds one payload per record at `start * 4096`:

    16-byte header    magic u16 @+0, header size u16 @+2 (=16),
                      const u32 @+4, compressed size u32 @+8,
                      inflated size u32 @+12
    zlib stream       starts at +16, always `78 da`

and is obfuscated by TWO XOR layers:

1. `buffer_xor_decrypt(v5, B << 12, name_hash("002aba34"))`
   -- slotdat_load_and_verify @ 0x1400A6290.  Plain MT19937 stream,
   `mt_seed(key)` + `mt_advance(20)`, each dword XORed with 0xB9D3018F.

2. an LCG mask, applied by the read completion path:
   `io_cmd_dispatch` @ 0x14045D600 case 0x10 copies the 12 bytes at
   `sub_14008AE50()` (== `&xmmword_1410C7A10 + 12`, where the SLOT.KEY
   loader decoded the .KEY file header) into file+204 (state) /
   file+208 (increment) / file+212, and raises flag 0x40 -- the LCG branch
   of `entry_payload_transform` @ 0x140123E90:

       for each dword:  *p ^= state;  state = 48828125 * state + inc

   The state is *derived*, not stored raw -- `sub_140123DB0` @ 0x140123DB0:

       v     = d1 ^ d0
       state = v | ((v ^ 0x6576) << 16)
       inc   = d2 * v

   with d0..d2 the three dwords of the DECRYPTED SLOT.KEY header.
   For the retail disc0 copy: d0 = 0xc79ebeba, d1 = 0xdf41c1b1,
   d2 = 0xb06a43b9 -> state = 0x1aff7f0b, inc = 0xa250aff3.

Both layers are plain XOR and every record uses the same stream from record
offset 0, so they are folded into one keystream generated once and sliced.

Inflated content
----------------
`u32 @+0` is the resource count; entries are 16 bytes each starting at +8
(`slotdat_find_res_entry` @ 0x1400A61F0 reads `v1 + 2`, i.e. +8):

    +0x00  id        kept when id != 0, (id & 0xFF000000) != 0x7F000000
                     and (id & 0x7F000000) == 0x20000000
    +0x08  offset    (dword2 & 0x3FFFFFFF), relative to the data area

The data area starts at `align_down(16 * count + 4103, 4096)`.
"""

import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

from . import config
from .crypto import MT19937, XOR_CONST, buffer_xor_decrypt, name_hash

SECTOR = 4096
KEY_HDR, KEY_REC = 12, 20
MASK20 = (1 << 20) - 1
REC_HDR = 16
ZLIB_SIG = b"\x78\xda"

# entry_payload_transform @ 0x140123E90, mode 0x40 branch
LCG_MUL = 48828125                  # 5 ** 11
LCG_XOR = 0x6576                    # sub_140123DB0 @ 0x140123DB0
MASK32 = (1 << 32) - 1

STEM = "002aba34"


def key_path() -> Path:
    return config.pristine(config.DISC0_DIR / f"{STEM}.KEY")


def dat_path() -> Path:
    return config.pristine(config.DISC0_DIR / f"{STEM}.DAT")


# ----------------------------------------------------------------- key index

@dataclass(frozen=True)
class SlotRecord:
    index: int
    start: int          # first sector of the payload
    end: int            # one past the last sector
    inflated: int       # A -- inflated sectors
    stored: int         # B -- stored (compressed) sectors
    id_hash: int
    a_copy: int
    b_copy: int

    @property
    def extra(self) -> int:
        """Sectors after the main block: a second, separately-inflated blob."""
        return self.end - self.start - self.stored


def load_index(path: Path = None) -> list:
    """The 2,137 SLOT.KEY records, decrypted."""
    path = path or key_path()
    buf = bytearray(path.read_bytes())
    buffer_xor_decrypt(buf, name_hash(path.stem))
    n = (len(buf) - KEY_HDR) // KEY_REC
    out = []
    for i in range(n):
        w0, w1, h, a, b = struct.unpack_from("<IIIII", buf, KEY_HDR + KEY_REC * i)
        out.append(SlotRecord(i, w0 & MASK20, w1 & MASK20, w0 >> 20, w1 >> 20,
                              h, a, b))
    return out


def lcg_params(path: Path = None) -> tuple:
    """(state, increment) of the second layer, from the .KEY header."""
    path = path or key_path()
    hdr = bytearray(path.read_bytes()[:KEY_HDR])
    buffer_xor_decrypt(hdr, name_hash(STEM))
    d0, d1, d2 = struct.unpack("<3I", bytes(hdr))
    v = (d1 ^ d0) & MASK32
    state = (v | ((v ^ LCG_XOR) << 16)) & MASK32
    inc = (d2 * v) & MASK32
    return state, inc


# ------------------------------------------------------------------ keystream

def keystream(ndwords: int, state: int, inc: int, key: int = None) -> bytes:
    """Both XOR layers folded, `ndwords` dwords, little endian."""
    if key is None:
        key = name_hash(STEM)
    try:
        import numpy as np
    except ImportError:
        np = None

    if np is not None:
        ks = np.empty(ndwords, dtype=np.uint32)
        s = state
        # the LCG is sequential by nature; done once for the whole container
        for i in range(ndwords):
            ks[i] = s
            s = (LCG_MUL * s + inc) & MASK32
        mt = MT19937(key)
        mt.advance(20)
        ks ^= np.frombuffer(
            struct.pack("<%dI" % ndwords,
                        *[(mt.next() ^ XOR_CONST) & MASK32
                          for _ in range(ndwords)]), dtype=np.uint32)
        return ks.tobytes()

    s = state
    mt = MT19937(key)
    mt.advance(20)
    out = []
    for _ in range(ndwords):
        out.append((s ^ mt.next() ^ XOR_CONST) & MASK32)
        s = (LCG_MUL * s + inc) & MASK32
    return struct.pack("<%dI" % ndwords, *out)


# -------------------------------------------------------------------- records

def read_block(rec: SlotRecord, path: Path = None) -> bytes:
    """The raw on-disk bytes of a record's main block (B sectors)."""
    path = path or dat_path()
    with open(path, "rb") as fh:
        fh.seek(rec.start * SECTOR)
        return fh.read(rec.stored * SECTOR)


def decrypt(blob: bytes, ks: bytes) -> bytes:
    """Remove both XOR layers.  `ks` must cover the whole block."""
    n = len(blob) & ~3
    merged = int.from_bytes(blob[:n], "little") ^ \
        int.from_bytes(ks[:n], "little")
    return merged.to_bytes(n, "little") + blob[n:]


def parse_header(plain: bytes) -> tuple:
    """(magic, header_size, const, compressed, inflated)."""
    magic, hdr_size = struct.unpack_from("<HH", plain, 0)
    const, comp, raw = struct.unpack_from("<III", plain, 4)
    return magic, hdr_size, const, comp, raw


def inflate(plain: bytes, hdr_size: int = REC_HDR, comp: int = None) -> bytes:
    if comp is None:
        comp = struct.unpack_from("<I", plain, 8)[0]
    return zlib.decompress(plain[hdr_size:hdr_size + comp])


# ----------------------------------------------------------------- res table

def res_table(data: bytes) -> tuple:
    """(count, [entry dwords...], data-area offset)."""
    count = struct.unpack_from("<I", data, 0)[0]
    entries = [struct.unpack_from("<4I", data, 8 + 16 * i)
               for i in range(count)]
    area = (16 * count + 4103) & ~0xFFF
    return count, entries, area


# Cutscene tables.  Heuristic, but both halves agree exactly (_probe_slot25):
#   * every table whose id is in this window first shows up in record >= 1863
#   * no table outside the window does
# and the comic cutscene line from ANALYSIS/08 §1 lives in 0x003af54d, inside
# the window.  The tail records carry RBX (text) only -- the comic art itself
# is elsewhere (STAGEDAT.PDT), which is why these records are text-only.
CUTSCENE_ID_LO = 0x003AF000
CUTSCENE_ID_HI = 0x003B0A00


def is_cutscene(table_id: int) -> bool:
    """True for the comic-cutscene olang tables (see the note above)."""
    return CUTSCENE_ID_LO <= table_id < CUTSCENE_ID_HI


def res_kept(entry) -> bool:
    """The filter slotdat_find_res_entry @ 0x1400A61F0 applies."""
    eid = entry[0]
    return bool(eid) and (eid & 0xFF000000) != 0x7F000000 \
        and (eid & 0x7F000000) == 0x20000000


# --------------------------------------------------------- embedded olang text

def slot_pools(data: bytes) -> list:
    """[(entry_index, entry_id, offset, blob)] of an inflated slot's pools.

    Entries carry no length; a pool runs up to the next pool's offset.  The
    `0x7f000000` / `0` ids are sentinels (they are exactly what
    slotdat_find_res_entry's filter skips) and are dropped.
    """
    count, entries, area = res_table(data)
    live = [i for i in range(count)
            if entries[i][0] and (entries[i][0] >> 24) != 0x7F]
    live.sort(key=lambda i: entries[i][2] & 0x3FFFFFFF)
    bounds = [entries[i][2] & 0x3FFFFFFF for i in live]
    ends = bounds[1:] + [max(len(data) - area, 0)]
    out = []
    for i, off, stop in zip(live, bounds, ends):
        out.append((i, entries[i][0], off,
                    data[area + off:area + max(stop, off)]))
    return out


def pools(rec: SlotRecord, ks: bytes, path: Path = None) -> list:
    """[(entry_id, offset, blob)] of a record's live resource entries."""
    data = inflate(decrypt(read_block(rec, path), ks))
    return [(eid, off, blob) for _i, eid, off, blob in slot_pools(data)]


@dataclass(frozen=True)
class TextRow:
    table_id: int
    lang: int
    group: int
    entry: int
    meta: int
    text: bytes

    def __str__(self) -> str:
        return (f"slot/{self.table_id:#010x}/{self.group:#08x}/"
                f"{self.entry:#08x}/{self.lang:#06x}")


def embedded_olang(pool_blobs=None, skip_langs=(0x34BC87,)):
    """Every .olang table carried inside SLOT.DAT, de-duplicated.

    Returns (rows, first_seen, locations):
      rows        [TextRow] one per (table, lang, group, entry)
      first_seen  {(table_id, lang): record index}
      locations   {(table_id, lang): [(record, pool_id), ...]}

    The same table is stored in several records (one per region build); every
    copy was verified byte-identical, so one row per (table, lang, group,
    entry) is enough and write-back patches all copies.
    `skip_langs` drops non-text key ids -- 0x34bc87 is a 240-row flag table
    whose every string is b"\\x01".
    """
    from . import olang

    if pool_blobs is None:
        recs = load_index()
        state, inc = lcg_params()
        nd = max(r.stored for r in recs) * SECTOR // 4 + 16
        ks = keystream(nd, state, inc)

        def pool_blobs():
            for rec in recs:
                for eid, off, blob in pools(rec, ks):
                    yield rec.index, eid, blob

    seen = {}
    locations = {}
    first_seen = {}
    for rec_index, eid, blob in pool_blobs():
        if len(blob) < 0x20 or blob[:4] != b"RBX\x00":
            continue
        tbl = olang.parse(blob, f"slot/{rec_index}/{eid:#010x}")
        for lang, gk, ek, meta, text in _rows_of(tbl):
            if lang in skip_langs:
                continue
            key = (tbl.table_id, lang)
            locations.setdefault(key, [])
            loc = (rec_index, eid)
            if loc not in locations[key]:
                locations[key].append(loc)
            first_seen.setdefault(key, rec_index)
            seen.setdefault(key, {})[(gk, ek, meta)] = text

    rows = []
    for (table_id, lang), mapping in sorted(seen.items()):
        for (gk, ek, meta), text in sorted(mapping.items()):
            rows.append(TextRow(table_id, lang, gk, ek, meta, text))
    return rows, first_seen, locations


def unescape(s: str) -> str:
    """Undo the TSV escaping used by the corpus writers (_probe_slot24/25).

    Backslash is escaped first and restored last, so `\\\\n` in the file means
    a literal backslash followed by `n`, not a newline.
    """
    return (s.replace("\\\\", "\x00")
             .replace("\\n", "\n").replace("\\t", "\t")
             .replace("\\r", "\r").replace("\x00", "\\"))


def _rows_of(tbl):
    """[(lang, group_key, entry_key, meta, text)] in table order."""
    from . import olang
    out = []
    for g in tbl.groups:
        for ei in range(g.entry_start, g.entry_start + g.entry_count):
            if ei >= len(tbl.entries):
                continue
            e = tbl.entries[ei]
            for ki in range(e.key_start, e.key_start + e.key_count):
                if ki >= len(tbl.keys):
                    continue
                lang, so, meta, _pad = tbl.keys[ki]
                text = olang.string_at(tbl, so)
                if text:
                    out.append((lang, g.key, e.key, meta, text))
    return out
