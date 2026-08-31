"""PWSF PDT/DAT archive container, reverse-engineered from METAL GEAR SOLID PEACE WALKER.exe.

Evidence chain (IDA, imagebase 0x140000000):

  archive_index_load        0x1401238C0   container parse (this module)
  sub_140044950             0x140044950   raw ReadFile, sequential, NO sector alignment
  sub_140121570             0x140121570   thin wrapper around sub_140044950
  sub_14010F8B0             0x14010F8B0   mt_seed(key) + mt_advance(20)
  sub_14010F5C0             0x14010F5C0   streaming MT xor (continues state)
  sub_140123DB0             0x140123DB0   key derive   (mode 0x40)
  sub_140123CC0             0x140123CC0   dword LCG unmask (mode 0x40)
  sub_140123DD0             0x140123DD0   byte  xor unmask (mode 0x100)
  entry_index_bsearch       0x140123D60   BST walk over the name table (NOT a bsearch)
  entry_name_hash           0x14011F820   name -> 24-bit key (+ ext id in the high byte)
  g_ext_id_table            0x140F4C7D0   (const char *ext, u32 id), 16 B/entry, 67 entries
  archive_read_entry_simple 0x140122730   payload read pipeline
  entry_payload_transform   0x140123E90   payload unmask (mode 0x40 / 0x100)
  entry_payload_unmask      0x140124000   payload CRC-32 accumulator
  path_resolve_install      0x140043DA0   logical package name -> real file

Container layout (file offsets, contiguous):

    +0x00   40   header
    +0x28   12n  index table
    +0x28+12n  24n  name table      (n = int16 @ header+0x18)

Header fields (after MT decrypt):

    +0x00  u32  lo    if 0 -> no second-stage unmask at all
    +0x04  u32  hi    if 0 -> mode 0x100 (byte xor)   else -> mode 0x40 (dword LCG)
    +0x08  u32  m     LCG increment multiplier (mode 0x40 only)
    +0x0C  28   scratch region, unmasked in place; +0x0C is then zeroed by the game
    +0x18  i16  entry count n, must satisfy 0 <= n <= 96

The unmask is applied THREE times in sequence over one continuous LCG stream
(mode 0x40 only): scratch(28) -> index(12n) -> names(24n).
Mode 0x100 is stateless: every byte xor (lo & 0xFF).
"""

import struct
from dataclasses import dataclass, field

from pwsf_crypto import MT19937, XOR_CONST, name_hash, buffer_xor_decrypt

MASK32 = 0xFFFFFFFF

HDR_SIZE = 40
IDX_ENTRY = 12
NAM_ENTRY = 24
SCRATCH_OFF = 0x0C
SCRATCH_SIZE = 28
COUNT_OFF = 0x18
MAX_ENTRIES = 96

# sub_140123CC0: v4 = inc + 48828125 * v4
LCG_MUL = 48828125


@dataclass
class Node:
    """One 24-byte name-table node. entry_index_bsearch (0x140123D60) is a BST walk:

        +0x00  u32  key
        +0x04  u32  slot        (return value, index into the 12-byte index table)
        +0x08  u64  gt          followed when needle > key
        +0x10  u64  le          followed when needle <= key

    gt/le are relocated by the game against the START of the name table,
    so node_file_off = names_file_off + gt/le, and 0 means NULL.
    """
    key: int = 0
    slot: int = 0
    gt: int = 0
    le: int = 0


@dataclass
class Entry:
    """One 12-byte index-table slot:  u32 a, u32 b, u32 c.

    archive_index_load maps them to pkg+0xE0 (a), pkg+0xD8 (b), pkg+0xDC (c).
    """
    a: int = 0
    b: int = 0
    c: int = 0


@dataclass
class Archive:
    path: str = ""
    key: int = 0
    lo: int = 0
    hi: int = 0
    m: int = 0
    mode: int = 0            # 0 / 0x40 / 0x100
    count: int = 0
    hdr: bytes = b""
    index: bytes = b""
    names: bytes = b""
    names_off: int = 0
    entries: list = field(default_factory=list)
    nodes: list = field(default_factory=list)
    raw: bytes = b""


def _xor_stream(buf: bytearray, mt: MT19937) -> None:
    """sub_14010F5C0: dword-wise xor with (mt_next() ^ 0xB9D3018F), MT state continues."""
    for i in range(len(buf) >> 2):
        cur = int.from_bytes(buf[4 * i:4 * i + 4], "little")
        buf[4 * i:4 * i + 4] = ((cur ^ mt.next() ^ XOR_CONST) & MASK32).to_bytes(4, "little")


def _unmask_byte(buf: bytearray, k: int) -> None:
    """sub_140123DD0: every byte xor k (k is u8)."""
    k &= 0xFF
    for i in range(len(buf)):
        buf[i] ^= k


def _unmask_lcg(buf: bytearray, state: int, inc: int) -> int:
    """sub_140123CC0: dword-wise xor with an LCG keystream. Returns the new state."""
    v = state
    for i in range(len(buf) >> 2):
        cur = int.from_bytes(buf[4 * i:4 * i + 4], "little")
        buf[4 * i:4 * i + 4] = ((cur ^ v) & MASK32).to_bytes(4, "little")
        v = (inc + LCG_MUL * v) & MASK32
    return v


def parse(data: bytes, stem: str, path: str = "",
          max_entries: int = MAX_ENTRIES) -> Archive:
    """Decrypt + parse a PDT/DAT container. Raises ValueError on inconsistency.

    max_entries defaults to the 96 enforced by archive_index_load; raise it when
    probing containers that take a different load path.
    """
    arc = Archive(path=path, raw=data)
    arc.key = name_hash(stem)

    mt = MT19937(arc.key)
    mt.advance(20)

    hdr = bytearray(data[:HDR_SIZE])
    if len(hdr) < HDR_SIZE:
        raise ValueError("file shorter than 40-byte header")
    _xor_stream(hdr, mt)

    lo, hi, m = struct.unpack_from("<III", hdr, 0)
    arc.lo, arc.hi, arc.m = lo, hi, m

    # second-stage unmask of the 28-byte scratch region (header+0x0C .. +0x27)
    state = inc = 0
    if lo:
        if hi:
            arc.mode = 0x40
            s = (hi ^ lo) & MASK32
            state = (s | ((s ^ 0x6576) << 16)) & MASK32   # sub_140123DB0 -> *a4
            inc = (m * s) & MASK32                        # sub_140123DB0 -> *a5
            state = _unmask_lcg(
                memoryview(hdr)[SCRATCH_OFF:SCRATCH_OFF + SCRATCH_SIZE], state, inc)
        else:
            arc.mode = 0x100
            _unmask_byte(
                memoryview(hdr)[SCRATCH_OFF:SCRATCH_OFF + SCRATCH_SIZE], lo)

    # the game zeroes header+0x0C right after the unmask, before reading the count
    hdr[SCRATCH_OFF:SCRATCH_OFF + 4] = b"\0\0\0\0"
    arc.hdr = bytes(hdr)

    n = struct.unpack_from("<h", hdr, COUNT_OFF)[0]       # movsx rsi, word [...]
    arc.count = n
    if n < 0 or n > max_entries:
        raise ValueError(f"entry count {n} out of range 0..{max_entries}")

    idx_n = IDX_ENTRY * n
    nam_n = NAM_ENTRY * n
    arc.names_off = HDR_SIZE + idx_n
    if arc.names_off + nam_n > len(data):
        raise ValueError(
            f"tables need {arc.names_off + nam_n:#x} bytes, file is {len(data):#x}")

    index = bytearray(data[HDR_SIZE:arc.names_off])
    _xor_stream(index, mt)
    names = bytearray(data[arc.names_off:arc.names_off + nam_n])
    _xor_stream(names, mt)

    # the same unmask continues over index then names, with one shared LCG stream
    if arc.mode == 0x40:
        state = _unmask_lcg(index, state, inc)
        _unmask_lcg(names, state, inc)
    elif arc.mode == 0x100:
        _unmask_byte(index, lo)
        _unmask_byte(names, lo)

    arc.index = bytes(index)
    arc.names = bytes(names)

    for i in range(n):
        arc.entries.append(Entry(*struct.unpack_from("<III", index, IDX_ENTRY * i)))
        k, s, gt, le = struct.unpack_from("<IIQQ", names, NAM_ENTRY * i)
        arc.nodes.append(Node(key=k, slot=s, gt=gt, le=le))

    return arc


def verify(arc: Archive, filesize: int = 0, align: int = 0x800) -> list:
    """Independent self-consistency checks. Empty list == the parse is sound.

    These matter because a wrong key still produces a plausible-looking count;
    the checks below are what actually separate a real container from noise.
    """
    problems = []

    names_field = struct.unpack_from("<I", arc.hdr, 0x20)[0]
    if names_field != arc.names_off:
        problems.append(f"hdr+0x20 names_off {names_field:#x} != {arc.names_off:#x}")

    lim = NAM_ENTRY * arc.count
    for i, nd in enumerate(arc.nodes):
        for tag, v in (("gt", nd.gt), ("le", nd.le)):
            if v and not (0 <= v < lim):
                problems.append(f"node[{i}].{tag}={v:#x} outside 0..{lim:#x}")
                break
        if nd.slot >= arc.count:
            problems.append(f"node[{i}].slot={nd.slot} >= count {arc.count}")
            break

    slots = [nd.slot for nd in arc.nodes]
    if len(set(slots)) != len(slots):
        problems.append(f"slots not distinct ({len(set(slots))}/{len(slots)})")

    payload = (arc.names_off + lim + align - 1) & ~(align - 1)
    if arc.entries and arc.entries[0].c != payload:
        problems.append(f"first entry offset {arc.entries[0].c:#x} != "
                        f"aligned payload start {payload:#x}")
    end = (arc.entries[0].c if arc.entries else payload)
    for i, e in enumerate(arc.entries):
        if e.c != end:
            problems.append(f"entry[{i}] offset {e.c:#x} != expected {end:#x}")
            break
        end = (e.c + e.a + align - 1) & ~(align - 1)
    if filesize and end > filesize:
        problems.append(f"entries end {end:#x} past filesize {filesize:#x}")

    return problems


def read_entry(arc: Archive, slot: int, data: bytes = None) -> bytes:
    """Decrypt one entry payload.

    Pipeline, from archive_read_entry_simple (0x140122730):
        1. buffer_xor_decrypt(buf, len, key)   -- 0x14010F4C0, FRESH MT state,
                                                  key = pkg+0xE4 = name_hash(stem)
        2. entry_payload_transform(pkg, buf, len) -- 0x140123E90:
               mode 0x100 -> xor every byte with (lo & 0xFF)      [verified]
               mode 0x40  -> dword LCG using pkg+0xC4 / pkg+0xC8  [UNVERIFIED]
    Verified: crc32(payload[:len & ~3]) == entry.b on 50/50 entries
    across DLCBGM / DLCTEX / DLCVOICE packages.
    """
    if data is None:
        data = arc.raw
    e = arc.entries[slot]
    blob = data[e.c:e.c + e.a]
    if len(blob) < e.a:
        raise ValueError(f"entry {slot}: file truncated at {e.c:#x}+{e.a:#x}")
    return decrypt_payload(arc, blob)


def decrypt_payload(arc: Archive, blob) -> bytes:
    """Same pipeline as read_entry, for an already-extracted payload slice."""
    buf = bytearray(blob)
    buffer_xor_decrypt(buf, arc.key)
    if arc.mode == 0x100:
        # sub_140123E90 mode 0x100: xor every byte with LODWORD(hdr[0]) & 0xFF
        # NOTE: bytearray.translate returns a NEW object, it is not in-place.
        buf = buf.translate(_XOR_TABLES_get(arc.lo & 0xFF))
    elif arc.mode == 0x40:
        raise NotImplementedError(
            "mode 0x40 payload needs the LCG seed at pkg+0xC4/0xC8; unverified")
    return bytes(buf)


_XOR_TABLES = {}


def _XOR_TABLES_get(k: int) -> bytes:
    """256-byte translation table for `x ^ k` (bytearray.translate is C-speed)."""
    t = _XOR_TABLES.get(k)
    if t is None:
        t = _XOR_TABLES[k] = bytes(i ^ k for i in range(256))
    return t


def entry_crc(blob: bytes) -> int:
    """entry_payload_unmask (0x140124000).

    Its table is dword_1409BEE20; dword_1409BEE20[i] ^ 0x3FC47CDA is exactly the
    standard reflected CRC-32 table (poly 0xEDB88320), and the two xors of
    0x3FC47CDA cancel -- so this is plain CRC-32 with a 0xFFFFFFFF pre/post
    inversion. `a3 & 0xFFFFFFFC` means trailing bytes past the last whole dword
    are NOT covered.
    """
    import zlib
    return zlib.crc32(blob[:len(blob) & ~3]) & MASK32


def bst_walk(arc: Archive, needle: int) -> int:
    """entry_index_bsearch, replicated. Returns the slot or -1."""
    off = 0
    if arc.count <= 0:
        return -1
    while True:
        node = arc.nodes[off // NAM_ENTRY]
        if node.key == needle:
            return node.slot
        nxt = node.le if needle <= node.key else node.gt
        if not nxt:
            return -1
        off = nxt


def bst_sorted(arc: Archive) -> list:
    """In-order traversal, yielding (key, slot) pairs sorted by key."""
    out = []
    seen = set()

    def rec(off: int, depth: int = 0):
        if not off and depth:
            return
        if off in seen or off // NAM_ENTRY >= arc.count:
            return
        seen.add(off)
        node = arc.nodes[off // NAM_ENTRY]
        if node.le:
            rec(node.le, depth + 1)
        out.append((node.key, node.slot))
        if node.gt:
            rec(node.gt, depth + 1)

    if arc.count:
        rec(0)
    return out


def load(path) -> Archive:
    from pathlib import Path
    p = Path(path)
    return parse(p.read_bytes(), p.stem, str(p))
