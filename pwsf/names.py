"""Archive entry name hashing, reverse-engineered from METAL GEAR SOLID PEACE WALKER.exe.

Evidence chain (IDA, imagebase 0x140000000):

  entry_name_hash          0x14011F820   24-bit rolling hash, stops at '.' or NUL
  g_ext_id_table           0x140F4C7D0   pairs of (const char *ext, u32 id), 16 B/entry
  str_hash24               0x14011F780   same core, no extension handling
  entry_index_bsearch      0x140123D60   BST lookup; the a2 xor applies to the
                                         NEEDLE only, so stored node keys are raw
                                         entry_name_hash values

Algorithm (0x14011F820):

    h = 0
    for c in name:
        if c == '.' or c == 0: break
        h = (c + ((32 * h) | (h >> 19))) & 0xFFFFFF
    if h == 0: h = 1
    if name[i] == '.':
        ext = name[i+1:]
        if ext in g_ext_id_table: h |= ext_id << 24
    return h

Note (32*h) | (h >> 19) is exactly ROTL24(h, 5): 32*h occupies bits 5..28 and
h >> 19 occupies bits 0..4, they never overlap. So h = (ROTL24(h,5) + c) & 0xFFFFFF,
which is invertible: h_prev = ROTR24((h - c) & 0xFFFFFF, 5).
"""

EXT_IDS = {
    "mdpe": 0x1a, "qar": 0xf1, "vrdv": 0x21, "vrd": 0x20, "mgm": 0x30,
    "mds": 0x05, "row": 0x6e, "spk": 0x1d, "cap": 0x35, "rat": 0x6b,
    "mtfa": 0x0a, "eqp": 0x64, "psq": 0xff, "dcd": 0x1b, "mtst": 0x18,
    "gcx": 0x02, "cvd": 0x10, "bgp": 0x38, "ohd": 0x1e, "tri": 0x03,
    "rpd": 0x16, "mdp": 0x13, "vlm": 0x65, "vcpg": 0x24, "kms": 0x15,
    "la2": 0x5f, "ptcp": 0x33, "vcp": 0x23, "fcx": 0x17, "ola": 0x6d,
    "rcm": 0x6c, "lt2": 0x06, "olang": 0x5d, "mtsq": 0x09, "pcmp": 0x36,
    "vram": 0x61, "mdh": 0x04, "mmd": 0x1f, "bin": 0x01, "mdpb": 0x19,
    "img": 0x69, "mdc": 0x13, "vib": 0x6a, "zon": 0x12, "cddl": 0x34,
    "txp": 0x14, "vrdt": 0x22, "nav": 0x0f, "cmf": 0x63, "png": 0x68,
    "la3": 0x5e, "lst": 0x66, "dar": 0xf0, "ypk": 0x1c, "rlc": 0x32,
    "mtra": 0x6f, "geom": 0x0c, "cv2": 0x07, "prx": 0x31, "mtar": 0x08,
    "eft": 0x11, "slot": 0x60, "mdl": 0x13, "mtcm": 0x0b, "sep": 0x37,
    "mdb": 0x13, "cnf": 0xf2,
}

# reverse lookup: ext ids are not unique (mdp/mdc/mdl/mdb all 0x13)
ID_EXTS = {}
for _k, _v in EXT_IDS.items():
    ID_EXTS.setdefault(_v, []).append(_k)

M24 = 0xFFFFFF


def rotl24(h: int, n: int = 5) -> int:
    h &= M24
    return ((h << n) | (h >> (24 - n))) & M24


def rotr24(h: int, n: int = 5) -> int:
    h &= M24
    return ((h >> n) | (h << (24 - n))) & M24


def entry_name_hash(name) -> int:
    """0x14011F820. Accepts str or bytes (latin-1)."""
    if isinstance(name, str):
        name = name.encode("latin-1")
    i, h = 0, 0
    while i < len(name) and name[i] not in (0x00, 0x2E):
        h = (name[i] + ((32 * h) | (h >> 19))) & M24
        i += 1
    if h == 0:
        h = 1
    if i < len(name) and name[i] == 0x2E:
        ext = name[i + 1:].split(b"\0")[0].decode("latin-1")
        eid = EXT_IDS.get(ext)
        if eid is not None:
            h |= eid << 24
    return h


def str_hash24(s) -> int:
    """0x14011F780: entry_name_hash without the extension stage."""
    if isinstance(s, str):
        s = s.encode("latin-1")
    h = 0
    for c in s:
        if c == 0:
            break
        h = (c + ((32 * h) | (h >> 19))) & M24
    return h if h else 1


def invert(target: int, maxlen: int = 24,
           alphabet: bytes = bytes(range(0x20, 0x7F))) -> list:
    """All plaintext preimages of a 24-bit hash, searched backwards from the end.

    Only the low 24 bits are matched; pass the full key and mask separately if
    the extension id is present.
    """
    target &= M24
    out = []

    def rec(h: int, suffix: bytes, depth: int):
        if depth > maxlen:
            return
        if h == 0 and suffix:
            out.append(suffix)
        if h == 1 and not suffix:
            return
        for c in alphabet:
            prev = rotr24((h - c) & M24)
            if prev == 0 and suffix:
                out.append(bytes([c]) + suffix)
            else:
                rec(prev, bytes([c]) + suffix, depth + 1)

    rec(target, b"", 0)
    return sorted(set(out))
