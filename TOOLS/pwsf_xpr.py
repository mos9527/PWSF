"""PWSF XPR2 container (Xbox 360 resource package) reader / writer.

Layout, from xpr_package_load @ 0x140042630 (everything big-endian):

    +0   'XPR2'                 compared against 1481658930 = 0x58505232
    +4   u32 header_size
    +8   u32 data_size
    +12  header block           header_size bytes
         +0  u32 resource count
         +4  directory, 24 B/entry:
               +0  u32 type tag ('TX2D' / 'USER')
               +4  u32 offset into the HEADER block
               +8  u32 size
               +16 u32 offset of the NUL-terminated name (header block)
         then the name strings and the resource payloads
         data block             data_size bytes

Encryption: the loader seeds one MT stream with name_hash(path) and then calls
the resumable decrypt three times, for 12 / header_size / data_size bytes.
All three lengths are multiples of 4, so no partial keystream word is carried
across the boundaries and the result is identical to decrypting the whole file
as one contiguous stream -- which is what buffer_xor_decrypt does.  save()
asserts that alignment so the equivalence keeps holding after a rebuild.
"""

import struct
from dataclasses import dataclass
from pathlib import Path

from pwsf_crypto import name_hash, buffer_xor_decrypt

MAGIC = b"XPR2"
PROLOGUE = 12
DIR_ENTRY = 24


@dataclass
class XprResource:
    tag: bytes
    name: str
    offset: int
    size: int
    name_off: int


class XprPackage:
    def __init__(self, header: bytearray, data: bytearray, resources: list):
        self.header = header
        self.data = data
        self.resources = resources

    # ---------------------------------------------------------------- load

    @classmethod
    def parse(cls, plain: bytes) -> "XprPackage":
        if plain[:4] != MAGIC:
            raise ValueError(f"bad XPR2 magic: {plain[:4]!r}")
        header_size, data_size = struct.unpack_from(">II", plain, 4)
        if PROLOGUE + header_size + data_size != len(plain):
            raise ValueError(
                f"size mismatch: 12+{header_size}+{data_size} != {len(plain)}")

        header = bytearray(plain[PROLOGUE:PROLOGUE + header_size])
        data = bytearray(plain[PROLOGUE + header_size:])

        count, = struct.unpack_from(">I", header, 0)
        resources = []
        for i in range(count):
            e = 4 + DIR_ENTRY * i
            tag, off, size = struct.unpack_from(">4sII", header, e)
            name_off, = struct.unpack_from(">I", header, e + 16)
            end = header.find(b"\x00", name_off)
            resources.append(XprResource(
                tag, header[name_off:end].decode("ascii"), off, size, name_off))
        return cls(header, data, resources)

    @classmethod
    def load(cls, path) -> "XprPackage":
        path = Path(path)
        raw = bytearray(path.read_bytes())
        return cls.parse(bytes(buffer_xor_decrypt(raw, name_hash(path.stem))))

    # ---------------------------------------------------------------- access

    def resource(self, name: str) -> XprResource:
        for r in self.resources:
            if r.name == name:
                return r
        raise KeyError(f"no resource named {name!r} (have "
                       f"{[r.name for r in self.resources]})")

    def blob(self, name: str) -> bytearray:
        r = self.resource(name)
        return self.header[r.offset:r.offset + r.size]

    def replace_tail_resource(self, name: str, payload: bytes) -> None:
        """Replace a resource that is the LAST thing in the header block.

        Only the tail case is supported on purpose: every other resource would
        shift, and the directory stores absolute header-block offsets, so a
        general repack needs the name table moved too.  For the fonts the
        growing resource ('FontData') is already last, so this is enough.
        """
        r = self.resource(name)
        tail = max(x.offset + x.size for x in self.resources)
        if r.offset + r.size != tail:
            raise ValueError(f"{name!r} is not the last resource in the header")

        # whatever padding follows the last resource is preserved verbatim
        slack = bytes(self.header[r.offset + r.size:])
        self.header[r.offset:] = payload + slack
        # keep header_size a multiple of 4 (see module docstring)
        if len(self.header) % 4:
            self.header.extend(b"\x00" * (4 - len(self.header) % 4))
        r.size = len(payload)

    # ---------------------------------------------------------------- build

    def build(self) -> bytes:
        for i, r in enumerate(self.resources):
            e = 4 + DIR_ENTRY * i
            struct.pack_into(">4sII", self.header, e, r.tag, r.offset, r.size)
            struct.pack_into(">I", self.header, e + 16, r.name_off)
        if len(self.header) % 4:
            raise ValueError("header_size must stay a multiple of 4")
        out = bytearray(MAGIC)
        out += struct.pack(">II", len(self.header), len(self.data))
        out += self.header
        out += self.data
        return bytes(out)

    def save(self, path, key: int = None) -> int:
        path = Path(path)
        if key is None:
            key = name_hash(path.stem)
        blob = bytearray(self.build())
        path.write_bytes(bytes(buffer_xor_decrypt(blob, key)))
        return len(blob)
