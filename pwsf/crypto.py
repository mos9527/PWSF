"""PWSF crypto primitives, reverse-engineered from METAL GEAR SOLID PEACE WALKER.exe.

Evidence chain (IDA, imagebase 0x140000000):
  name_hash                0x14010F450
  mt_twist                 0x14010F250
  mt_next                  0x14010ED60
  mt_advance               0x14010ED90
  mt_seed                  0x14010F000
  mt_alloc                 0x14010ED00   (state size 0x1388 = 1250 * u32)
  buffer_xor_decrypt       0x14010F4C0
  olang_path_decrypt_and_store 0x140085900
"""

import struct

MASK32 = 0xFFFFFFFF

# mt_mag01_a @ 0x140F4C7C0 = {0, 0x9908B0DF}  (standard MT19937)
MATRIX_A = 0x9908B0DF
# mt_temper_mask_shl7  @ 0x1409BD930 = 0xFF3A58AD  == (0x9D2C5680 >> 7) on the bits that survive <<7
# mt_temper_mask_shl15 @ 0x1409BD940 = 0xFFFFDF8C  == (0xEFC60000 >> 15) on the bits that survive <<15
MASK_SHL7 = 0xFF3A58AD
MASK_SHL15 = 0xFFFFDF8C
# buffer_xor_decrypt XOR constant
XOR_CONST = 0xB9D3018F

UPPER_MASK = 0x80000000
LOWER_MASK = 0x7FFFFFFF
N = 624
M = 397


def name_hash(path: str) -> int:
    """Hash used to derive an .olang decryption key from its resource path.

    Replicates 0x14010F450:
      1. take the basename: everything after the LAST occurrence of '/', ':' or '\\'
         (bitmap 0x200000000801 tested against (c - 47))
      2. hash the basename up to the first '.' (or NUL)
         h = 7477 * c + 144751 * h   (mod 2^32)
    """
    mask = 0x200000000801
    start = 0
    for idx, ch in enumerate(path.encode("latin-1")):
        d = (ch - 47) & 0xFF
        if d <= 0x2D and ((mask >> d) & 1):
            start = idx + 1

    h = 0
    for ch in path.encode("latin-1")[start:]:
        if ch == 0x2E:  # '.' stops the hash
            break
        h = (7477 * ch + 144751 * h) & MASK32
    return h


class MT19937:
    """MT19937 with the game's custom LCG seeding (0x14010F000).

    State layout (as allocated by mt_alloc, 0x1388 bytes):
        [0]      index
        [1..624] mt[0..623]
        [625]    mt[624] (wrap sentinel, == mt[0] after twist)
        [626..]  624 pre-tempered outputs, consumed by mt_next
    """

    def __init__(self, seed: int):
        self.mt = [0] * (N + 1)
        self.tempered = [0] * N
        self.index = 0

        x = seed & MASK32
        for i in range(N):
            y = (69069 * x + 1) & MASK32
            self.mt[i] = (x & 0xFFFF0000) | (y >> 16)
            x = (69069 * y + 1) & MASK32

        self._twist()

    def _twist(self) -> None:
        mt = self.mt
        for i in range(N - M):  # 227
            y = (mt[i] & UPPER_MASK) | (mt[i + 1] & LOWER_MASK)
            mt[i] = mt[i + M] ^ (y >> 1) ^ (MATRIX_A if (y & 1) else 0)
        mt[N] = mt[0]
        for i in range(N - M, N):  # 397
            y = (mt[i] & UPPER_MASK) | (mt[i + 1] & LOWER_MASK)
            mt[i] = mt[i + (M - N)] ^ (y >> 1) ^ (MATRIX_A if (y & 1) else 0)
        self._retemper()

    def _retemper(self) -> None:
        mt = self.mt
        t = self.tempered
        for i in range(N):
            y = mt[i]
            y ^= y >> 11
            y ^= (y & MASK_SHL7) << 7
            y &= MASK32
            y ^= (y & MASK_SHL15) << 15
            y &= MASK32
            y ^= y >> 18
            t[i] = y

    def next(self) -> int:
        if self.index >= N:
            self._twist()
            self.index = 0
        v = self.tempered[self.index]
        self.index += 1
        return v

    def advance(self, n: int) -> None:
        """Replicates mt_advance (0x14010ED90).

        NOTE: the argument is byte-scaled -- the effective output skip is
        (n >> 2) + current_index.  mt_advance(state, 20) therefore skips 5.
        """
        v3 = (n >> 2) + self.index
        full = v3 // N
        rem = v3 % N
        for _ in range(full):
            self._twist()
            self.index = 0
        self.index = rem


def buffer_xor_decrypt(data: bytearray, key: int) -> bytearray:
    """In-place XOR decryption, replicating 0x14010F4C0 + mt_advance(..., 20).

    The dword loop is vectorised through a single big-integer xor; the keystream
    itself still has to come out of MT one word at a time.
    """
    mt = MT19937(key)
    mt.advance(20)

    n = len(data)
    nd = n >> 2
    if nd:
        ks = struct.pack("<%dI" % nd,
                         *[(mt.next() ^ XOR_CONST) & MASK32 for _ in range(nd)])
        end = 4 * nd
        merged = int.from_bytes(data[:end], "little") ^ int.from_bytes(ks, "little")
        data[:end] = merged.to_bytes(end, "little")

    rem = n & 3
    if rem:
        k = mt.next() ^ XOR_CONST
        off = 4 * nd
        for j in range(rem):
            data[off + j] ^= k & 0xFF
            k >>= 8
    return data
