#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""§13.7 方案 A：把小字体重定向到我们扩的全字库（改 exe）。

做法：让 `g_font_small` 加载 `0007ccd8.xpr`（4096x4096 全字库）而不是
`000ebbe8.xpr`（2048x1024，只有 155 字），并把它的图集尺寸常量从
2048x1024 改成 4096x4096。这样所有走小字体的界面（如 DATABASE 人员档案）
都直接出全字，排版零变化（两字体度量完全相同，§13.1）。

三处补丁（均来自 ANALYSIS/05_font.md §1 / §13.7）：
  1. 文件名串 "000ebbe8.xpr" -> "0007ccd8.xpr"（同长 9，原地替换）
     位置：字符串表（默认分支 v1 的名）
  2. font_init_load_all 里小字体的高：
       mov r9d, 400h  (1024)  ->  mov r9d, 1000h  (4096)   @ 0x14004363B
  3. 小字体的宽：
       mov r8d, 800h  (2048)  ->  mov r8d, 1000h  (4096)   @ 0x140043645

补丁前会逐字节校验目标位置确实是预期原字节，否则拒绝（避免版本不符误改）。

用法：
  python _probe_font_redirect.py --dry-run      # 只打印将改的字节
  python _probe_font_redirect.py --apply        # 备份 .orig 并打补丁
  python _probe_font_redirect.py --restore      # 还原
"""
import argparse
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from pwsf import config  # noqa: E402

IMAGE_BASE = 0x140000000

# (description, rva, expected_bytes, new_bytes)
PATCHES = [
    ("small font filename 000ebbe8.xpr -> 0007ccd8.xpr", None,
     b"000ebbe8.xpr", b"0007ccd8.xpr"),
    ("small font height 1024 -> 4096 (mov r9d,400h->1000h)", 0x14004363B,
     bytes([0x41, 0xB9, 0x00, 0x04, 0x00, 0x00]),
     bytes([0x41, 0xB9, 0x00, 0x10, 0x00, 0x00])),
    ("small font width 2048 -> 4096 (mov r8d,800h->1000h)", 0x140043645,
     bytes([0x41, 0xB8, 0x00, 0x08, 0x00, 0x00]),
     bytes([0x41, 0xB8, 0x00, 0x10, 0x00, 0x00])),
]


def find_exe() -> Path:
    gd = config.GAME_DIR
    cands = list(gd.glob("*.exe"))
    if not cands:
        raise SystemExit(f"no .exe in {gd}")
    # 主程序 exe（非 launcher）
    for c in cands:
        if "launcher" not in c.name.lower():
            return c
    return cands[0]


def rva_to_off(data: bytes, rva: int) -> int:
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != 0x20B:
        raise SystemExit("not PE32+")
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    sect = opt + 240  # sizeof optional header for PE32+
    for _ in range(num_sections):
        va, sz, raw = struct.unpack_from("<I", data, sect + 12)[0], \
            struct.unpack_from("<I", data, sect + 16)[0], \
            struct.unpack_from("<I", data, sect + 20)[0]
        if va <= rva < va + sz:
            return raw + (rva - va)
        sect += 40
    raise SystemExit(f"rva {rva:#x} not in any section")


def main():
    ap = argparse.ArgumentParser(description="redirect small font to full atlas (exe patch)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--restore", action="store_true")
    args = ap.parse_args()
    if sum([args.dry_run, args.apply, args.restore]) != 1:
        ap.error("exactly one of --dry-run / --apply / --restore")

    exe = find_exe()
    orig = exe.with_suffix(exe.suffix + ".orig")
    data = bytearray(exe.read_bytes())

    if args.restore:
        if not orig.exists():
            raise SystemExit(f"no backup {orig}")
        orig.replace(exe)
        print(f"restored {exe}")
        return

    # locate string patch by scanning (the 4 font names live in one table)
    changes = []  # (off, old, new, desc)
    for desc, rva, old, new in PATCHES:
        if rva is None:
            idx = data.find(old)
            if idx < 0:
                raise SystemExit(f"string {old!r} not found (wrong build?)")
            # ensure only one occurrence of the .xpr name
            if data.count(old) != 1:
                raise SystemExit(f"{old!r} appears {data.count(old)} times, "
                                  f"refusing")
            changes.append((idx, bytes(old), bytes(new), desc))
        else:
            off = rva_to_off(bytes(data), rva - IMAGE_BASE)
            cur = bytes(data[off:off + len(old)])
            if cur != old:
                raise SystemExit(f"{desc}: bytes at {rva:#x} are "
                                 f"{cur.hex()} not {old.hex()} (wrong build?)")
            changes.append((off, old, new, desc))

    if args.dry_run:
        for off, old, new, desc in changes:
            print(f"  {desc}\n    @{off:#x}  {bytes(old).hex()} -> {bytes(new).hex()}")
        print(f"\n{len(changes)} patch(es) would apply to {exe.name}; "
              f"no bytes written")
        return

    # --apply
    if not orig.exists():
        orig.write_bytes(bytes(data))
        print(f"backup -> {orig}")
    for off, old, new, desc in changes:
        data[off:off + len(new)] = new
        print(f"  patched {desc}")
    exe.write_bytes(bytes(data))
    print(f"wrote {exe} ({len(changes)} patches)")


if __name__ == "__main__":
    main()
