"""_probe_font11.py — 那张 512x512 BC3 像素字体在哪一个文件里。

RenderDoc 抓帧里有一张 512x512 / BC3_UNORM 的 ASCII 图集（`ResourceId::6091`，
抓帧里还有一张几乎相同的 `ResourceId::6087`），字形是七段码风格的像素字，与
FONT/*.xpr 那两张 ATG 字体（4096x4096 与 2048x1024，8 位单通道、线性）完全不是
一个体系：既不是 XPR2 容器，也没有 FontData 描述。

本探针把显存里取出来的原始 BC3 字节（未解码）在游戏目录的所有贴图包里逐字节
搜，定位来源文件与偏移，并判断文件里那一份与显存里那一份是不是同一张。

输入：research/BUILD/_rd_tex*.bin
      （RenderDoc execute_python 落盘：controller.GetTextureData 的原始 store）
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config                                    # noqa: E402
from pwsf.crypto import buffer_xor_decrypt, name_hash      # noqa: E402

BUILD = Path(__file__).resolve().parents[1] / "BUILD"
EXPECTED = 512 * 512          # BC3 is 1 byte per pixel


def pick_needle(d: bytes) -> tuple:
    """A 64-byte window that is not blank, so it is identifying."""
    for o in range(0, len(d) - 64, 16):
        chunk = d[o:o + 64]
        if len(set(chunk)) > 8:
            return o, chunk
    return 0, d[:64]


def describe(blob: bytes, here: bytes) -> str:
    diff = [i for i, (a, b) in enumerate(zip(here, blob)) if a != b]
    if not diff:
        return "IDENTICAL"
    # is the difference local (a few glyphs redrawn) or spread over the image?
    blocks = {i // 4096 for i in diff}
    return (f"{len(diff)} bytes differ, first at {diff[0]:#x}, "
            f"{len(blocks)}/{len(blob) // 4096} 4K-blocks touched")


def main() -> None:
    dumps = sorted(BUILD.glob("_rd_tex*.bin"))
    if not dumps:
        raise SystemExit(f"no _rd_tex*.bin in {BUILD} -- dump from RenderDoc first")

    game = config.GAME_DIR
    cands = sorted(game.glob("Text/*.txp")) + sorted(game.glob("loading/*.txp"))
    cands += sorted(game.glob("*.txp"))
    seen = []
    cands = [p for p in cands if not (p in seen or seen.append(p))]

    for dump in dumps:
        blob = dump.read_bytes()
        at, needle = pick_needle(blob)
        print(f"\n=== {dump.name}: {len(blob)} B "
              f"(expected {EXPECTED}) needle @ {at:#x} ===")
        for p in cands:
            raw = p.read_bytes()
            try:
                data = bytes(buffer_xor_decrypt(bytearray(raw), name_hash(p.stem)))
            except Exception as exc:                        # noqa: BLE001
                print(f"  {p.name}: decrypt failed: {exc}")
                continue
            i = data.find(needle)
            if i < 0:
                continue
            print(f"  HIT {p.relative_to(game)} @ {i:#x} ({i})  "
                  f"{describe(blob, data[i:i + len(blob)])}")


if __name__ == "__main__":
    main()
