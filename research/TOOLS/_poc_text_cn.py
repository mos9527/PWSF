r"""PoC: translate a real UI screen to Chinese, end to end.

Chain exercised:
    translations -> olang rebuild -> re-encrypt      (pwsf_olang_build)
                 -> needed code points -> font build (pwsf_font_build)
                 -> install both, with backups

Target: group 0x9B86AB of MLG/Text/009c9ea4.olang, the player-name / password
screen the font PoC screenshot came from.  Eight strings, including two that
carry a %d format specifier -- deliberately kept, so the rebuild is proven not
to disturb inline markup.

The English slot is the one rewritten, because that is the language the game is
running in.  Picking a proper target slot is calendar item 06 section 4.

Usage:
    python _poc_text_cn.py             # build + verify into ..\BUILD
    python _poc_text_cn.py --install   # back up and install
    python _poc_text_cn.py --restore   # undo
"""

import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash, buffer_xor_decrypt
from pwsf_font_build import build_font, verify_coverage
from pwsf_olang import parse, string_at
from pwsf_olang_build import OlangBuilder

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "BUILD"

TEXT_FILE = "009c9ea4"
FONT_FILE = "0007ccd8"
GROUP = 0x9B86AB
LANG_EN = 0x0D0E

TRANSLATIONS = {
    0x0198DA: "不修改密码就离开吗？",
    0x3020BC: "玩家名一经确定便无法更改。",
    # line breaks are a real 0x0A, not the two characters '\' 'n' (_probe_olang4)
    0x3F2C7B: "所选名称过短。\n请输入长度超过 %d 个字符的名称。",
    0x4C248F: "返回标题画面吗？",
    0x518104: "请输入玩家名。",
    0x51EEA1: "请修改密码。",
    0x5F42B2: "所选名称过短。\n请输入长度超过 %d 个字符的名称。",
    0x75BF6E: "其中包含本游戏无法使用的字词。",
}


def pristine(stem: str) -> Path:
    for sub in ("MLG/Text", "FONT"):
        p = GAME / sub.replace("/", "\\") / f"{stem}.{'olang' if sub.endswith('Text') else 'xpr'}"
        bak = p.with_suffix(p.suffix + ".orig")
        if p.exists():
            return bak if bak.exists() else p
    raise FileNotFoundError(stem)


def build_text() -> Path:
    BUILD.mkdir(exist_ok=True)
    src = pristine(TEXT_FILE)
    key = name_hash(TEXT_FILE)
    tbl = parse(bytes(buffer_xor_decrypt(bytearray(src.read_bytes()), key)))
    b = OlangBuilder(tbl)

    print(f"{src.name}: {len(tbl.keys)} strings, rewriting group {GROUP:#x} "
          f"(en slot)")
    for entry, zh in TRANSLATIONS.items():
        before = b.get_text(GROUP, entry, LANG_EN)
        b.set_text(GROUP, entry, LANG_EN, zh)
        print(f"  {entry:#08x}  {before[:44]!r}")
        print(f"            -> {zh!r}")

    out = BUILD / f"{TEXT_FILE}.olang"
    blob = bytearray(b.serialize())
    out.write_bytes(bytes(buffer_xor_decrypt(blob, key)))
    print(f"  wrote {out} ({out.stat().st_size} bytes, "
          f"original {src.stat().st_size})")
    return out


def verify_text(built: Path) -> None:
    tbl = parse(bytes(buffer_xor_decrypt(bytearray(built.read_bytes()),
                                         name_hash(TEXT_FILE))))
    b = OlangBuilder(tbl)
    problems = []
    for entry, zh in TRANSLATIONS.items():
        got = b.get_text(GROUP, entry, LANG_EN)
        if got != zh:
            problems.append(f"{entry:#08x}: {got!r} != {zh!r}")
        if ("%d" in zh) != ("%d" in got):
            problems.append(f"{entry:#08x}: %d specifier lost")

    # everything outside the rewritten group must be untouched
    orig = parse(bytes(buffer_xor_decrypt(bytearray(pristine(TEXT_FILE).read_bytes()),
                                          name_hash(TEXT_FILE))))
    changed = 0
    for g in orig.groups:
        for ei in range(g.entry_start, g.entry_start + g.entry_count):
            e = orig.entries[ei]
            for ki in range(e.key_start, e.key_start + e.key_count):
                a = string_at(orig, orig.keys[ki][1])
                c = string_at(tbl, tbl.keys[ki][1])
                if a != c:
                    changed += 1
                    if g.key != GROUP:
                        problems.append(f"string outside the target group "
                                        f"changed: group {g.key:#x} entry {e.key:#x}")
    print(f"  {changed} strings differ from the original "
          f"(expected {len(TRANSLATIONS)})")
    if problems:
        print("\nPROBLEMS:")
        for p in problems[:10]:
            print("  " + p)
        raise SystemExit(1)


def needed_codepoints() -> set:
    return {ord(c) for zh in TRANSLATIONS.values() for c in zh}


def install(pairs) -> None:
    for built, dst in pairs:
        bak = dst.with_suffix(dst.suffix + ".orig")
        if not bak.exists():
            shutil.copy2(dst, bak)
            print(f"backed up -> {bak.name}")
        shutil.copy2(built, dst)
        print(f"installed -> {dst}")


def restore() -> None:
    for dst in (GAME / "MLG" / "Text" / f"{TEXT_FILE}.olang",
                GAME / "FONT" / f"{FONT_FILE}.xpr"):
        bak = dst.with_suffix(dst.suffix + ".orig")
        if bak.exists():
            shutil.copy2(bak, dst)
            print(f"restored {dst.name}")
        else:
            print(f"no backup for {dst.name}, left alone")


def main() -> None:
    if "--restore" in sys.argv:
        restore()
        return

    built_text = build_text()
    verify_text(built_text)

    cps = needed_codepoints()
    print(f"\ntranslations need {len(cps)} distinct code points")
    built_font = BUILD / f"{FONT_FILE}.xpr"
    build_font(cps, pristine(FONT_FILE), built_font)
    bad = verify_coverage(built_font, cps)
    if bad:
        print("PROBLEMS: still uncovered: "
              + " ".join(f"U+{c:04X} {chr(c)}" for c in bad))
        raise SystemExit(1)
    print("  coverage verified: every needed code point has a non-blank glyph")

    print("\nbuild OK")
    if "--install" in sys.argv:
        install([(built_text, GAME / "MLG" / "Text" / f"{TEXT_FILE}.olang"),
                 (built_font, GAME / "FONT" / f"{FONT_FILE}.xpr")])


if __name__ == "__main__":
    main()
