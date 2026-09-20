"""_fix_untranslated.py —— 把「机翻照抄原文」的条目清掉，好让下一轮重翻

机翻偶尔直接把英文原文塞进 `msgstr`：专名、图标引用、缩写是**对的**
（`FSLN`、`<I=SEL>`、`VOCALOID`、`LIQUID M.` 本就该保留），但整句英文照抄是
漏译，留着就是游戏里冒出一段英文。

判据（保守，只有确定是漏译才动）：
    `<I=...>` 图标引用        -> 保留
    没有小写字母（缩写/代号） -> 保留
    长度 <= 8                 -> 保留
    其余（含小写、成句的英文） -> 清空，等下一轮 `translate.py` 重翻

顺带说明 `po_import` 那边：译文与原文逐字节相同时写入是 no-op，
`build_table` 会跳过它并计数（不再计入 `written`），所以这类条目不会让
`verify_table` 的 "changed == len(written)" 失衡。

用法：
    python research\\TOOLS\\_fix_untranslated.py            # 只报告
    python research\\TOOLS\\_fix_untranslated.py --apply     # 清空并重扫
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import poio                                    # noqa: E402
from pwsf import config, slots                 # noqa: E402


def looks_kept(text: str) -> bool:
    """该不该保留英文原文。"""
    return "<I=" in text or not re.search("[a-z]", text) or len(text) <= 8


def main():
    apply = "--apply" in sys.argv
    sources = slots.sources()
    miss, keep = [], []
    for path in sorted(Path(config.PO_DIR).rglob("*.po")):
        entries, _ = poio.parse(path)
        for e in entries:
            if not e.msgstr:
                continue
            for r in e.refs:
                if sources.get(r) != e.msgstr:
                    continue
                (keep if looks_kept(e.msgstr) else miss).append((path, e))

    print(f"译文 == 原文：{len(miss) + len(keep)} 条")
    print(f"  保留合理（图标/缩写/短串）：{len(keep)} 条")
    print(f"  疑似漏译（将清空重翻）    ：{len(miss)} 条")
    if not apply:
        for path, e in miss[:20]:
            print(f"    {path.name}:{e.msgstr_line}  {e.msgid[:60]!r}")
        print("\n加 --apply 才会写回")
        return

    by_path = {}
    for path, e in miss:
        by_path.setdefault(path, {})[e.msgstr_line] = ""
    for path, mapping in sorted(by_path.items()):
        poio.commit(path, mapping, poio.eol_of(path))
        print(f"  清空 {path.name}: {len(mapping)} 条")

    left = 0
    for path in sorted(Path(config.PO_DIR).rglob("*.po")):
        for e in poio.parse(path)[0]:
            if e.msgstr and any(sources.get(r) == e.msgstr for r in e.refs):
                left += 1
    print(f"重扫：仍有 {left} 条译文 == 原文（应当只剩保留合理的那些）")


if __name__ == "__main__":
    main()
