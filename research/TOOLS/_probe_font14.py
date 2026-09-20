"""_probe_font14.py — pixel-font 拦截：只拦 meta==1 的槽位，别的照旧。

ANALYSIS/05_font.md §15 证明 olang 的 `key.meta` 是字体选择器：`0x1` 的文本
用 `Text/*.txp` 里那张 512x512 BC3 像素字图集画，而那张图集一个汉字都没有。
于是 `po_export` 默认不导出这批槽位，`po_lint` 对译了中文的报
`pixel-font` 错误。

本探针按 _probe_po4.py 的规矩做端到端：每条校验各自触发，且**正确的译文不报**。

    case 1  meta==1 的槽位填中文  -> 1 个 pixel-font ERROR
    case 2  meta==0x402 的槽位填中文 -> 0 个 pixel-font
    case 3  meta==1 的槽位留空    -> 0 个 pixel-font（不译就没事）
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config, po_lint, slots           # noqa: E402

CN = "按下开始"


def pick(refs, sources, limit=40):
    """A short single-line source with no markup, so only our check can fire."""
    out = []
    for r in sorted(refs):
        s = sources.get(r, "")
        if not s.strip() or len(s) > 24:
            continue
        if any(x in s for x in ("<I=", "<R=", "%", "\n", "\\n")):
            continue
        out.append((r, s))
        if len(out) >= limit:
            break
    return out


def write_po(path: Path, ref: str, msgid: str, msgstr: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'#: {ref}\nmsgid "{msgid}"\nmsgstr "{msgstr}"\n', encoding="utf-8")


def main() -> None:
    config.require_game()
    sources = slots.sources()
    pixel = slots.pixel_font_refs()
    print(f"pixel-font slots: {len(pixel)}")

    pix = pick(pixel, sources)
    normal = pick(set(sources) - set(pixel) - {
        r for r in sources if r.startswith("codec/")}, sources)
    if not pix or not normal:
        raise SystemExit("could not find sample slots")

    ref_p, msgid_p = pix[0]
    ref_n, msgid_n = normal[0]
    print(f"  meta 0x1   sample: {ref_p}  {msgid_p!r}")
    print(f"  meta 0x402 sample: {ref_n}  {msgid_n!r}")

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        write_po(root / "a.po", ref_p, msgid_p, CN)
        rep = po_lint.lint(root, check_font=False)
        got = [p for p in rep.problems if p.code == "pixel-font"]
        print(f"\ncase 1  meta==1 + Chinese: {len(got)} pixel-font error(s), "
              f"severity={[p.severity for p in got]}")
        for p in got:
            print(f"        {p.where}: {p.message[:90]}")
        assert len(got) == 1 and got[0].severity == "error", "case 1 failed"

        write_po(root / "a.po", ref_n, msgid_n, CN)
        rep = po_lint.lint(root, check_font=False)
        got = [p for p in rep.problems if p.code == "pixel-font"]
        print(f"case 2  meta==0x402 + Chinese: {len(got)} pixel-font error(s) "
              f"(expected 0)")
        assert not got, "case 2 failed: a normal slot was rejected"

        write_po(root / "a.po", ref_p, msgid_p, "")
        rep = po_lint.lint(root, check_font=False)
        got = [p for p in rep.problems if p.code == "pixel-font"]
        print(f"case 3  meta==1 left empty: {len(got)} pixel-font error(s) "
              f"(expected 0)")
        assert not got, "case 3 failed: an untranslated slot was rejected"

    print("\nOK: only meta==1 slots with non-Latin-1 text are rejected")


if __name__ == "__main__":
    main()
