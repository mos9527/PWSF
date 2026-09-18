r"""Probe: every po_lint check, shown firing on a deliberately broken .po.

A validator nobody has seen fail is indistinguishable from `return []`.  Each
case below builds a one-entry .po against a REAL reference and msgid -- so the
only thing wrong with it is the thing being tested -- runs the linter, and
asserts the exact set of error codes that comes back.

The last case is a correct translation and must produce nothing at all; it is
what keeps the other fourteen honest.

Two checks cannot be provoked from the shipped corpus, and this probe records
why rather than pretending to test them:

    ruby (dropped)  no English source string contains <R=...> at all; furigana
                    live in the Japanese CODEC text, which Steam never shipped
                    (ANALYSIS/02 §6.1).  Only the "translation ADDS ruby"
                    direction is reachable, and that is case `ruby-added`.
    target          every olang slot that has an English key also has all five
                    other language keys (3,138 == 3,138 measured below), so
                    "no slot to write into" cannot happen for any target
                    language.  That is also the answer PLANS/06 §4 needs.

Run from anywhere:  python research/TOOLS/_probe_po4.py
"""

import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config, po_export, po_lint, slots

OUT = config.BUILD_DIR / "_probe_po4"

problems = []


def pick(pred) -> tuple:
    """The first (reference, source text) pair that satisfies `pred`."""
    for ref, text in slots.sources().items():
        if ref.startswith(slots.OLANG + "/") and pred(text):
            return ref, text
    raise SystemExit("no source string matches the probe's requirement")


def write_case(name: str, entries: list) -> Path:
    """entries: list of (refs, msgid, msgstr). Returns the directory to lint."""
    d = OUT / name
    d.mkdir(parents=True, exist_ok=True)
    blocks = [po_export.HEADER.format(part=name, source="probe",
                                      count=len(entries))]
    for refs, msgid, msgstr in entries:
        block = [f"#: {r}" for r in refs]
        block.append("msgid " + po_export.po_string(msgid))
        block.append("msgstr " + po_export.po_string(msgstr))
        blocks.append("\n".join(block))
    (d / f"{name}.po").write_text("\n\n".join(blocks) + "\n", encoding="utf-8")
    return d


def run(name: str, entries: list, expect_errors: set, expect_warns=frozenset(),
        check_font: bool = False) -> None:
    rep = po_lint.lint(write_case(name, entries), check_font=check_font)
    errors = {p.code for p in rep.errors}
    warns = {p.code for p in rep.warnings}
    ok = errors == expect_errors and warns == set(expect_warns)
    print(f"  {'ok  ' if ok else 'FAIL'} {name:18} errors={sorted(errors)} "
          f"warnings={sorted(warns)}")
    if not ok:
        problems.append(f"{name}: expected errors {sorted(expect_errors)} / "
                        f"warnings {sorted(expect_warns)}, got "
                        f"{sorted(errors)} / {sorted(warns)}")
        for p in rep.problems[:3]:
            problems.append("    " + str(p).replace("\n", " "))


def main() -> None:
    config.require_game()
    if OUT.is_dir():
        shutil.rmtree(OUT)

    plain_ref, plain = pick(lambda t: t.strip() and "<" not in t
                            and "%" not in t and "\n" not in t)
    icon_ref, icon = pick(lambda t: "<I=" in t)
    fmt_ref, fmt = pick(lambda t: "%d" in t)
    print(f"probe material:\n  plain  {plain_ref}  {plain!r}\n"
          f"  icon   {icon_ref}  {icon!r}\n  fmt    {fmt_ref}  {fmt!r}\n")

    en = set(slots.olang_sources(config.LANG_EN))
    others = {name: len(en & set(slots.olang_sources(key)))
              for key, name in config.LANG_KEYS.items() if key != config.LANG_EN}
    print(f"language keys per slot: {len(en)} en slots, and every one of them "
          f"also has " + ", ".join(f"{v} {k}" for k, v in others.items()) + "\n")
    for name, shared in others.items():
        if shared != len(en):
            problems.append(f"{len(en) - shared} slot(s) have no {name} key -- "
                            f"the `target` check is reachable after all")

    print("cases:")
    run("clean", [([plain_ref], plain, "译文")], set())
    # the icon source is four lines long, so collapsing it also trips
    # line-count -- two independent defects, two independent reports
    run("icon-dropped", [([icon_ref], icon, "把图标丢掉了")], {"icon"},
        {"line-count"})
    run("icon-unterminated", [([plain_ref], plain, "按 <I=DEC 继续")], {"icon"})
    run("format-dropped", [([fmt_ref], fmt, "名称过短。\n请换一个。")],
        {"format"})
    run("format-changed", [([fmt_ref], fmt,
                            "名称过短。\n请至少输入 %s 个字符。")], {"format"})
    run("control-char", [([plain_ref], plain, "译\x00文")], {"control"})
    run("blank", [([plain_ref], plain, "   ")], {"blank"})
    run("msgid-drift", [([plain_ref], plain + " (edited)", "译文")],
        {"msgid-drift"})
    run("ref-unknown", [(["olang/009c9ea4/0x000001/0x000002"], plain, "译文")],
        {"ref"})
    run("ref-unparseable", [(["olang/009c9ea4/nope"], plain, "译文")], {"ref"})
    run("ref-missing", [([], plain, "译文")], {"ref"})
    run("conflict", [([plain_ref], plain, "译文甲"),
                     ([plain_ref], plain, "译文乙")], {"conflict"})
    run("ruby-added", [([plain_ref], plain, "译文<R=表示,よみ>")], {"ruby"})
    run("line-count", [([plain_ref], plain, "译文\n第二行")], set(),
        {"line-count"})
    # U+FFE5 fullwidth yen sits above cMaxGlyph U+FF5E: the translator table
    # cannot address it, so no font build could ever carry it
    run("font-over-maxglyph", [([plain_ref], plain, "价格：￥100")], {"font"},
        check_font=True)
    # a private-use code point: msyh.ttc maps nothing there and substitutes a
    # tofu box, which is exactly why the check compares against .notdef output
    # instead of testing for a blank bitmap
    run("font-notdef-in-ttf", [([plain_ref], plain, "译文\ue123")], {"font"},
        check_font=True)


if __name__ == "__main__":
    main()
    if problems:
        print(f"\n{len(problems)} PROBLEM(S):")
        for p in problems[:20]:
            print("  " + p)
        raise SystemExit(1)
    print("\nevery check fires on exactly its own defect, and stays quiet on a "
          "correct translation")
