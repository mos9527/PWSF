r"""Validate translated .po files before anything gets compiled.

Every check here exists because breaking it yields a *broken* game rather than
a merely ugly one; PLANS/06 §6 is the list this implements.

    ref             the reference resolves to a real slot
    msgid-drift     the msgid still equals the source text, byte for byte
    icon            <I=...> button/icon references survive verbatim (01 §4)
    format          %d and friends survive, same specifiers, same order
    ruby            <R=表示,よみ> is never dropped silently (03 号)
    control         no NUL or stray control byte -- the pool is NUL-terminated
    blank           a non-empty source never becomes whitespace-only
    conflict        two entries must not write the same slot differently
    font            every code point can be carried by the rebuilt font (05 号)

`msgid-drift` is the load-bearing one: it is what makes a reference trustworthy
as a write-back address.  If the corpus is re-exported and a slot's English
text changed, the translation attached to it is stale and must not be written.

Warnings do not block: line-count changes are usually a deliberate re-break,
and CODEC references cannot be delivered yet (write-back is blocked on
ANALYSIS/03 §2), but neither makes the olang build wrong.
"""

import argparse
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import config, font_build, po, slots

ICON_RE = re.compile(r"<I=[^>]*>")
RUBY_RE = re.compile(r"<R=[^>]*>")
# printf specifiers as the game's vsnprintf-style formatters accept them
FORMAT_RE = re.compile(r"%[-+ #0]*[0-9]*(?:\.[0-9]+)?(?:hh|h|ll|l|L|z|j|t)?"
                       r"[diuoxXfFeEgGaAcsp%]")
ALLOWED_CONTROL = {"\n", "\r", "\t"}

ERROR = "error"
WARN = "warn"


def lang_key(name: str) -> int:
    """LANG_KEYS id for a short language name, e.g. "en" -> 0x0D0E."""
    for k, v in config.LANG_KEYS.items():
        if v == name:
            return k
    raise SystemExit(f"unknown language {name!r}; "
                     f"known: {', '.join(config.LANG_KEYS.values())}")


@dataclass
class Problem:
    severity: str
    code: str
    where: str
    message: str

    def __str__(self) -> str:
        return f"{self.severity:5} {self.code:12} {self.where}  {self.message}"


@dataclass
class Report:
    problems: list = field(default_factory=list)
    translations: dict = field(default_factory=dict)   # reference -> msgstr
    stats: dict = field(default_factory=dict)

    @property
    def errors(self) -> list:
        return [p for p in self.problems if p.severity == ERROR]

    @property
    def warnings(self) -> list:
        return [p for p in self.problems if p.severity == WARN]

    def add(self, severity, code, where, message) -> None:
        self.problems.append(Problem(severity, code, where, message))


def _control_chars(s: str) -> list:
    return sorted({c for c in s if ord(c) < 0x20 and c not in ALLOWED_CONTROL}
                  | {c for c in s if ord(c) == 0x7F})


def _markup(rep: Report, where: str, msgid: str, msgstr: str,
            allow_ruby_drop: bool) -> None:
    for code, rx in (("icon", ICON_RE), ("format", FORMAT_RE)):
        src, dst = sorted(rx.findall(msgid)), sorted(rx.findall(msgstr))
        if src != dst:
            rep.add(ERROR, code, where,
                    f"source has {src or 'none'}, translation has {dst or 'none'}")
    # an unterminated <I= would be written into the pool as plain text and the
    # icon would never render, so count the openers too
    if msgstr.count("<I=") != len(ICON_RE.findall(msgstr)):
        rep.add(ERROR, "icon", where, "unterminated <I= in the translation")

    src_ruby, dst_ruby = RUBY_RE.findall(msgid), RUBY_RE.findall(msgstr)
    if src_ruby and not dst_ruby:
        rep.add(WARN if allow_ruby_drop else ERROR, "ruby", where,
                f"{len(src_ruby)} ruby annotation(s) dropped: "
                + " ".join(src_ruby[:3]))
    elif len(dst_ruby) > len(src_ruby):
        rep.add(ERROR, "ruby", where,
                f"translation adds ruby the source never had: {dst_ruby[0]}")


def lint(po_dir=None, lang: int = config.LANG_EN, allow_ruby_drop: bool = False,
         check_font: bool = True) -> Report:
    po_dir = po_dir or config.PO_DIR
    rep = Report()
    sources = slots.sources()
    # the source is always English; `lang` is the slot being written, and a
    # non-English target only exists for entries that ship that language
    targets = None if lang == config.LANG_EN else set(slots.olang_sources(lang))
    owner = {}          # reference -> (where, msgstr) of the entry that claims it
    counts = dict(files=len(po.po_files(po_dir)), entries=0, translated=0,
                  refs=0, olang_slots=0, codec_slots=0)

    for path, e in po.iter_entries(po_dir):
        where = f"{path.name}:{e.lineno}"
        counts["entries"] += 1

        if not e.refs:
            rep.add(ERROR, "ref", where, "entry has no #: reference")
        for r in e.refs:
            counts["refs"] += 1
            try:
                ref = slots.parse_ref(r)
            except ValueError as exc:
                rep.add(ERROR, "ref", where, str(exc))
                continue
            if r not in sources:
                rep.add(ERROR, "ref", where, f"no such slot in the game data: {r}")
            elif sources[r] != e.msgid:
                rep.add(ERROR, "msgid-drift", where,
                        f"{r}: msgid is not the source text\n"
                        f"        po  {e.msgid!r}\n"
                        f"        bin {sources[r]!r}")

        if not e.msgstr:
            continue
        if not e.msgstr.strip() and e.msgid.strip():
            rep.add(ERROR, "blank", where,
                    "translation is whitespace only; leave it empty instead")
            continue
        counts["translated"] += 1

        _markup(rep, where, e.msgid, e.msgstr, allow_ruby_drop)
        bad = _control_chars(e.msgstr)
        if bad:
            rep.add(ERROR, "control", where, "control characters in the "
                    "translation: " + " ".join(f"U+{ord(c):04X}" for c in bad))
        if e.msgid.count("\n") != e.msgstr.count("\n"):
            rep.add(WARN, "line-count", where,
                    f"{e.msgid.count(chr(10)) + 1} source line(s), "
                    f"{e.msgstr.count(chr(10)) + 1} translated -- the game does "
                    f"not wrap, long lines get clipped")

        for r in e.refs:
            if r in owner and owner[r][1] != e.msgstr:
                rep.add(ERROR, "conflict", where,
                        f"{r} is also translated differently at {owner[r][0]}")
            owner[r] = (where, e.msgstr)
            rep.translations[r] = e.msgstr
            if r.startswith(slots.CODEC + "/"):
                counts["codec_slots"] += 1
            else:
                counts["olang_slots"] += 1
                if targets is not None and r not in targets:
                    rep.add(ERROR, "target", where,
                            f"{r} has no {config.LANG_KEYS[lang]} key to write "
                            f"into; that slot only ships some of the six "
                            f"languages")

    if counts["codec_slots"]:
        rep.add(WARN, "codec", "-",
                f"{counts['codec_slots']} CODEC slot(s) translated but not "
                f"deliverable yet: bytecode write-back is blocked on "
                f"briefing_insn_decode case 0x10/0x20 (ANALYSIS/03 §2)")

    codepoints = {ord(c) for r, t in rep.translations.items()
                  if not r.startswith(slots.CODEC + "/") for c in t}
    counts["codepoints"] = len(codepoints)
    rep.stats = counts
    if check_font and codepoints:
        _lint_font(rep, codepoints)
    return rep


def _lint_font(rep: Report, codepoints: set) -> None:
    src = config.pristine(config.FONT_DIR / f"{config.FONT_LARGE}.xpr")
    if not src.is_file():
        rep.add(ERROR, "font", "-", f"font package not found: {src}")
        return
    p = font_build.plan(codepoints, src, config.FONT_TTF)
    rep.stats["font"] = {k: v for k, v in p.items()
                         if k not in ("missing", "over", "blank")}
    rep.stats["font"]["missing"] = len(p["missing"])

    if p["over"]:
        rep.add(ERROR, "font", "-",
                f"{len(p['over'])} code point(s) above cMaxGlyph "
                f"U+{p['max_glyph']:04X}, e.g. "
                + " ".join(f"U+{c:04X}" for c in p["over"][:5]))
    if p["blank"]:
        rep.add(ERROR, "font", "-",
                f"{config.FONT_TTF.name} has no glyph for "
                f"{len(p['blank'])} code point(s), they would become tofu: "
                + " ".join(f"U+{c:04X} {chr(c)}" for c in p["blank"][:5]))
    if p["rows_needed"] > p["free_rows"]:
        rep.add(ERROR, "font", "-",
                f"{len(p['missing'])} new glyphs need {p['rows_needed']} atlas "
                f"rows, only {p['free_rows']} are free")


def print_report(rep: Report, limit: int = 20) -> None:
    s = rep.stats
    print(f"{s['files']} .po files, {s['entries']} entries, {s['refs']} references")
    print(f"translated: {s['translated']} entries covering "
          f"{s['olang_slots']} olang + {s['codec_slots']} codec slots, "
          f"{s['codepoints']} distinct code points")
    if "font" in s:
        f = s["font"]
        print(f"font: {f['covered']}/{f['wanted']} code points already in "
              f"{config.FONT_LARGE}, {f['missing']} to add "
              f"({f['rows_needed']} of {f['free_rows']} free rows)")

    for severity in (ERROR, WARN):
        group = [p for p in rep.problems if p.severity == severity]
        if not group:
            continue
        print(f"\n{len(group)} {severity}(s):")
        for p in group[:limit]:
            print("  " + str(p))
        if len(group) > limit:
            print(f"  ... {len(group) - limit} more")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--po-dir", type=Path, default=config.PO_DIR)
    ap.add_argument("--lang", default="en",
                    help="which language slot the translations target "
                         f"({'/'.join(config.LANG_KEYS.values())}, default en)")
    ap.add_argument("--allow-ruby-drop", action="store_true",
                    help="demote dropped <R=...> ruby annotations to a warning")
    ap.add_argument("--no-font", action="store_true",
                    help="skip the code point coverage check")
    ap.add_argument("--limit", type=int, default=20,
                    help="problems printed per severity (default 20)")
    args = ap.parse_args()
    config.require_game()

    lang = lang_key(args.lang)
    rep = lint(args.po_dir, lang, args.allow_ruby_drop, not args.no_font)
    print_report(rep, args.limit)
    if rep.errors:
        raise SystemExit(1)
    print("\nlint OK" + (f" ({len(rep.warnings)} warning(s))"
                         if rep.warnings else ""))


if __name__ == "__main__":
    main()
