"""Paths and constants for the PWSF toolchain.

Every setting resolves in this order:

    1. environment variable        PWSF_GAME_DIR, PWSF_FONT_TTF, PWSF_OUT_DIR
    2. pwsf.local.json in the repo root   (gitignored, per-machine overrides)
    3. auto-detection, then a built-in default

Nothing here raises on import, so `import pwsf.crypto` still works on a machine
without the game installed.  Call `require_game()` at the start of anything that
actually needs to read game files.

pwsf.local.json example:

    {
      "game_dir": "D:/Games/MGS_PW/mgspw",
      "font_ttf": "C:/Windows/Fonts/simhei.ttf"
    }

`python -m pwsf.config --init` writes such a file pre-filled with whatever is
resolved right now, so editing it is the only step left.
"""

import argparse
import json
import os
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCAL_CONFIG = REPO_ROOT / "pwsf.local.json"

# ----------------------------------------------------------------- overrides

def _local() -> dict:
    if LOCAL_CONFIG.is_file():
        try:
            return json.loads(LOCAL_CONFIG.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    return {}


_LOCAL = _local()


def _setting(env: str, key: str, default=None):
    value = os.environ.get(env) or _LOCAL.get(key)
    return Path(value) if value else default


# ----------------------------------------------------------------- game dir

GAME_SUBPATH = Path("steamapps/common/MGS_PW/mgspw")


def _steam_libraries() -> list:
    """Default Steam root plus any extra libraries listed in libraryfolders.vdf."""
    roots = []
    for env in ("ProgramFiles(x86)", "ProgramFiles"):
        base = os.environ.get(env)
        if base:
            roots.append(Path(base) / "Steam")
    roots.append(Path("C:/Steam"))

    libraries = list(roots)
    for root in roots:
        vdf = root / "steamapps" / "libraryfolders.vdf"
        if not vdf.is_file():
            continue
        try:
            text = vdf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in re.finditer(r'"path"\s*"([^"]+)"', text):
            libraries.append(Path(m.group(1).replace("\\\\", "\\")))
    return libraries


def _detect_game_dir():
    for lib in _steam_libraries():
        candidate = lib / GAME_SUBPATH
        if (candidate / "FONT").is_dir():
            return candidate
    return None


GAME_DIR = _setting("PWSF_GAME_DIR", "game_dir") or _detect_game_dir() \
    or Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")

EXE_NAME = "METAL GEAR SOLID PEACE WALKER.exe"


def require_game() -> Path:
    """Return the game directory, with a useful error if it is not usable."""
    if (GAME_DIR / "FONT").is_dir() and (GAME_DIR / "MLG").is_dir():
        return GAME_DIR
    raise SystemExit(
        f"game directory not found or incomplete: {GAME_DIR}\n"
        f"set PWSF_GAME_DIR, or write {LOCAL_CONFIG.name} in the repo root:\n"
        f'  {{"game_dir": "D:/path/to/MGS_PW/mgspw"}}')


BACKUP_SUFFIX = ".orig"


def pristine(path: Path) -> Path:
    """The untouched original of a game file, if an installer backed it up.

    Anything that EXTRACTS source data must go through this. The installers
    overwrite files in place and keep the original next to them as `*.orig`;
    reading the live file instead would feed already-translated text back into
    the corpus as if it were the English source.

    Safe for the decryption key too: name_hash stops at the first '.', so
    "009c9ea4.olang.orig" hashes identically to "009c9ea4".
    """
    backup = path.with_name(path.name + BACKUP_SUFFIX)
    return backup if backup.is_file() else path


def installed_backups() -> list:
    """Every game file whose live copy differs from its `.orig` backup.

    A backup that matches its live file is left over from a restore, not an
    installed build, so it must not be reported as one.
    """
    if not GAME_DIR.is_dir():
        return []
    out = []
    for backup in GAME_DIR.rglob("*" + BACKUP_SUFFIX):
        live = backup.with_name(backup.name[:-len(BACKUP_SUFFIX)])
        if live.is_file() and live.read_bytes() != backup.read_bytes():
            out.append(backup)
    return sorted(out, key=lambda p: p.stat().st_mtime, reverse=True)


# ----------------------------------------------------------- game subfolders

TEXT_DIR = GAME_DIR / "MLG" / "Text"            # 14 UI/subtitle olang tables
EXLANG_TEXT_DIR = GAME_DIR / "EXLANG" / "Text"  # Portuguese only, no English
FONT_DIR = GAME_DIR / "FONT"                    # XPR2 font packages
UI_TEX_DIR = GAME_DIR / "Text"                  # button icon .txp packs
DISC0_DIR = GAME_DIR / "MLG" / "disc0_rel"
BRIEFING_DAT = DISC0_DIR / "0076531d.DAT"       # CODEC / BRIEFING container

# ------------------------------------------------------------- repo folders

RESEARCH_DIR = REPO_ROOT / "research"           # reverse engineering workspace
ANALYSIS_DIR = RESEARCH_DIR / "ANALYSIS"        # evidence and extraction output
PLANS_DIR = RESEARCH_DIR / "PLANS"
TOOLS_DIR = RESEARCH_DIR / "TOOLS"              # probe / PoC scripts
BUILD_DIR = _setting("PWSF_OUT_DIR", "out_dir", RESEARCH_DIR / "BUILD")
PO_DIR = _setting("PWSF_PO_DIR", "po_dir", REPO_ROOT / "src")   # translation

DUMP_OLANG_TSV = ANALYSIS_DIR / "_dump_olang.tsv"
BRIEFING_TSV = ANALYSIS_DIR / "_briefing_lines.tsv"
SUBTITLE_TSV = ANALYSIS_DIR / "subtitle_ingame.tsv"
ARCHIVE_INDEX_TSV = ANALYSIS_DIR / "_archive_index.tsv"

# --------------------------------------------------------------- font build

FONT_TTF = _setting("PWSF_FONT_TTF", "font_ttf", Path(r"C:\Windows\Fonts\msyh.ttc"))
FONT_LARGE = "0007ccd8"    # 4096x4096, the only font glyph lookup ever uses
FONT_SMALL = "000ebbe8"    # loaded but never indexed (g_font_index is always 0)

# ------------------------------------------------------------------ olang

# key ids in the third olang level; see ANALYSIS/01_olang_text.md
LANG_KEYS = {0x0D0E: "en", 0x0D32: "fr", 0x0D45: "de",
             0x0D94: "it", 0x0DB0: "ja", 0x0ED0: "es"}
LANG_EN = 0x0D0E

# -lan values accepted by lang_get_language_id @ 0x140027B40, see 07_launch_args
LAUNCH_LANGS = ("en", "fr", "gr", "it", "sp", "pt")

# ------------------------------------------------------------------ export

PO_CHUNK = int(os.environ.get("PWSF_PO_CHUNK") or _LOCAL.get("po_chunk") or 400)


def default_local() -> dict:
    """Every overridable setting, holding the value resolved on this machine."""
    return {
        "game_dir": GAME_DIR.as_posix(),
        "font_ttf": FONT_TTF.as_posix(),
        "po_dir": PO_DIR.as_posix(),
        "out_dir": BUILD_DIR.as_posix(),
        "po_chunk": PO_CHUNK,
    }


def default_local_json() -> str:
    return json.dumps(default_local(), indent=2, ensure_ascii=False) + "\n"


def summary() -> str:
    return "\n".join([
        f"repo      {REPO_ROOT}",
        f"game      {GAME_DIR}"
        + ("" if (GAME_DIR / 'FONT').is_dir() else "   [NOT FOUND]"),
        f"font ttf  {FONT_TTF}"
        + ("" if FONT_TTF.is_file() else "   [NOT FOUND]"),
        f"research  {RESEARCH_DIR}",
        f"src (po)  {PO_DIR}",
        f"build     {BUILD_DIR}",
        f"local cfg {LOCAL_CONFIG}"
        + ("" if LOCAL_CONFIG.is_file() else "   (absent)"),
    ])


def main() -> None:
    ap = argparse.ArgumentParser(
        description="show the resolved PWSF paths, or seed "
                    f"{LOCAL_CONFIG.name} with them")
    ap.add_argument("--init", action="store_true",
                    help=f"write the resolved settings to {LOCAL_CONFIG.name}")
    ap.add_argument("--print-default", action="store_true",
                    help=f"print the same {LOCAL_CONFIG.name} body to stdout")
    ap.add_argument("--force", action="store_true",
                    help="with --init, overwrite an existing file")
    args = ap.parse_args()

    if args.print_default:
        print(default_local_json(), end="")
        return
    if args.init:
        if LOCAL_CONFIG.is_file() and not args.force:
            raise SystemExit(f"{LOCAL_CONFIG} already exists; "
                             f"pass --force to overwrite it")
        LOCAL_CONFIG.write_text(default_local_json(), encoding="utf-8")
        print(f"wrote {LOCAL_CONFIG}\n")
        print(default_local_json(), end="")
        return
    print(summary())


if __name__ == "__main__":
    main()
