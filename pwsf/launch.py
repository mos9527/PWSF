r"""Start the game, and optionally stand in for the Steam launcher.

Two things live here.

1. `python -m pwsf.launch` starts the game directly.  The working directory
   MUST be the game directory -- the font is looked up as "." (README) -- and
   the launch arguments from ANALYSIS/07_launch_args.md are supplied so the
   game does not fall back to the Japanese branch, whose assets the Steam
   release never shipped.

2. `--install-shim` replaces `<install>\launcher\launcher.exe` with
   `pwsf/shim/launcher_shim.c` compiled by `cl`.  The shipped launcher is a
   Unity IL2CPP front end; this deliberately does not reverse engineer it, it
   just starts the game itself, so clicking Play in Steam goes straight into
   the game.  The original is kept as `launcher.exe.orig` (the same convention
   everything else in pwsf uses) and `--restore-shim` puts it back.

    python -m pwsf.launch                 # start the game
    python -m pwsf.launch --dry-run       # show the command only
    python -m pwsf.launch --wait          # stay attached until it exits

    python -m pwsf.launch --status        # is the launcher replaced?
    python -m pwsf.launch --build-shim    # compile only, into BUILD/
    python -m pwsf.launch --install-shim  # compile, back up, replace
    python -m pwsf.launch --restore-shim  # put the original launcher back
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from . import config

GAME_EXE = "METAL GEAR SOLID PEACE WALKER.exe"
# ANALYSIS/07_launch_args.md: -lan must be spelled right or the game silently
# picks the Japanese branch, which is not shipped on Steam.
DEFAULT_ARGS = ["-lan", "en", "-region", "eu",
                "-selfregion", "EU", "-ctrltype", "XS"]

SHIM_SRC = Path(__file__).parent / "shim" / "launcher_shim.c"
SHIM_NAME = "launcher_shim.exe"
INI_NAME = "pwsf_launch.ini"

VSDEVCMD = [
    r"C:\Program Files\Microsoft Visual Studio\18\Community"
    r"\Common7\Tools\VsDevCmd.bat",
    r"C:\Program Files\Microsoft Visual Studio\2022\Community"
    r"\Common7\Tools\VsDevCmd.bat",
]


def launcher_dir() -> Path:
    """<install>/launcher, i.e. the sibling of the game directory."""
    return config.GAME_DIR.parent / "launcher"


def game_exe() -> Path:
    return config.GAME_DIR / GAME_EXE


def find_vsdevcmd():
    return next((p for p in VSDEVCMD if Path(p).is_file()), None)


# -------------------------------------------------------------------- launch

def launch(args: list, wait: bool = False, dry_run: bool = False) -> int:
    exe = game_exe()
    if not exe.is_file():
        raise SystemExit(f"game not found: {exe}")
    cmd = [str(exe)] + args
    if dry_run:
        print("cd " + str(config.GAME_DIR))
        print("& " + " ".join(f'"{c}"' if " " in c else c for c in cmd))
        return 0
    print(f"cwd  {config.GAME_DIR}")
    print("cmd  " + " ".join(cmd))
    proc = subprocess.Popen(cmd, cwd=str(config.GAME_DIR))
    print(f"pid  {proc.pid}")
    if not wait:
        return 0
    return proc.wait()


# ---------------------------------------------------------------------- shim

def build_shim(outdir: Path) -> Path:
    """Compile the shim with cl. Returns the .exe path."""
    vs = find_vsdevcmd()
    if not vs:
        raise SystemExit("no Visual Studio with VsDevCmd.bat found; cannot "
                         "compile the shim")
    if not SHIM_SRC.is_file():
        raise SystemExit(f"shim source missing: {SHIM_SRC}")
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / SHIM_NAME
    # cmd /c mis-parses a quoted path followed by &&, so go through a .bat
    bat = outdir / "_build_shim.bat"
    bat.write_text(
        f'@echo off\r\n'
        f'call "{vs}" -no_logo -arch=x64\r\n'
        f'cl /nologo /W3 /O2 /Fo:"{outdir}\\\\" /Fe:"{out}" '
        f'"{SHIM_SRC}" /link /subsystem:windows\r\n',
        encoding="ascii")
    r = subprocess.run(["cmd", "/c", str(bat)], capture_output=True,
                       text=True)
    bat.unlink(missing_ok=True)
    for line in ((r.stdout or "") + (r.stderr or "")).splitlines():
        if line.strip():
            print("  | " + line.rstrip())
    if not out.is_file():
        raise SystemExit("compilation failed")
    print(f"built {out}")
    return out


def write_ini(path: Path, args: list) -> None:
    """UTF-16 so non-ASCII install paths survive GetPrivateProfileStringW."""
    body = ("; written by pwsf.launch --install-shim\r\n"
            "[launch]\r\n"
            "dir=..\\mgspw\r\n"
            f"exe={GAME_EXE}\r\n"
            f"args={' '.join(args)}\r\n")
    path.write_text(body, encoding="utf-16")


def install_shim(args: list) -> None:
    ld = launcher_dir()
    target = ld / "launcher.exe"
    if not target.is_file():
        raise SystemExit(f"launcher not found: {target}")
    backup = target.with_name(target.name + config.BACKUP_SUFFIX)
    if backup.is_file():
        raise SystemExit(f"{backup.name} already exists -- the launcher is "
                         f"already replaced; --restore-shim first")

    exe = build_shim(config.BUILD_DIR)
    shutil.copy2(target, backup)
    shutil.copy2(exe, target)
    write_ini(ld / INI_NAME, args)
    print(f"backed up  {backup}")
    print(f"replaced   {target}")
    print(f"wrote      {ld / INI_NAME}")
    print("\nSteam's Play button now starts the game directly.")


def restore_shim() -> None:
    ld = launcher_dir()
    target = ld / "launcher.exe"
    backup = target.with_name(target.name + config.BACKUP_SUFFIX)
    if not backup.is_file():
        raise SystemExit(f"no backup at {backup}; nothing to restore")
    shutil.copy2(backup, target)
    backup.unlink()
    (ld / INI_NAME).unlink(missing_ok=True)
    print(f"restored {target}")
    print(f"removed  {backup}")


def status() -> None:
    ld = launcher_dir()
    target = ld / "launcher.exe"
    backup = target.with_name(target.name + config.BACKUP_SUFFIX)
    print(f"game      {game_exe()}  "
          f"{'ok' if game_exe().is_file() else 'MISSING'}")
    print(f"launcher  {target}  "
          f"{'ok' if target.is_file() else 'MISSING'}")
    print(f"shim      {'INSTALLED' if backup.is_file() else 'not installed'}"
          f"  (backup: {backup.name if backup.is_file() else '-'})")
    ini = ld / INI_NAME
    if ini.is_file():
        print(f"\n{ini}:")
        for line in ini.read_text(encoding="utf-16").splitlines():
            print("  " + line)


# ---------------------------------------------------------------------- main

def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0])
    ap.add_argument("gameargs", nargs="*",
                    help="arguments passed to the game verbatim; use `--` to "
                         "separate them ('-- -lan fr'). Anything given here "
                         "replaces the defaults entirely")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--wait", action="store_true",
                    help="stay attached until the game exits")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--build-shim", action="store_true")
    ap.add_argument("--install-shim", action="store_true")
    ap.add_argument("--restore-shim", action="store_true")
    args = ap.parse_args()

    if args.status:
        status()
        return
    if args.restore_shim:
        restore_shim()
        return
    if args.build_shim:
        build_shim(config.BUILD_DIR)
        return
    if args.install_shim:
        install_shim(args.gameargs or DEFAULT_ARGS)
        return

    launch(args.gameargs or DEFAULT_ARGS, args.wait, args.dry_run)


if __name__ == "__main__":
    main()
