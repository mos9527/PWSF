r"""Install a compiled build into the game, and take it back out.

Driven by `BUILD/MANIFEST.tsv`, which `po_import` writes: it carries, per file,
the destination inside the game directory, the hash of the built file and the
hash of the original the build was made from.  That last column is what makes
this safe to run twice, or on a machine whose game has been patched:

    live == built       already installed, left alone
    live == original    back it up, then install
    live == neither     installed only if a backup already holds the recorded
                        original; otherwise refused, because there would be no
                        way back.  --force overrides.

A backup is never created from content that does not match the recorded
original, and an existing backup is never overwritten.  `*.orig` is what every
extraction path reads as English source (`config.pristine`, PLANS/06 §8.1), so
a backup taken from modified content would quietly poison the corpus.

The state machine is walked case by case in `_probe_po5.py`.

Usage:
    python -m pwsf.install              # status only, writes nothing
    python -m pwsf.install --install
    python -m pwsf.install --restore
    python -m pwsf.install --restore --all   # every *.orig in the game dir

hooklib64 builds exactly one artifact, `pwsf.dll`; what it is called once
installed is a deployment decision (`--hook winmm` -> `winmm.dll`, default;
`--hook asi` -> `pwsf.asi`; `--hook none` -> not deployed).  The game must find
it in the same directory as `mgspw.exe` for the font hook to load.  It is not
part of `MANIFEST.tsv`, so `install` copies `pwsf.dll` under the requested name
and records that name in `pwsf_hook.txt`; `restore` removes exactly the name
that was recorded.  A `winmm.dll` that is not ours (e.g. the player's own ASI
loader) is never clobbered or deleted.  Build it first:

    cd hooklib64
    cmake -S . -B build -G "Visual Studio 18 2026" -A x64
    cmake --build build --config Release     # -> build/Release/pwsf.dll
"""

import argparse
import shutil
from dataclasses import dataclass
from pathlib import Path

from . import config
from .po_import import MANIFEST, sha256

LIVE_BUILT, LIVE_ORIGINAL, LIVE_UNKNOWN, LIVE_MISSING = (
    "installed", "original", "unknown", "missing")


@dataclass
class Item:
    dest: Path
    built: Path
    kind: str
    size: int
    sha: str
    orig_sha: str

    @property
    def backup(self) -> Path:
        return self.dest.with_name(self.dest.name + config.BACKUP_SUFFIX)

    def state(self) -> str:
        if not self.dest.is_file():
            return LIVE_MISSING
        live = sha256(self.dest)
        if live == self.sha:
            return LIVE_BUILT
        if live == self.orig_sha:
            return LIVE_ORIGINAL
        return LIVE_UNKNOWN


def read_manifest(build_dir: Path) -> list:
    path = build_dir / MANIFEST
    if not path.is_file():
        raise SystemExit(f"no manifest at {path}\n"
                         f"run: python -m pwsf.po_import")
    items = []
    for line in path.read_text(encoding="utf-8").splitlines()[1:]:
        dest, built, kind, size, sha, orig_sha = line.split("\t")
        items.append(Item(config.GAME_DIR / dest, build_dir / built, kind,
                          int(size), sha, orig_sha))
    for it in items:
        if not it.built.is_file():
            raise SystemExit(f"manifest lists {it.built.name}, "
                             f"but it is not in {build_dir}")
        if sha256(it.built) != it.sha:
            raise SystemExit(f"{it.built} does not match its manifest hash; "
                             f"rebuild with python -m pwsf.po_import")
    return items


def status(items: list) -> None:
    for it in items:
        rel = it.dest.relative_to(config.GAME_DIR)
        state = it.state()
        note = "" if not it.backup.is_file() else \
            f", backup {'ok' if sha256(it.backup) == it.orig_sha else 'FOREIGN'}"
        print(f"  {state:9} {rel} ({it.kind}, {it.size} bytes{note})")


def install(items: list, force: bool = False, verify_game: bool = True) -> None:
    """Write a build into the game.

    verify_game=True (dev default): refuse to clobber a file that is neither
    the recorded original nor this build, unless --force.  This keeps `.orig`
    backups trustworthy as a re-extraction source.

    verify_game=False (shipped patch): the player is assumed to have confirmed
    the game is the latest clean Steam build, so we just back up (if no `.orig`
    yet) and overwrite.  No hash gate -- see AGENTS.md / PLANS/07.
    """
    for it in items:
        rel = it.dest.relative_to(config.GAME_DIR)
        if verify_game:
            state = it.state()
            if state == LIVE_MISSING:
                raise SystemExit(f"{rel} does not exist in the game directory")
            if state == LIVE_BUILT:
                print(f"  unchanged {rel} (this build is already installed)")
                continue
            if it.backup.is_file():
                if sha256(it.backup) != it.orig_sha and not force:
                    raise SystemExit(
                        f"{rel}: the existing {config.BACKUP_SUFFIX} backup is "
                        f"not the original this build was made from. Restore "
                        f"first, or re-run po_import, or pass --force.")
            elif state == LIVE_ORIGINAL:
                shutil.copy2(it.dest, it.backup)
                print(f"  backed up {rel} -> {it.backup.name}")
            elif not force:
                raise SystemExit(
                    f"{rel}: live file is neither the original this build was "
                    f"made from nor this build, and there is no backup to fall "
                    f"back on. Reinstall the game file, or pass --force to "
                    f"overwrite it (the original would then be unrecoverable).")
        else:
            if not it.backup.is_file() and it.dest.is_file():
                shutil.copy2(it.dest, it.backup)
                print(f"  backed up {rel} -> {it.backup.name}")

        shutil.copy2(it.built, it.dest)
        if verify_game and sha256(it.dest) != it.sha:
            raise SystemExit(f"{rel}: copied file does not match the build hash")
        print(f"  installed {rel} ({it.kind})")


def restore(items: list) -> None:
    for it in items:
        rel = it.dest.relative_to(config.GAME_DIR)
        if not it.backup.is_file():
            print(f"  no backup for {rel}, left alone")
            continue
        shutil.copy2(it.backup, it.dest)
        ok = sha256(it.dest) == it.orig_sha
        print(f"  restored {rel}" + ("" if ok else
              "  (WARNING: backup differs from the manifest original)"))


def restore_all() -> None:
    """Undo every backup in the game directory, manifest or not.

    The PoC scripts installed files this manifest never knew about, so there
    has to be a way to get back to a clean install without one.
    """
    backups = sorted(config.GAME_DIR.rglob("*" + config.BACKUP_SUFFIX))
    if not backups:
        print("  no backups in the game directory, nothing to restore")
        return
    for bak in backups:
        dest = bak.with_name(bak.name[:-len(config.BACKUP_SUFFIX)])
        shutil.copy2(bak, dest)
        print(f"  restored {dest.relative_to(config.GAME_DIR)}")


# --- injection DLL (hooklib64 build output) ---------------------------------
# Additive file living next to mgspw.exe; not part of MANIFEST.tsv.  hooklib64
# builds one artifact (`pwsf.dll`); what it is called once deployed is this
# module's call (--hook winmm|asi|none).

# hooklib64 只产一个 pwsf.dll；装进游戏时叫什么名字由 --hook 决定
HOOK_DLL = "pwsf.dll"
HOOK_WINMM = "winmm.dll"
HOOK_ASI = "pwsf.asi"
HOOK_NAMES = (HOOK_WINMM, HOOK_ASI)
HOOK_MODES = ("winmm", "asi", "none")


# 记录"我们装了哪个名字"。游戏目录里的 winmm.dll 可能是用户自己的 ASI loader
# （3.6 MB 那种），绝不能当成我们的产物来覆盖或删除。
HOOK_MARK = "pwsf_hook.txt"


def hook_name(mode: str) -> str:
    return HOOK_WINMM if mode == "winmm" else HOOK_ASI


def _hook_mark() -> Path:
    return config.GAME_DIR / HOOK_MARK


def _deployed_names() -> list:
    p = _hook_mark()
    if not p.is_file():
        return []
    return [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines()
            if ln.strip()]


def _mark_deployed(name: str) -> None:
    _hook_mark().write_text(name + "\n", encoding="utf-8")


def _is_ours(dst: Path) -> bool:
    """True only when `dst` is the artifact hooklib64 built.

    The game directory can legitimately hold a foreign `winmm.dll` -- an ASI
    loader the player put there -- which must never be clobbered or deleted.
    """
    art = find_hook_artifact()
    return art is not None and dst.is_file() and sha256(dst) == sha256(art)


def _hooklib_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "hooklib64"


def find_hook_artifact() -> Path | None:
    """The built hooklib64 artifact: `pwsf.dll`, whatever it gets deployed as."""
    root = _hooklib_dir()
    for cand in (root / HOOK_DLL, root / "build" / "Release" / HOOK_DLL):
        if cand.is_file():
            return cand
    return None


def status_hook(mode: str = "winmm") -> None:
    art = find_hook_artifact()
    want = hook_name(mode)
    ours = _deployed_names()
    shown = False
    for name in HOOK_NAMES:
        dst = config.GAME_DIR / name
        if not dst.is_file():
            continue
        shown = True
        if name in ours or _is_ours(dst):
            note = "" if name == want else f"  (stale, --hook wants {want})"
            print(f"  hook      installed  {name}{note}")
        elif not art:
            print(f"  hook      present    {name} ({HOOK_DLL} not built)")
        else:
            print(f"  hook      foreign    {name} (not ours, left alone)")
    if not shown:
        if not art:
            print(f"  hook      not built  {HOOK_DLL} "
                  f"(cd hooklib64 && cmake --build build)")
        else:
            print(f"  hook      missing    {want} (--install to deploy)")


def deploy_hook(mode: str = "winmm", force: bool = False) -> None:
    """Copy hooklib64's pwsf.dll next to mgspw.exe under its deploy name.

    Refuses to clobber an existing file that is neither this build nor a hook
    we installed before: with an ASI loader in the game directory, a foreign
    `winmm.dll` is someone else's and must survive.  --force overrides.
    """
    if mode == "none":
        remove_hook()
        print("  hook      skipped    (--hook none)")
        return
    art = find_hook_artifact()
    if not art:
        print(f"  (hook: {HOOK_DLL} not built -- "
              f"cd hooklib64 && cmake --build build)")
        return
    target = hook_name(mode)
    other = HOOK_WINMM if mode == "asi" else HOOK_ASI
    stale = config.GAME_DIR / other
    if stale.is_file() and (other in _deployed_names() or _is_ours(stale)):
        stale.unlink()          # never leave both: that would double-inject
        print(f"  removed {other} (switching to {target})")
    dst = config.GAME_DIR / target
    if dst.is_file() and sha256(dst) == sha256(art):
        _mark_deployed(target)
        print(f"  unchanged {target} (hook already installed)")
        return
    if dst.is_file() and not _is_ours(dst) \
            and target not in _deployed_names() and not force:
        raise SystemExit(
            f"{target}: a file with that name already exists in the game "
            f"directory and is not a hook we installed -- it may be your own "
            f"ASI loader. Refusing to overwrite it; pass --force if you "
            f"really mean it, or pick another --hook mode.")
    shutil.copy2(art, dst)
    _mark_deployed(target)
    print(f"  installed {target} (hook, from {art.name})")


def remove_hook() -> None:
    """Delete the hook we installed -- and nothing else.

    Names come from the marker file if it exists; otherwise only a file that
    is byte-for-byte the built artifact is removed.  A foreign `winmm.dll`
    (an ASI loader) is never touched.
    """
    names = _deployed_names()
    if names:
        for name in names:
            dst = config.GAME_DIR / name
            if dst.is_file():
                dst.unlink()
                print(f"  removed {name} (hook)")
        _hook_mark().unlink(missing_ok=True)
        return
    for name in HOOK_NAMES:
        dst = config.GAME_DIR / name
        if _is_ours(dst):
            dst.unlink()
            print(f"  removed {name} (hook)")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--build-dir", type=Path, default=config.BUILD_DIR)
    ap.add_argument("--install", action="store_true")
    ap.add_argument("--restore", action="store_true")
    ap.add_argument("--all", action="store_true",
                    help="with --restore, undo every *.orig backup in the "
                         "game directory instead of just this build's files")
    ap.add_argument("--force", action="store_true",
                    help="with --install, overwrite game files whose content "
                         "is not recognised (the original may be lost)")
    ap.add_argument("--hook", choices=HOOK_MODES, default="winmm",
                    help="with --install, deploy hooklib64's pwsf.dll as "
                         "winmm.dll (default) or pwsf.asi, or not at all")
    args = ap.parse_args()
    config.require_game()

    if args.restore and args.all:
        print(f"restoring every backup under {config.GAME_DIR}")
        restore_all()
        return

    items = read_manifest(args.build_dir)
    print(f"{len(items)} file(s) in {args.build_dir / MANIFEST}")
    if args.install:
        install(items, args.force)
        deploy_hook(args.hook, args.force)
    elif args.restore:
        restore(items)
        remove_hook()
    else:
        status(items)
        status_hook(args.hook)
        print("\n--install to write these into the game, --restore to undo")


if __name__ == "__main__":
    main()
