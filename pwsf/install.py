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

hooklib64 builds exactly one artifact, `pwsf.dll`, and it is only ever deployed
as `pwsf.asi` (`--hook asi`, default; `--hook none` skips it).  Shipping as
`winmm.dll` does not work: that loads us during import resolution, before the
exe finishes decrypting, so the sigscan finds nothing (measured 2026-09-22).

`pwsf.asi` needs an ASI loader.  The repo carries one in `tools/loader/`, and
`install` writes it **only when the game directory has no `winmm.dll` at all** --
an existing one belongs to whoever put it there (another mod) and is left alone.
The game must find both in the same directory as `mgspw.exe`.  Neither is part of
`MANIFEST.tsv`; `install` records the hook name in `pwsf_hook.txt` and `restore`
removes exactly that.  Build the hook first:

    cd hooklib64
    cmake -S . -B build -G "Visual Studio 18 2026" -A x64
    cmake --build build --config Release     # -> build/Release/pwsf.dll
"""

import argparse
import shutil
import subprocess
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


def install(items: list, force: bool = False, verify_game: bool = True,
            backup: bool = True) -> None:
    """Write a build into the game.

    verify_game=True (dev default): refuse to clobber a file that is neither
    the recorded original nor this build, unless --force.  This keeps `.orig`
    backups trustworthy as a re-extraction source.

    verify_game=False (shipped patch): the player is assumed to have confirmed
    the game is the latest clean Steam build, so there is no hash gate -- see
    AGENTS.md / PLANS/07.

    backup=False (shipped patch): overwrite without leaving an `.orig`, i.e.
    nothing to restore from -- undoing it means Steam's verify-integrity.
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
            if backup and not it.backup.is_file() and it.dest.is_file():
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


# --- injection DLL (hooklib64 build output) + ASI loader ---------------------
# 只有一种形态：hooklib64 产 `pwsf.dll`，装成 `pwsf.asi`，由 ASI loader 加载。
# 不再伪装成 winmm.dll —— 那样会在导入解析阶段就加载，跑在 exe 解密之前，
# sigscan 扫不到（2026-09-22 实测 WINMM.dll 版 sigscan = 0）。
# 游戏目录没有 winmm.dll 时才补一个自带的 loader，已有则原样保留（别的 mod 的）。

HOOK_DLL = "pwsf.dll"
HOOK_ASI = "pwsf.asi"
HOOK_WINMM = "winmm.dll"      # 只用来识别「已存在的 ASI loader」，不覆盖也不删
HOOK_NAMES = (HOOK_ASI, HOOK_WINMM)
HOOK_MODES = ("asi", "none")

# 记录"我们装了哪个名字"：还原时只删这个，绝不碰外来/原样保留的 loader
HOOK_MARK = "pwsf_hook.txt"


def find_loader_artifact() -> Path | None:
    """The bundled ASI loader (`winmm.dll`), if the repo carries one."""
    p = config.REPO_ROOT / "tools" / "loader" / HOOK_WINMM
    return p if p.is_file() else None


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


def build_hook(debug: bool = False, verbose: bool = True) -> bool:
    """Configure and build hooklib64's `pwsf.dll` with cmake.

    Folded into the pipeline so `po_import --install` produces the injection DLL
    on its own instead of asking for a hand-run cmake.  Needs Visual Studio
    Build Tools (MSVC + Windows SDK) and cmake on PATH.

    Returns False -- with a warning, never an exception -- when cmake is not
    there or the build fails; the deploy then reports the artifact as missing.
    """
    root = _hooklib_dir()
    build = root / "build"
    flag = "ON" if debug else "OFF"
    steps = [
        ["cmake", "-S", str(root), "-B", str(build), "-A", "x64",
         f"-DPWSF_DEBUG={flag}"],
        ["cmake", "--build", str(build), "--config", "Release"],
    ]
    for cmd in steps:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        except (OSError, subprocess.SubprocessError) as exc:
            print(f"  hook: cannot run cmake ({exc}); skipping the hook build")
            return False
        if r.returncode != 0:
            print(f"  hook: {' '.join(cmd)} failed (exit {r.returncode})")
            for line in (r.stderr or "").splitlines()[-5:]:
                print(f"    {line}")
            return False
    if verbose:
        print(f"  hook: {HOOK_DLL} built (PWSF_DEBUG={flag})")
    return True


def status_hook(mode: str = "asi") -> None:
    art = find_hook_artifact()
    ours = _deployed_names()
    dst = config.GAME_DIR / HOOK_ASI
    if dst.is_file():
        if HOOK_ASI in ours or _is_ours(dst):
            if art is not None and sha256(dst) == sha256(art):
                print(f"  hook      installed  {HOOK_ASI}")
            else:
                print(f"  hook      differs    {HOOK_ASI} "
                      f"(rebuild, then --install)")
        elif not art:
            print(f"  hook      present    {HOOK_ASI} ({HOOK_DLL} not built)")
        else:
            print(f"  hook      foreign    {HOOK_ASI} (not ours, left alone)")
    elif not art:
        print(f"  hook      not built  {HOOK_DLL} "
              f"(cd hooklib64 && cmake --build build)")
    else:
        print(f"  hook      missing    {HOOK_ASI} (--install to deploy)")

    loader = config.GAME_DIR / HOOK_WINMM
    if loader.is_file():
        kind = "ours(fake)" if _is_ours(loader) else "kept"
        print(f"  loader    {kind:9}  {HOOK_WINMM}")
    elif find_loader_artifact():
        print(f"  loader    missing    {HOOK_WINMM} (--install adds the "
              f"bundled one)")
    else:
        print(f"  loader    none       (repo carries no ASI loader)")


def deploy_hook(mode: str = "asi", force: bool = False) -> None:
    """Install `pwsf.asi` next to mgspw.exe, plus an ASI loader if none exists.

    Only the asi shape is shipped: pretending to be `winmm.dll` loads us during
    import resolution, before the exe finishes decrypting, and the sigscan finds
    nothing (measured 2026-09-22).

    The bundled loader is written **only when the game directory has no
    `winmm.dll` at all** -- an existing one belongs to whoever put it there
    (another mod) and must survive.  --force only relaxes the guard on our own
    `pwsf.asi`.
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

    dst = config.GAME_DIR / HOOK_ASI
    if dst.is_file() and sha256(dst) == sha256(art):
        print(f"  unchanged {HOOK_ASI} (hook already installed)")
    else:
        if dst.is_file() and not _is_ours(dst) \
                and HOOK_ASI not in _deployed_names() and not force:
            raise SystemExit(
                f"{HOOK_ASI}: a file with that name already exists in the game "
                f"directory and is not a hook we installed. Refusing to "
                f"overwrite it; pass --force if you really mean it.")
        shutil.copy2(art, dst)
        print(f"  installed {HOOK_ASI} (hook, from {art.name})")
    _mark_deployed(HOOK_ASI)

    bundled = find_loader_artifact()
    loader = config.GAME_DIR / HOOK_WINMM
    if loader.is_file():
        if _is_ours(loader) and bundled:
            # 我们自己的 dll 顶在 winmm.dll 上（早加载会扫不到），换回真 loader
            shutil.copy2(bundled, loader)
            print(f"  replaced {HOOK_WINMM} (our own dll) with the bundled "
                  f"ASI loader")
        else:
            print(f"  kept {HOOK_WINMM} (an ASI loader is already there)")
        return
    if not bundled:
        print(f"  (repo carries no ASI loader: {HOOK_ASI} will not load)")
        return
    shutil.copy2(bundled, loader)
    print(f"  installed {HOOK_WINMM} (bundled ASI loader, none was present)")


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
    ap.add_argument("--hook", choices=HOOK_MODES, default="asi",
                    help="with --install, deploy hooklib64's pwsf.dll as "
                         "pwsf.asi (default; needs an ASI loader -- the bundled "
                         "one is added only if the game directory has none), "
                         "or not at all")
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
