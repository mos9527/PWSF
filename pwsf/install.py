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


def install(items: list, force: bool = False) -> None:
    for it in items:
        rel = it.dest.relative_to(config.GAME_DIR)
        state = it.state()
        if state == LIVE_MISSING:
            raise SystemExit(f"{rel} does not exist in the game directory")
        if state == LIVE_BUILT:
            print(f"  unchanged {rel} (this build is already installed)")
            continue

        if it.backup.is_file():
            if sha256(it.backup) != it.orig_sha and not force:
                raise SystemExit(
                    f"{rel}: the existing {config.BACKUP_SUFFIX} backup is not "
                    f"the original this build was made from. Restore first, or "
                    f"re-run po_import, or pass --force.")
        elif state == LIVE_ORIGINAL:
            shutil.copy2(it.dest, it.backup)
            print(f"  backed up {rel} -> {it.backup.name}")
        elif not force:
            raise SystemExit(
                f"{rel}: live file is neither the original this build was made "
                f"from nor this build, and there is no backup to fall back on. "
                f"Reinstall the game file, or pass --force to overwrite it "
                f"(the original would then be unrecoverable).")

        shutil.copy2(it.built, it.dest)
        if sha256(it.dest) != it.sha:
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
    elif args.restore:
        restore(items)
    else:
        status(items)
        print("\n--install to write these into the game, --restore to undo")


if __name__ == "__main__":
    main()
