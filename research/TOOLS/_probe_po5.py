r"""Probe: the install state machine, on a synthetic game directory.

`pwsf.install` decides what to do by hashing: the live game file is either this
build, or the original this build was made from, or something else entirely.
The something-else cases are the ones that can destroy an install -- and they
are exactly the ones that are awkward to reach on a real machine, so this probe
builds a throwaway game tree and walks every state instead.

What must hold:

    fresh install      backs the original up, then writes; backup == original
    second install     does nothing, and does NOT re-take the backup
    restore            puts the original back
    foreign live file, no backup      refused, live file untouched
    foreign live file, good backup    installed (the original is still safe)
    backup that is not the original   refused, whatever the live file says
    --force                           overrides the refusals

The refusals matter more than the writes: `*.orig` is what every extraction
path reads as English source (`config.pristine`, PLANS/06 §8.1), so a backup
taken from already-modified content would quietly poison the corpus.

Run from anywhere:  python research/TOOLS/_probe_po5.py
"""

import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config, install, po_import

OUT = config.BUILD_DIR / "_probe_po5"
ORIGINAL = b"ORIGINAL english text" * 4
BUILT = b"BUILT chinese text" * 4
FOREIGN = b"SOMETHING ELSE, maybe another mod" * 3

DEST = "MLG/Text/00000001.olang"

problems = []


def check(ok: bool, message: str) -> None:
    if not ok:
        problems.append(message)


def setup(case: str, live: bytes, backup: bytes = None) -> list:
    """A fake game tree plus a build that claims ORIGINAL -> BUILT."""
    root = OUT / case
    if root.is_dir():
        shutil.rmtree(root)
    game, build = root / "game", root / "build"
    dest = game / DEST
    dest.parent.mkdir(parents=True)
    (game / "FONT").mkdir()                     # require_game() looks for these
    dest.write_bytes(live)
    if backup is not None:
        dest.with_name(dest.name + config.BACKUP_SUFFIX).write_bytes(backup)

    build.mkdir(parents=True)
    built = build / "00000001.olang"
    built.write_bytes(BUILT)
    orig_probe = build / "original.bin"
    orig_probe.write_bytes(ORIGINAL)
    row = (f"{DEST}\t{built.name}\tolang\t{len(BUILT)}\t"
           f"{po_import.sha256(built)}\t{po_import.sha256(orig_probe)}")
    orig_probe.unlink()
    (build / po_import.MANIFEST).write_text(
        "\n".join([po_import.MANIFEST_HEADER, row]) + "\n", encoding="utf-8")

    config.GAME_DIR = game        # install resolves destinations against this
    return install.read_manifest(build)


def attempt(fn, *args) -> str:
    """Run an install/restore and report whether it refused."""
    try:
        fn(*args)
    except SystemExit as exc:
        return f"refused: {exc}"
    return "done"


def live(case: str) -> bytes:
    return (OUT / case / "game" / DEST).read_bytes()


def backup_bytes(case: str):
    p = (OUT / case / "game" / DEST)
    p = p.with_name(p.name + config.BACKUP_SUFFIX)
    return p.read_bytes() if p.is_file() else None


def case(name: str, live_before: bytes, backup_before, expect_state: str) -> list:
    items = setup(name, live_before, backup_before)
    got = items[0].state()
    check(got == expect_state, f"{name}: state is {got!r}, expected {expect_state!r}")
    print(f"  {name}: live is {expect_state}"
          + ("" if backup_before is None else ", backup present"))
    return items


def main() -> None:
    real_game = config.GAME_DIR
    if OUT.is_dir():
        shutil.rmtree(OUT)
    try:
        print("states:")
        items = case("fresh", ORIGINAL, None, install.LIVE_ORIGINAL)
        print("   ", attempt(install.install, items))
        check(live("fresh") == BUILT, "fresh: build was not written")
        check(backup_bytes("fresh") == ORIGINAL,
              "fresh: backup is not the original")
        check(items[0].state() == install.LIVE_BUILT,
              "fresh: state after install is not 'installed'")

        # installing twice must not touch the backup: if it did, the second run
        # would record the first run's output as the original
        install.install(items)
        check(backup_bytes("fresh") == ORIGINAL,
              "fresh: the second install overwrote the backup")
        install.restore(items)
        check(live("fresh") == ORIGINAL, "fresh: restore did not undo it")
        print("    reinstall changed nothing, restore put the original back")

        items = case("foreign-no-backup", FOREIGN, None, install.LIVE_UNKNOWN)
        result = attempt(install.install, items)
        check(result.startswith("refused"),
              "foreign-no-backup: install was NOT refused")
        check(live("foreign-no-backup") == FOREIGN,
              "foreign-no-backup: the live file was modified anyway")
        print(f"    {result.splitlines()[0]}")

        items = case("foreign-forced", FOREIGN, None, install.LIVE_UNKNOWN)
        check(attempt(install.install, items, True) == "done",
              "foreign-forced: --force did not get through")
        check(live("foreign-forced") == BUILT, "foreign-forced: nothing written")
        print("    --force wrote it, and took no backup of foreign content")
        check(backup_bytes("foreign-forced") is None,
              "foreign-forced: foreign content was backed up as the original")

        items = case("foreign-with-backup", FOREIGN, ORIGINAL,
                     install.LIVE_UNKNOWN)
        check(attempt(install.install, items) == "done",
              "foreign-with-backup: install was refused despite a good backup")
        check(live("foreign-with-backup") == BUILT,
              "foreign-with-backup: nothing written")
        check(backup_bytes("foreign-with-backup") == ORIGINAL,
              "foreign-with-backup: the backup was disturbed")
        print("    installed over it; the untouched backup is the original")

        items = case("foreign-backup", ORIGINAL, FOREIGN, install.LIVE_ORIGINAL)
        result = attempt(install.install, items)
        check(result.startswith("refused"),
              "foreign-backup: install was NOT refused")
        print(f"    {result.splitlines()[0]}")

        items = case("restore-all", ORIGINAL, None, install.LIVE_ORIGINAL)
        install.install(items)
        install.restore_all()
        check(live("restore-all") == ORIGINAL,
              "restore-all: the original was not put back")
        print("    restore --all works without consulting the manifest")
    finally:
        config.GAME_DIR = real_game


if __name__ == "__main__":
    main()
    if problems:
        print(f"\n{len(problems)} PROBLEM(S):")
        for p in problems[:15]:
            print("  " + p)
        raise SystemExit(1)
    print("\nevery install state behaves, and no refusal leaves a wrong backup")
