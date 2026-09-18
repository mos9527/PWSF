"""PWSF — METAL GEAR SOLID PEACE WALKER (Steam) localisation toolchain.

Layer by layer, every format here was recovered from the shipped x64 binary;
the evidence for each lives in ANALYSIS/ and the module docstrings cite the
addresses they were derived from.

    config        paths and constants, overridable per machine
    crypto        name_hash, the game's MT19937 variant, buffer_xor_decrypt
    olang         RBX text table reader        (UI text + in-game subtitles)
    olang_build   RBX writer, byte-exact round trip
    briefing      CODEC / BRIEFING container and bytecode walker
    archive       PDT / DAT archives, payload decrypt + CRC-32
    archive_index whole-disk archive report
    names         entry_name_hash / str_hash24 / extension table
    xpr           XPR2 (Xbox 360 resource package) reader and writer
    font          ATG-style font inside an XPR2: translator table, glyphs, atlas
    font_build    code points + TTF -> a font that covers them
    subtitle      in-game subtitle exporter
    po            gettext .po reader
    po_export     English corpus -> chunked .po for translation
"""

__all__ = [
    "config", "crypto", "olang", "olang_build", "briefing", "archive",
    "archive_index", "names", "xpr", "font", "font_build", "subtitle",
    "po", "po_export",
]
