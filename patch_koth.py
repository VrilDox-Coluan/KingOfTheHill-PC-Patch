#!/usr/bin/env python3
"""
King of the Hill (2000) PC Modern Patcher
Patches King of the Hill: Hootenanny and King of the Hill: Texas Huntin'
from the user's own legally obtained CD-ROM or extracted ISO to run on
modern Windows (Windows 10/11).

NO copyrighted game files, Director runtime DLLs, or assets are distributed
with this tool. Everything is extracted from or patched directly against the
user's own CD-ROM/ISO dump and Windows system DLLs.
"""

import argparse
import os
import re
import shutil
import string
import subprocess
import sys
import tempfile
from pathlib import Path

VERSION = "0.2.0"

if getattr(sys, "frozen", False):
    BUNDLE_DIR = Path(sys._MEIPASS)
    APP_DIR = Path(sys.executable).resolve().parent
else:
    BUNDLE_DIR = Path(__file__).resolve().parent
    APP_DIR = BUNDLE_DIR

SRC_DIR = BUNDLE_DIR / "src"
sys.path.insert(0, str(SRC_DIR))
import build_winmm_proxy  # noqa: E402

# Clean Macromedia Director 8.0r178 PE stub length inside AUTORUN.EXE
DIRECTOR_STUB_LEN = 0xAE55

# Embedded Director 8.0r178 runtime DLLs inside AUTORUN.EXE
AUTORUN_EMBEDDED_DLLS = {
    "Proj.dll": (0xB11C, 131072),
    "DIRAPI.dll": (0x2B11C, 1241088),
    "IML32.dll": (0x15A11C, 552960),
    "msvcrt.dll": (0x1E111C, 266293),
}

# HOOT IML32.dll patch: bypass ImlWinBackdropClass clipping on modern DWM
HOOT_IML32_PATCHES = [
    (
        "Bypass ImlWinBackdropClass stage clipping",
        0x2E400,
        bytes.fromhex("85d20f843a010000"),
        bytes.fromhex("e93d010000909090"),
    ),
]

# HOOT SHARED\BP_LIB.CST Lingo bytecode patches (verified via ProjectorRays)
HOOT_BPLIB_PATCHES = [
    (
        "ParentScript 71 (bp_menu): keep title sprite on-stage (kSprOffstageLoc -> OrgLoc)",
        0x86616E,
        bytes.fromhex("890056"),
        bytes.fromhex("8a018f"),
    ),
    (
        "ParentScript 71 (bp_menu): bypass mFadeSounds startup hang",
        0x866308,
        bytes.fromhex("8900a5"),
        bytes.fromhex("93002f"),
    ),
    (
        "ParentScript 94 (bp_timeclock): extend scheduled event retry window (2m/5m -> 1m/50m) for Peggy's Tic-Tac-Toss & all HQ events",
        0x86BD55,
        bytes.fromhex("810002040551108a02da4b0843025711810e10810005"),
        bytes.fromhex("810001040551108a02da4b0843025711810e10810032"),
    ),
    (
        "ParentScript 582 (pb_main mEnter): initialize gameTimer = gCurRefTicks",
        0x92EE1A,
        bytes.fromhex("8100039014d4039014d5039014d6039014d7039014d8039014d9810005"),
        bytes.fromhex("41039014d4039014d5039014d6039014d7039014d88900f79014d94105"),
    ),
    (
        "ParentScript 582 (pb_main mIdle): replace unthrottled idle counter (10000) with real-time 4-minute gCurRefTicks limit",
        0x930938,
        bytes.fromhex("8a14d9810001059014d98a14d98127100f950019"),
        bytes.fromhex("8900f78a14d90681003c413c0441040410950019"),
    ),
]


def is_writable_dir(path: Path) -> bool:
    try:
        test_file = path / ".koth_patch_write_test"
        test_file.write_bytes(b"ok")
        test_file.unlink()
        return True
    except OSError:
        return False


def find_csc() -> Path:
    candidates = [
        Path(r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"),
        Path(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"),
    ]
    for c in candidates:
        if c.is_file():
            return c
    which = shutil.which("csc.exe")
    if which:
        return Path(which)
    raise FileNotFoundError(
        "Could not find Windows .NET Framework C# compiler (csc.exe). "
        "Expected C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe."
    )


def find_syswow64_winmm() -> Path:
    for p in (Path(r"C:\Windows\SysWOW64\winmm.dll"), Path(r"C:\Windows\System32\winmm.dll")):
        if p.is_file():
            return p
    raise FileNotFoundError("Could not locate 32-bit Windows winmm.dll in SysWOW64 or System32.")


def apply_binary_patches(file_path: Path, patches, make_backup=True, dry_run=False):
    data = bytearray(file_path.read_bytes())
    changed = 0
    for desc, off, old_b, new_b in patches:
        assert len(old_b) == len(new_b), f"Patch length mismatch: {desc}"
        cur = bytes(data[off : off + len(old_b)])
        if cur == new_b:
            print(f"    [skip] Already patched: {desc}")
            continue
        if cur != old_b:
            raise RuntimeError(
                f"Unexpected bytes in {file_path} at 0x{off:X} ({desc}).\n"
                f"  Expected: {old_b.hex()}\n"
                f"  Found:    {cur.hex()}"
            )
        data[off : off + len(new_b)] = new_b
        changed += 1
        print(f"    [ok]   {desc}")

    if changed and not dry_run:
        bak = file_path.with_suffix(file_path.suffix + ".BAK")
        if make_backup and not bak.exists():
            shutil.copy2(file_path, bak)
            print(f"    [bak]  Saved original backup -> {bak.name}")
        file_path.write_bytes(data)


def unwrap_safedisc_exe(exe_path: Path, clean_stub: bytes, dry_run=False):
    raw = bytearray(exe_path.read_bytes())
    if len(raw) < len(clean_stub):
        raise RuntimeError(f"{exe_path} is unexpectedly small ({len(raw)} bytes).")
    if bytes(raw[: len(clean_stub)]) == clean_stub:
        print(f"  [skip] {exe_path.name} already has clean Director 8.0r178 stub")
        return
    bak = exe_path.with_name(exe_path.stem + ".SAFEDISC.EXE")
    print(f"  [ok]   Unwrapping SafeDisc v1 stub on {exe_path.name} (backup -> {bak.name})")
    if not dry_run:
        if not bak.exists():
            shutil.copy2(exe_path, bak)
        raw[: len(clean_stub)] = clean_stub
        exe_path.write_bytes(raw)


def extract_autorun_runtime(autorun_path: Path):
    ar = autorun_path.read_bytes()
    if ar[:2] != b"MZ":
        raise RuntimeError(f"{autorun_path} is not a valid PE executable.")
    clean_stub = ar[:DIRECTOR_STUB_LEN]
    dlls = {}
    for name, (off, size) in AUTORUN_EMBEDDED_DLLS.items():
        chunk = ar[off : off + size]
        if len(chunk) != size or chunk[:2] != b"MZ":
            raise RuntimeError(
                f"Failed to verify embedded {name} at 0x{off:X} in {autorun_path}. "
                "Make sure you pointed to the King of the Hill (2000) PC CD-ROM."
            )
        dlls[name] = chunk
    return clean_stub, dlls


def patch_lingo_ini(ini_path: Path, is_hoot: bool, dry_run=False):
    if not ini_path.is_file():
        print(f"  [warn] {ini_path} not found, skipping LINGO.INI update")
        return
    text = ini_path.read_bytes().decode("latin1")
    new_text = re.sub(r'set\s+the\s+soundDevice\s*=\s*"QT3Mix"', 'set the soundDevice = "DirectSound"', text, flags=re.I)
    if is_hoot and not re.search(r"^\s*g_ini_DontUseTheSoundLevel\s*=\s*FALSE", new_text, flags=re.M | re.I):
        new_text = re.sub(
            r"^\s*--\s*g_ini_DontUseTheSoundLevel\s*=\s*FALSE",
            "    g_ini_DontUseTheSoundLevel = FALSE",
            new_text,
            count=1,
            flags=re.M | re.I,
        )
    if new_text != text:
        print(f"  [ok]   Updated {ini_path.name} (QT3Mix -> DirectSound)")
        if not dry_run:
            bak = ini_path.with_suffix(".INI.BAK")
            if not bak.exists():
                shutil.copy2(ini_path, bak)
            ini_path.write_bytes(new_text.encode("latin1"))
    else:
        print(f"  [skip] {ini_path.name} already configured for DirectSound")


def compile_launcher(out_exe: Path, dry_run=False):
    for candidate in (SRC_DIR / "KOTH_Launcher.exe", BUNDLE_DIR / "KOTH_Launcher.exe", APP_DIR / "KOTH_Launcher.exe"):
        if candidate.is_file():
            print(f"  [ok]   Using precompiled launcher ({candidate.name})")
            if not dry_run:
                shutil.copy2(candidate, out_exe)
            return

    csc = find_csc()
    cs_src = SRC_DIR / "KOTH_Fullscreen_Launcher.cs"
    print(f"  [ok]   Compiling {out_exe.name} with {csc}")
    if dry_run:
        return
    res = subprocess.run(
        [str(csc), "/nologo", "/optimize+", "/target:winexe", f"/out:{out_exe}", str(cs_src)],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        raise RuntimeError(f"csc.exe failed:\n{res.stdout}\n{res.stderr}")


def write_batch(path: Path, content: str, dry_run=False):
    print(f"  [ok]   Writing {path.name}")
    if not dry_run:
        path.write_text(content, encoding="ascii", newline="\r\n")


def find_game_dir(root: Path, rel_candidates):
    for rel in rel_candidates:
        p = root / rel
        if p.is_dir():
            return p
    return None


def copy_cd_to_output(src: Path, dst: Path, games, dry_run=False):
    print(f"[info] Copying required CD-ROM folders from {src} -> {dst} ...")
    if dry_run:
        return
    dst.mkdir(parents=True, exist_ok=True)
    ar_src = src / "AUTORUN.EXE"
    if ar_src.is_file() and not (dst / "AUTORUN.EXE").exists():
        shutil.copy2(ar_src, dst / "AUTORUN.EXE")
    # Note: HUNT needs Xtras + budapi32.dll from HOOT as well
    folders = set()
    if "hoot" in games or "hunt" in games:
        folders.add("HOOT")
    if "hunt" in games:
        folders.add("HUNT")
    for folder in sorted(folders):
        s_dir = src / folder
        d_dir = dst / folder
        if s_dir.is_dir():
            if not d_dir.exists():
                shutil.copytree(s_dir, d_dir)
                # Strip read-only attribute from CD-ROM copies
                for p in d_dir.rglob("*"):
                    try:
                        os.chmod(p, 0o666 if p.is_file() else 0o777)
                    except OSError:
                        pass


def patch_hoot(work_root: Path, clean_stub: bytes, dlls: dict, winmm_proxy_bytes: bytes, winmm_orig_path: Path, launcher_exe: Path, dry_run=False):
    print("\n=== Patching King of the Hill: Hootenanny (HOOT) ===")
    hoot_root = work_root / "HOOT"
    active_dir = find_game_dir(
        hoot_root,
        [
            Path("PROGRAMF/FOX/KINGOFTH/HOOTENAN"),
            Path("program files/fox/King of the Hill/Hootenanny"),
        ],
    )
    if not active_dir:
        raise FileNotFoundError(f"Could not find Hootenanny directory under {hoot_root}")

    alt_dir = hoot_root / "program files/fox/King of the Hill/Hootenanny"
    sync_dirs = [active_dir]
    if alt_dir.is_dir() and alt_dir.resolve() != active_dir.resolve():
        sync_dirs.append(alt_dir)

    for gdir in sync_dirs:
        print(f"  Target: {gdir}")
        for exe_name in ("HOOTPC.EXE", "HOOT.EXE"):
            ep = gdir / exe_name
            if ep.is_file():
                unwrap_safedisc_exe(ep, clean_stub, dry_run=dry_run)

        # Deploy runtime DLLs (IML32.dll gets HOOT backdrop bypass patch)
        for dll_name, dll_bytes in dlls.items():
            dst_dll = gdir / dll_name
            if not dry_run:
                dst_dll.write_bytes(dll_bytes)
        apply_binary_patches(gdir / "IML32.dll", HOOT_IML32_PATCHES, make_backup=False, dry_run=dry_run)

        if not dry_run:
            (gdir / "WINMM.dll").write_bytes(winmm_proxy_bytes)
            shutil.copy2(winmm_orig_path, gdir / "winmm_orig.dll")
        print("  [ok]   Installed Director 8 runtime DLLs + WINMM.dll proxy")

        # Patch SHARED\BP_LIB.CST
        bplib = gdir / "SHARED" / "BP_LIB.CST"
        if bplib.is_file():
            print(f"  Patching {bplib.name}:")
            apply_binary_patches(bplib, HOOT_BPLIB_PATCHES, make_backup=True, dry_run=dry_run)
        else:
            print(f"  [warn] Missing {bplib}")

        patch_lingo_ini(gdir / "LINGO.INI", is_hoot=True, dry_run=dry_run)

        if not dry_run:
            (gdir / "HOOTPC.INI").write_text("[Movies]\nFullScreen=0\nCenter=1\n", encoding="ascii")
        print("  [ok]   Wrote HOOTPC.INI (FullScreen=0, Center=1)")

    if not dry_run:
        shutil.copy2(launcher_exe, hoot_root / "KOTH_Fullscreen_Launcher.exe")

    rel_exe = active_dir.relative_to(hoot_root)
    write_batch(
        hoot_root / "Play_Hootenanny.bat",
        "@echo off\n"
        "taskkill /F /IM HOOTPC.EXE /IM HOOT.EXE >nul 2>&1\n"
        f'cd /d "%~dp0{rel_exe}"\n'
        f'start "" "%~dp0KOTH_Fullscreen_Launcher.exe" --title "King of the Hill - Hootenanny" "%~dp0{rel_exe}\\HOOTPC.EXE"\n',
        dry_run=dry_run,
    )
    write_batch(
        hoot_root / "Play_Hootenanny_Windowed.bat",
        "@echo off\n"
        "taskkill /F /IM HOOTPC.EXE /IM HOOT.EXE >nul 2>&1\n"
        f'cd /d "%~dp0{rel_exe}"\n'
        f'start "" "%~dp0KOTH_Fullscreen_Launcher.exe" --windowed --title "King of the Hill - Hootenanny" "%~dp0{rel_exe}\\HOOTPC.EXE"\n',
        dry_run=dry_run,
    )


def patch_hunt(work_root: Path, clean_stub: bytes, dlls: dict, winmm_proxy_bytes: bytes, winmm_orig_path: Path, launcher_exe: Path, dry_run=False):
    print("\n=== Patching King of the Hill: Texas Huntin' (HUNT) ===")
    hunt_root = work_root / "HUNT"
    gdir = find_game_dir(
        hunt_root,
        [
            Path("PROGRAMF/FOX/KINGOFTH/TEXASHUN"),
            Path("program files/fox/King of the Hill/Texas Huntin'"),
        ],
    )
    if not gdir:
        raise FileNotFoundError(f"Could not find Texas Huntin' directory under {hunt_root}")

    print(f"  Target: {gdir}")
    thunt_exe = gdir / "THUNTPC.EXE"
    if not thunt_exe.is_file():
        raise FileNotFoundError(f"Missing {thunt_exe}")
    unwrap_safedisc_exe(thunt_exe, clean_stub, dry_run=dry_run)

    # Deploy runtime DLLs (keep IML32.dll UNPATCHED for HUNT)
    for dll_name, dll_bytes in dlls.items():
        if not dry_run:
            (gdir / dll_name).write_bytes(dll_bytes)
    if not dry_run:
        (gdir / "WINMM.dll").write_bytes(winmm_proxy_bytes)
        shutil.copy2(winmm_orig_path, gdir / "winmm_orig.dll")
    print("  [ok]   Installed Director 8 runtime DLLs (unpatched IML32.dll) + WINMM.dll proxy")

    # Copy budapi32.dll and clean Windows .x32 Xtras from HOOT
    hoot_gdir = find_game_dir(
        work_root / "HOOT",
        [
            Path("PROGRAMF/FOX/KINGOFTH/HOOTENAN"),
            Path("program files/fox/King of the Hill/Hootenanny"),
        ],
    )
    if hoot_gdir:
        bud = hoot_gdir / "budapi32.dll"
        if bud.is_file() and not dry_run:
            shutil.copy2(bud, gdir / "budapi32.dll")
            print("  [ok]   Copied budapi32.dll from HOOT")

        hoot_xtras = hoot_gdir / "XTRAS"
        hunt_xtras = gdir / "XTRAS"
        if hoot_xtras.is_dir() and hunt_xtras.is_dir():
            backup_xtras = gdir / "XTRAS_ORIG_BACKUP"
            if not dry_run:
                backup_xtras.mkdir(exist_ok=True)
                for item in list(hunt_xtras.iterdir()):
                    if item.is_file() and not item.name.lower().endswith(".x32"):
                        dst_b = backup_xtras / item.name
                        if not dst_b.exists():
                            shutil.move(str(item), str(dst_b))
                for x32 in hoot_xtras.glob("*.x32"):
                    shutil.copy2(x32, hunt_xtras / x32.name)
            print("  [ok]   Replaced Mac/non-.x32 Xtras with Windows Director 8 .x32 Xtras")
    else:
        print("  [warn] HOOT folder not found alongside HUNT; skipped budapi32.dll and XTRAS copy")

    # Fix 8.3 truncated filenames expected by Texas Huntin' Lingo scripts
    stub_dir = gdir / "HUNTING.DIR"
    if stub_dir.is_file() and stub_dir.stat().st_size <= 64:
        bak_dir = gdir / "HUNTING.DIR.bak"
        print("  [ok]   Renaming 13-byte stub HUNTING.DIR -> HUNTING.DIR.bak")
        if not dry_run and not bak_dir.exists():
            stub_dir.rename(bak_dir)

    renames = [
        (gdir / "CASTS/SCENE/PLAYERSE.CST", gdir / "CASTS/SCENE/PlayerSelect.cst"),
        (gdir / "CASTS/QTS/MONDOKOT.MOV", gdir / "CASTS/QTS/MONDO_KOTH.mov"),
        (gdir / "TEXASHUN.INI", gdir / "Texas Huntin'.ini"),
    ]
    for src_f, dst_f in renames:
        if src_f.is_file() and not dst_f.exists():
            print(f"  [ok]   Restoring long filename: {src_f.name} -> {dst_f.name}")
            if not dry_run:
                shutil.copy2(src_f, dst_f)

    patch_lingo_ini(gdir / "LINGO.INI", is_hoot=False, dry_run=dry_run)

    if not dry_run:
        (gdir / "THUNTPC.INI").write_text("[Movies]\r\nFullScreen=0\r\nCenter=1\r\n", encoding="ascii")
        shutil.copy2(launcher_exe, gdir / "KOTH_Fullscreen_Launcher.exe")
    print("  [ok]   Wrote THUNTPC.INI (FullScreen=0, Center=1)")

    rel_exe = gdir.relative_to(hunt_root)
    write_batch(
        hunt_root / "Play_Texas_Hunting.bat",
        "@echo off\n"
        "taskkill /F /IM THUNTPC.EXE /IM KOTH_Fullscreen_Launcher.exe >nul 2>&1\n"
        f'cd /d "%~dp0{rel_exe}"\n'
        f'start "" "%~dp0{rel_exe}\\KOTH_Fullscreen_Launcher.exe" --title "King of the Hill - Texas Hunting" "%~dp0{rel_exe}\\THUNTPC.EXE"\n',
        dry_run=dry_run,
    )
    write_batch(
        hunt_root / "Play_Texas_Hunting_Windowed.bat",
        "@echo off\n"
        "taskkill /F /IM THUNTPC.EXE /IM KOTH_Fullscreen_Launcher.exe >nul 2>&1\n"
        f'cd /d "%~dp0{rel_exe}"\n'
        f'start "" "%~dp0{rel_exe}\\KOTH_Fullscreen_Launcher.exe" --windowed --title "King of the Hill - Texas Hunting" "%~dp0{rel_exe}\\THUNTPC.EXE"\n',
        dry_run=dry_run,
    )


def scan_for_cd():
    for d in [f"{c}:\\" for c in string.ascii_uppercase[3:]] + [".", ".."]:
        try:
            p = Path(d).resolve()
            if (p / "AUTORUN.EXE").is_file() and ((p / "HOOT").is_dir() or (p / "HUNT").is_dir()):
                return p
        except Exception:
            pass
    return None


def main():
    parser = argparse.ArgumentParser(
        description=f"King of the Hill: Hootenanny & Texas Huntin' Modern Compatibility Patch v{VERSION}"
    )
    parser.add_argument(
        "source",
        nargs="?",
        default=None,
        help="Path to the King of the Hill CD-ROM drive (e.g. D:\\) or extracted ISO directory containing AUTORUN.EXE, HOOT, and HUNT.",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Optional writable output directory (defaults to C:\\Games\\KingOfTheHill if source is read-only, or patches in-place if writable).",
    )
    parser.add_argument(
        "--game",
        choices=["both", "hoot", "hunt"],
        default="both",
        help="Which game(s) to patch (default: both).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Verify files and planned patches without writing any changes.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s v{VERSION}",
    )
    args = parser.parse_args()

    is_interactive = False
    print("============================================================")
    print(f" King of the Hill (2000) PC Compatibility Patch v{VERSION}")
    print(" Supports: Hootenanny (HOOT) & Texas Huntin' (HUNT)")
    print("============================================================\n")

    if not args.source:
        is_interactive = True
        detected = scan_for_cd()
        if detected:
            resp = input(f"Detected King of the Hill CD at [{detected}].\nPress Enter to use it, or enter another path: ").strip().strip('"')
            src_str = resp if resp else str(detected)
        else:
            src_str = input("Enter path to CD-ROM drive or extracted ISO directory: ").strip().strip('"')
        if not src_str:
            sys.exit("Aborted: no source provided.")
        src_root = Path(src_str).resolve()
    else:
        src_root = Path(args.source).resolve()

    if not src_root.is_dir():
        sys.exit(f"ERROR: Source directory does not exist: {src_root}")

    autorun_path = src_root / "AUTORUN.EXE"
    if not autorun_path.is_file():
        sys.exit(
            f"ERROR: AUTORUN.EXE not found in {src_root}.\n"
            "Point to the root of the King of the Hill (2000) PC CD-ROM or extracted ISO."
        )

    games = ["hoot", "hunt"] if args.game == "both" else [args.game]

    if args.out:
        work_root = Path(args.out).resolve()
        if work_root != src_root:
            copy_cd_to_output(src_root, work_root, games, dry_run=args.dry_run)
    elif not is_writable_dir(src_root):
        if is_interactive:
            default_out = Path(os.environ.get("SystemDrive", "C:") + r"\Games\KingOfTheHill")
            resp = input(f"Destination folder for patched game [default: {default_out}]: ").strip().strip('"')
            work_root = Path(resp).resolve() if resp else default_out
        else:
            work_root = (APP_DIR / "KingOfTheHill_Patched").resolve()
        print(f"[info] Source {src_root} is read-only (CD-ROM/ISO). Copying to {work_root} ...")
        copy_cd_to_output(src_root, work_root, games, dry_run=args.dry_run)
    else:
        work_root = src_root

    print("[info] Extracting clean Director 8.0r178 stub & runtime DLLs from user's AUTORUN.EXE ...")
    clean_stub, dlls = extract_autorun_runtime(autorun_path)

    winmm_orig_path = find_syswow64_winmm()
    tmp_build_obj = tempfile.TemporaryDirectory(prefix="koth_build_")
    tmp_build = Path(tmp_build_obj.name)
    winmm_proxy_path = tmp_build / "WINMM.dll"
    launcher_exe = tmp_build / "KOTH_Fullscreen_Launcher.exe"

    try:
        print(f"[info] Building WINMM.dll proxy from {winmm_orig_path} ...")
        if not args.dry_run:
            size, num_exp, entry_rva = build_winmm_proxy.build_winmm_proxy(str(winmm_proxy_path), str(winmm_orig_path))
            print(f"  [ok]   Built WINMM.dll ({size} bytes, {num_exp} forwarded exports, EntryPoint=0x{entry_rva:X})")
            winmm_proxy_bytes = winmm_proxy_path.read_bytes()
        else:
            winmm_proxy_bytes = b""

        compile_launcher(launcher_exe, dry_run=args.dry_run)

        if "hoot" in games:
            patch_hoot(work_root, clean_stub, dlls, winmm_proxy_bytes, winmm_orig_path, launcher_exe, dry_run=args.dry_run)
        if "hunt" in games:
            patch_hunt(work_root, clean_stub, dlls, winmm_proxy_bytes, winmm_orig_path, launcher_exe, dry_run=args.dry_run)
    finally:
        tmp_build_obj.cleanup()

    print("\n============================================================")
    print("DONE! Your patched game files are ready in:")
    print(f"  {work_root}")
    if "hoot" in games:
        print(f"  - Hootenanny (Fullscreen): {work_root / 'HOOT' / 'Play_Hootenanny.bat'}")
        print(f"  - Hootenanny (Windowed):   {work_root / 'HOOT' / 'Play_Hootenanny_Windowed.bat'}")
    if "hunt" in games:
        print(f"  - Texas Huntin' (Fullscreen): {work_root / 'HUNT' / 'Play_Texas_Hunting.bat'}")
        print(f"  - Texas Huntin' (Windowed):   {work_root / 'HUNT' / 'Play_Texas_Hunting_Windowed.bat'}")
    print("============================================================")

    if is_interactive:
        try:
            input("\nPatch complete! Press Enter to exit...")
        except (KeyboardInterrupt, EOFError):
            pass


if __name__ == "__main__":
    main()
