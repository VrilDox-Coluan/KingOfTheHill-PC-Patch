# King of the Hill (2000) PC — Modern Windows Compatibility & Bugfix Patch

> [!WARNING]
> ### ⚠️ Legal Disclaimer: Bring Your Own CD-ROM / ISO
> **No game data is in this repository. No CD-ROM, no ISO, no executables, no Macromedia Director runtime DLLs, no assets, and no proprietary files are included. Bring your own legally obtained copy of the *King of the Hill* (2000, Fox Interactive) PC CD-ROM.**
>
> All game binaries, Director runtime libraries, Xtras, casts, audio, and video remain on your own CD-ROM / extracted ISO. This repository contains **only** original open-source patching tooling, a DWM fullscreen/windowed launcher (`KOTH_Fullscreen_Launcher.cs`), and an x86 `WINMM.dll` proxy generator (`build_winmm_proxy.py`).

> [!NOTE]
> ### 🛑 Project Scope & Community Note
> This project is a lightweight preservation & compatibility patcher for modern Windows (Windows 10/11). It is open-sourced for the retro PC preservation community and is free to fork, improve, or use as a research base toward a future native recompilation / Linux port.

A zero-dependency patcher and launcher suite that makes both games from the 2000 **King of the Hill** PC CD-ROM — **King of the Hill: Hootenanny** (`HOOT`) and **King of the Hill: Texas Huntin'** (`HUNT`) — playable on modern Windows 10/11 in both **Fullscreen** and **Windowed** modes, while fixing original Macromedia Director 7/8 Lingo gameplay bugs exposed by modern CPUs.

---

## What This Patch Fixes

### Shared (Both *Hootenanny* & *Texas Huntin'*)
- **SafeDisc v1 Compatibility (No `secdrv.sys` required)**: Transplants the clean Macromedia Director 8.0r178 projector stub directly from your own CD-ROM's `AUTORUN.EXE` onto `HOOTPC.EXE` and `THUNTPC.EXE`, and extracts the matching Director 8 runtime DLLs (`Proj.dll`, `DIRAPI.dll`, `IML32.dll`, `msvcrt.dll`) from `AUTORUN.EXE`.
- **Modern DWM Fullscreen & Windowed Launcher (`src/KOTH_Fullscreen_Launcher.cs`)**: Renders the legacy 640×480 Director stage cleanly via Desktop Window Manager thumbnails (`DwmRegisterThumbnail`) in aspect-correct fullscreen or a crisp 640×480 window, eliminating 8-bit/16-bit display mode switches and click-offset issues.
- **Mouse, Keyboard & Backdrop Input Fixes (`src/build_winmm_proxy.py`)**: Builds a lightweight 32-bit `WINMM.dll` proxy (forwarding all exports to your system's `SysWOW64\winmm.dll`) that fixes cursor translation, prevents duplicated keystrokes in text fields (e.g., HOA / Sign-In forms), and redirects `ImlWinBackdropClass` mouse messages properly.
- **Audio Compatibility**: Switches `LINGO.INI` from legacy `"QT3Mix"` (QuickTime 3 audio mixer) to `"DirectSound"` so audio plays reliably without QuickTime crashes or hangs.

### *King of the Hill: Hootenanny* (`HOOT`) Specific Fixes
- **IML32 Stage Clipping Fix**: Patches 8 bytes at `0x2E400` in `IML32.dll` (`85 D2 0F 84 3A 01 00 00` → `E9 3D 01 00 00 90 90 90`) to bypass `ImlWinBackdropClass` clipping.
- **Startup Freeze & Title Screen Fix (`BP_LIB.CST`, `ParentScript 71 - bp_menu section`)**:
  - `0x86616E`: Keeps the title screen background sprite on-stage (`OrgLoc` instead of `kSprOffstageLoc`).
  - `0x866308`: Bypasses the `mFadeSounds` startup deadlock that caused intermittent freezes on launch.
- **Dale's Paintball Instant-Loss Bug (`BP_LIB.CST`, `ParentScript 582 - pb_main manager class`)**:
  - In the original script, Paintball was the only minigame using an unthrottled `on mIdle` call counter (`gameTimer = gameTimer + 1; if gameTimer = 10000`) for its match timer. On modern CPUs, `mIdle` runs thousands of times per second, triggering `#TIMELIMIT` loss within 1–3 seconds.
  - `0x92EE1A` (`on mEnter`) & `0x930938` (`on mIdle`): Replaces the idle counter with a real-time 4-minute wall-clock timeout using `gCurRefTicks` (`if (gCurRefTicks - gameTimer) > (60 * 60 * 4) then`).
- **Peggy's Tic-Tac-Toss & Scheduled Events Missed Triggers (`BP_LIB.CST`, `ParentScript 94 - bp_timeclock manager class`)**:
  - In the original `on mCanLaunchModalHQTrigger`, scheduled events only triggered if the player was idle in `#hq` and were permanently dropped after just 5 game minutes (**25 real seconds**). Because Peggy's Tic-Tac-Toss (`#tt`) is scheduled right after Status Reports (`02:00`/`04:00`/`06:00`) in 6 of 10 schedules (or right after Bobby's Scavenger Hunt), it was frequently dropped silently.
  - `0x86BD55`: Reduces the retry interval from 2 to 1 game minute (~5 real seconds) and extends the retry window from 5 to 50 game minutes (still cleanly bounded by the next hour's `#mNewScene`).

### *King of the Hill: Texas Huntin'* (`HUNT`) Specific Fixes
- **8.3 Truncated Filename Restoration**: Renames the 13-byte stub `HUNTING.DIR` → `HUNTING.DIR.bak`, restores `PLAYERSE.CST` → `PlayerSelect.cst`, `MONDOKOT.MOV` → `MONDO_KOTH.mov`, and `TEXASHUN.INI` → `Texas Huntin'.ini`.
- **Xtras & Runtime Cleanup**: Backs up Mac/non-`.x32` Xtras to `XTRAS_ORIG_BACKUP/` and installs the clean Windows Director 8 `.x32` Xtras and `budapi32.dll` from your CD-ROM's `HOOT` folder.

---

## Requirements

- **Windows 10 or Windows 11** (built-in .NET Framework 4.x `csc.exe` is used automatically — no Visual Studio required).
- **Python 3.8+** (standard library only — **zero `pip` packages required**).
- Your own **King of the Hill (2000) PC CD-ROM** or extracted **ISO** folder containing `AUTORUN.EXE`, `HOOT\`, and `HUNT\`.

---

## How to Use

### Option 1: Double-Click (`apply_patch.bat`)
1. Insert your *King of the Hill* CD-ROM, mount your `.iso`, or extract it to a folder (e.g., `C:\Games\KOTH`).
2. Run **`apply_patch.bat`** (or drag-and-drop your CD-ROM / extracted ISO folder onto `apply_patch.bat`).
3. When prompted:
   - Enter the path to your CD-ROM drive or extracted ISO folder (e.g. `D:\` or `C:\Games\KOTH`).
   - Optionally enter an output folder (if your source is a read-only CD-ROM/ISO, it will automatically copy the needed folders to `.\KOTH_Patched` and patch them there).
4. Launch the games using the generated batch files:
   - **Hootenanny**: `HOOT\Play_Hootenanny.bat` (Fullscreen) or `HOOT\Play_Hootenanny_Windowed.bat` (Windowed)
   - **Texas Huntin'**: `HUNT\Play_Texas_Hunting.bat` (Fullscreen) or `HUNT\Play_Texas_Hunting_Windowed.bat` (Windowed)

### Option 2: Command Line (`patch_koth.py`)
```powershell
# Patch both games from a mounted CD-ROM/ISO into a writable folder:
python patch_koth.py D:\ --out C:\Games\KOTH_Patched

# Patch an already-extracted writable folder in-place:
python patch_koth.py C:\Games\KOTH

# Patch only Hootenanny or only Texas Huntin':
python patch_koth.py C:\Games\KOTH --game hoot
python patch_koth.py C:\Games\KOTH --game hunt

# Verify everything without modifying any files:
python patch_koth.py C:\Games\KOTH --dry-run
```

Original files (`HOOTPC.SAFEDISC.EXE`, `THUNTPC.SAFEDISC.EXE`, `BP_LIB.CST.BAK`, `LINGO.INI.BAK`) are always backed up before modification.

---

## Repository Structure

```text
KingOfTheHill-PC-Patch/
├── README.md                       # Documentation & legal disclaimers
├── LICENSE                         # MIT License (for original patcher/launcher code)
├── .gitignore                      # Blocks all game files, ISOs, and built binaries
├── apply_patch.bat                 # User-friendly Windows batch front-end
├── patch_koth.py                   # Self-contained pure-Python 3 patcher
└── src/
    ├── KOTH_Fullscreen_Launcher.cs # C# DWM fullscreen/windowed launcher
    └── build_winmm_proxy.py        # Pure-Python 32-bit WINMM.dll proxy generator
```

---

## Acknowledgments & Thanks

- **[ProjectorRays](https://github.com/ProjectorRays/ProjectorRays)** — A huge thank you to the **ProjectorRays** team and contributors! Every single Macromedia Director Lingo bytecode investigation and fix in this project (including diagnosing the startup `mFadeSounds` hang, Dale's Paintball unthrottled `mIdle` timer, Peggy's Tic-Tac-Toss `bp_timeclock` trigger retry window, and *Texas Huntin'*'s 8.3 cast/QuickTime filename lookups) was made possible by decompiling the Director `.CST`/`.DXR` scripts with **ProjectorRays**.

---

## License

The original source code in this repository (`patch_koth.py`, `apply_patch.bat`, `src/KOTH_Fullscreen_Launcher.cs`, `src/build_winmm_proxy.py`) is released under the **MIT License** (see [LICENSE](LICENSE)).

*King of the Hill* and its associated trademarks, characters, audio, artwork, and game scripts are the property of their respective copyright holders. This project is an independent, non-commercial fan compatibility patch and is not affiliated with or endorsed by Fox Interactive or 20th Television.
