import os
import sys
import struct

DEFAULT_WINMM = r"C:\Windows\SysWOW64\winmm.dll"
if not os.path.exists(DEFAULT_WINMM):
    DEFAULT_WINMM = r"C:\Windows\System32\winmm.dll"

IMAGE_BASE = 0x68800000
SECT_ALIGN = 0x1000
FILE_ALIGN = 0x200


def read_pe32_exports(dll_path):
    """Pure-Python PE32 export directory parser (no external dependencies)."""
    data = open(dll_path, "rb").read()
    if data[:2] != b"MZ":
        raise ValueError(f"Not a valid PE file: {dll_path}")
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b"PE\x00\x00":
        raise ValueError(f"Invalid PE signature: {dll_path}")
    machine, num_secs, _, _, _, opt_sz, _ = struct.unpack_from("<HHIIIHH", data, pe_off + 4)
    if machine != 0x014C:
        raise ValueError(f"Expected 32-bit x86 DLL (0x014C), got 0x{machine:04X}: {dll_path}")
    opt_off = pe_off + 24
    exp_rva, exp_sz = struct.unpack_from("<II", data, opt_off + 96)
    sec_off = opt_off + opt_sz
    secs = []
    for i in range(num_secs):
        _, vsize, va, rsize, roff = struct.unpack_from("<8sIIII", data, sec_off + i * 40)
        secs.append((va, max(vsize, rsize), roff))

    def rva_to_off(rva):
        for va, span, roff in secs:
            if va <= rva < va + span:
                return roff + (rva - va)
        raise ValueError(f"RVA 0x{rva:X} not mapped in {dll_path}")

    def read_cstr(rva):
        o = rva_to_off(rva)
        end = data.index(b"\x00", o)
        return data[o:end].decode("ascii")

    eo = rva_to_off(exp_rva)
    _, _, _, _, _, exp_base, num_funcs, num_names, funcs_rva, names_rva, ords_rva = struct.unpack_from("<IIHHIIIIIII", data, eo)
    name_by_idx = {}
    names_off = rva_to_off(names_rva)
    ords_off = rva_to_off(ords_rva)
    for i in range(num_names):
        name_rva = struct.unpack_from("<I", data, names_off + i * 4)[0]
        ord_idx = struct.unpack_from("<H", data, ords_off + i * 2)[0]
        name_by_idx[ord_idx] = read_cstr(name_rva)

    funcs_off = rva_to_off(funcs_rva)
    symbols = []
    for idx in range(num_funcs):
        fn_rva = struct.unpack_from("<I", data, funcs_off + idx * 4)[0]
        if fn_rva != 0:
            symbols.append((exp_base + idx, name_by_idx.get(idx)))
    return symbols, exp_base


def align_up(val, align):
    return (val + align - 1) & ~(align - 1)


class X86Asm:
    """Minimal x86-32 assembler with labels and VA relocation tracking."""

    def __init__(self, text_va):
        self.text_va = text_va
        self.buf = bytearray()
        self.labels = {}
        self.fixups = []  # (offset, kind, target_or_va) kind: 'rel32' | 'abs32' | 'rel8'
        self.relocs = []  # RVAs of 32-bit absolute VAs requiring base relocation

    @property
    def va(self):
        return self.text_va + len(self.buf)

    def label(self, name):
        self.labels[name] = len(self.buf)

    def emit(self, bs):
        self.buf.extend(bs)

    def abs32_va(self, target_va):
        self.relocs.append(0x1000 + len(self.buf))
        self.emit(struct.pack("<I", target_va))

    def abs32_label(self, name):
        self.relocs.append(0x1000 + len(self.buf))
        self.fixups.append((len(self.buf), "abs32", name))
        self.emit(b"\x00\x00\x00\x00")

    def jmp_label(self, name):
        self.emit(b"\xE9")
        self.fixups.append((len(self.buf), "rel32", name))
        self.emit(b"\x00\x00\x00\x00")

    def jcc_label(self, cc_opcode2, name):
        # 0x0F <cc_opcode2> rel32 (e.g. 0x84=je, 0x85=jne, 0x8C=jl, 0x8D=jge, 0x8E=jle, 0x8F=jg)
        self.emit(bytes([0x0F, cc_opcode2]))
        self.fixups.append((len(self.buf), "rel32", name))
        self.emit(b"\x00\x00\x00\x00")

    def call_label(self, name):
        self.emit(b"\xE8")
        self.fixups.append((len(self.buf), "rel32", name))
        self.emit(b"\x00\x00\x00\x00")

    def call_iat(self, iat_va):
        # FF 15 <imm32>
        self.emit(b"\xFF\x15")
        self.abs32_va(iat_va)

    def finalize(self):
        for off, kind, target in self.fixups:
            if kind == "rel32":
                target_off = self.labels[target]
                disp = target_off - (off + 4)
                struct.pack_into("<i", self.buf, off, disp)
            elif kind == "abs32":
                target_va = self.text_va + self.labels[target]
                struct.pack_into("<I", self.buf, off, target_va)
        return bytes(self.buf)


def build_rdata(exp_symbols, exp_base, rdata_rva):
    """Build .rdata containing Imports (KERNEL32 + USER32), static strings, and Exports."""
    rdata_va = IMAGE_BASE + rdata_rva
    buf = bytearray()

    def pad(n=4):
        while len(buf) % n:
            buf.append(0)

    # --- 1. Static ASCII strings for EnsurePatched / GetClassName / FindWindowA checks ---
    def add_str(s):
        off = len(buf)
        buf.extend(s.encode("ascii") + b"\x00")
        return off

    s_iml32_off = add_str("IML32.dll")
    s_proj_off = add_str("Proj.dll")
    s_dirapi_off = add_str("DIRAPI.dll")
    s_backdrop_off = add_str("ImlWinBackdropClass")
    s_host_title_off = add_str("KOTH_FULLSCREEN_HOST")
    pad(4)

    # --- 2. Import Directory ---
    # 2 DLL descriptors + 1 null descriptor = 3 * 20 = 60 bytes
    k32_names = ["GetModuleHandleA", "VirtualProtect", "DisableThreadLibraryCalls"]
    u32_names = [
        "GetCursorPos",
        "GetMessagePos",
        "PeekMessageA",
        "DispatchMessageA",
        "GetTopWindow",
        "GetSystemMetrics",
        "GetClassNameA",
        "FindWindowA",
        "GetAsyncKeyState",
    ]

    imp_dir_off = len(buf)
    buf.extend(b"\x00" * 60)

    k32_ilt_off = len(buf)
    buf.extend(b"\x00" * (4 * (len(k32_names) + 1)))
    u32_ilt_off = len(buf)
    buf.extend(b"\x00" * (4 * (len(u32_names) + 1)))

    k32_iat_off = len(buf)
    buf.extend(b"\x00" * (4 * (len(k32_names) + 1)))
    u32_iat_off = len(buf)
    buf.extend(b"\x00" * (4 * (len(u32_names) + 1)))

    k32_dll_off = add_str("KERNEL32.dll")
    u32_dll_off = add_str("USER32.dll")
    pad(2)

    iat = {}
    for idx, nm in enumerate(k32_names):
        pad(2)
        hn_off = len(buf)
        buf.extend(struct.pack("<H", 0) + nm.encode("ascii") + b"\x00")
        rva = rdata_rva + hn_off
        struct.pack_into("<I", buf, k32_ilt_off + idx * 4, rva)
        struct.pack_into("<I", buf, k32_iat_off + idx * 4, rva)
        iat[nm] = rdata_va + k32_iat_off + idx * 4

    for idx, nm in enumerate(u32_names):
        pad(2)
        hn_off = len(buf)
        buf.extend(struct.pack("<H", 0) + nm.encode("ascii") + b"\x00")
        rva = rdata_rva + hn_off
        struct.pack_into("<I", buf, u32_ilt_off + idx * 4, rva)
        struct.pack_into("<I", buf, u32_iat_off + idx * 4, rva)
        iat[nm] = rdata_va + u32_iat_off + idx * 4

    # Fill descriptors (ILT RVA, TimeDateStamp=0, ForwarderChain=0, NameRVA, IAT RVA)
    struct.pack_into(
        "<IIIII",
        buf,
        imp_dir_off,
        rdata_rva + k32_ilt_off,
        0,
        0,
        rdata_rva + k32_dll_off,
        rdata_rva + k32_iat_off,
    )
    struct.pack_into(
        "<IIIII",
        buf,
        imp_dir_off + 20,
        rdata_rva + u32_ilt_off,
        0,
        0,
        rdata_rva + u32_dll_off,
        rdata_rva + u32_iat_off,
    )
    pad(4)

    # --- 3. Export Directory (Forwarders to winmm_orig) ---
    # All forwarder strings must sit inside [exp_dir_off, exp_dir_end)
    exp_dir_off = len(buf)
    buf.extend(b"\x00" * 40)  # IMAGE_EXPORT_DIRECTORY

    min_ord = min(o for o, _ in exp_symbols)
    max_ord = max(o for o, _ in exp_symbols)
    num_funcs = max_ord - min_ord + 1
    named = sorted([(o, n) for o, n in exp_symbols if n], key=lambda x: x[1])
    num_names = len(named)

    eat_off = len(buf)
    buf.extend(b"\x00" * (4 * num_funcs))
    npt_off = len(buf)
    buf.extend(b"\x00" * (4 * num_names))
    ot_off = len(buf)
    buf.extend(b"\x00" * (2 * num_names))
    pad(4)

    dll_name_off = add_str("WINMM.dll")

    # Write forwarder strings & populate EAT
    ord_map = dict(exp_symbols)
    for idx in range(num_funcs):
        o = min_ord + idx
        if o in ord_map:
            nm = ord_map[o]
            fwd = f"winmm_orig.{nm}" if nm else f"winmm_orig.#{o}"
            fwd_off = add_str(fwd)
            struct.pack_into("<I", buf, eat_off + idx * 4, rdata_rva + fwd_off)

    # Write export names & populate NPT + OT
    for idx, (o, nm) in enumerate(named):
        nm_off = add_str(nm)
        struct.pack_into("<I", buf, npt_off + idx * 4, rdata_rva + nm_off)
        struct.pack_into("<H", buf, ot_off + idx * 2, o - min_ord)

    exp_dir_end = len(buf)
    struct.pack_into(
        "<IIHHIIIIIII",
        buf,
        exp_dir_off,
        0,  # Characteristics
        0,  # TimeDateStamp
        0,  # MajorVersion
        0,  # MinorVersion
        rdata_rva + dll_name_off,
        min_ord,
        num_funcs,
        num_names,
        rdata_rva + eat_off,
        rdata_rva + npt_off,
        rdata_rva + ot_off,
    )

    info = {
        "str_iml32_va": rdata_va + s_iml32_off,
        "str_proj_va": rdata_va + s_proj_off,
        "str_dirapi_va": rdata_va + s_dirapi_off,
        "str_backdrop_va": rdata_va + s_backdrop_off,
        "str_host_title_va": rdata_va + s_host_title_off,
        "imp_dir_rva": rdata_rva + imp_dir_off,
        "imp_dir_size": 60,
        "iat_rva": rdata_rva + k32_iat_off,
        "iat_size": (u32_iat_off + 4 * (len(u32_names) + 1)) - k32_iat_off,
        "exp_dir_rva": rdata_rva + exp_dir_off,
        "exp_dir_size": exp_dir_end - exp_dir_off,
        "iat": iat,
    }
    return bytes(buf), info


def build_text(info, data_va):
    a = X86Asm(IMAGE_BASE + 0x1000)
    iat = info["iat"]

    g_old_prot_va = data_va
    g_dirapi_ret_va = data_va + 4
    g_lbutton_hold_va = data_va + 8
    g_last_gx_va = data_va + 12
    g_last_gy_va = data_va + 16
    g_has_last_va = data_va + 20

    # =========================================================================
    # Helpers: StrEq(const char* a, const char* b) -> eax = 1 if equal else 0
    # =========================================================================
    # cdecl/stdcall(a, b) ret 8
    a.label("StrEq")
    a.emit(b"\x56\x57")  # push esi; push edi
    a.emit(b"\x8B\x74\x24\x0C")  # mov esi, [esp+0x0c] (a)
    a.emit(b"\x8B\x7C\x24\x10")  # mov edi, [esp+0x10] (b)
    a.label("StrEq_loop")
    a.emit(b"\x8A\x06")  # mov al, [esi]
    a.emit(b"\x3A\x07")  # cmp al, [edi]
    a.jcc_label(0x85, "StrEq_ne")  # jne
    a.emit(b"\x84\xC0")  # test al, al
    a.jcc_label(0x84, "StrEq_eq")  # je
    a.emit(b"\x46\x47")  # inc esi; inc edi
    a.jmp_label("StrEq_loop")
    a.label("StrEq_eq")
    a.emit(b"\x6A\x01\x58\x5F\x5E\xC2\x08\x00")  # push 1; pop eax; pop edi; pop esi; ret 8
    a.label("StrEq_ne")
    a.emit(b"\x33\xC0\x5F\x5E\xC2\x08\x00")  # xor eax,eax; pop edi; pop esi; ret 8

    # =========================================================================
    # MapScreenToStage(int* px, int* py, int clientMode)  [stdcall ret 12]
    # [ebp+8]=px, [ebp+12]=py, [ebp+16]=clientMode
    # locals: [ebp-4]=targetW, [ebp-8]=targetH, [ebp-0xc]=dstX, [ebp-0x10]=dstY,
    #         [ebp-0x14]=stageX, [ebp-0x18]=stageY
    # =========================================================================
    a.label("MapScreenToStage")
    a.emit(b"\x55\x8B\xEC")  # push ebp; mov ebp, esp
    a.emit(b"\x83\xEC\x18")  # sub esp, 0x18
    a.emit(b"\x53\x56\x57")  # push ebx; push esi; push edi

    a.emit(b"\x6A\x00")  # push 0 (SM_CXSCREEN)
    a.call_iat(iat["GetSystemMetrics"])
    a.emit(b"\x89\xC6")  # mov esi, eax  (esi = sw)

    a.emit(b"\x6A\x01")  # push 1 (SM_CYSCREEN)
    a.call_iat(iat["GetSystemMetrics"])
    a.emit(b"\x89\xC7")  # mov edi, eax  (edi = sh)

    a.emit(b"\x81\xFE\x80\x02\x00\x00")  # cmp esi, 640
    a.jcc_label(0x8E, "Map_done")  # jle
    a.emit(b"\x81\xFF\xE0\x01\x00\x00")  # cmp edi, 480
    a.jcc_label(0x8E, "Map_done")  # jle

    # stageX = (sw - 640) >> 1; stageY = (sh - 480) >> 1
    a.emit(b"\x8D\x86\x80\xFD\xFF\xFF")  # lea eax, [esi - 640]
    a.emit(b"\xD1\xF8")  # sar eax, 1
    a.emit(b"\x89\x45\xEC")  # mov [ebp-0x14], eax (stageX)
    a.emit(b"\x8D\x87\x20\xFE\xFF\xFF")  # lea eax, [edi - 480]
    a.emit(b"\xD1\xF8")  # sar eax, 1
    a.emit(b"\x89\x45\xE8")  # mov [ebp-0x18], eax (stageY)

    # Check if fullscreen launcher is active: FindWindowA(NULL, "KOTH_FULLSCREEN_HOST")
    a.emit(b"\x68")
    a.abs32_va(info["str_host_title_va"])
    a.emit(b"\x6A\x00")  # push 0 (lpClassName = NULL)
    a.call_iat(iat["FindWindowA"])
    a.emit(b"\x85\xC0")  # test eax, eax
    a.jcc_label(0x84, "Map_windowed")  # jz Map_windowed

    # Fullscreen active: check sw * 3 >= sh * 4 (wide vs narrow)
    a.emit(b"\x69\xC6\x03\x00\x00\x00")  # imul eax, esi, 3
    a.emit(b"\x69\xCF\x04\x00\x00\x00")  # imul ecx, edi, 4
    a.emit(b"\x39\xC8")  # cmp eax, ecx
    a.jcc_label(0x8C, "Map_narrow")  # jl Map_narrow

    # Wide: targetH = sh; targetW = (sh * 4) / 3
    a.emit(b"\x89\x7D\xF8")  # mov [ebp-8], edi (targetH)
    a.emit(b"\x89\xC8\x99")  # mov eax, ecx; cdq
    a.emit(b"\x6A\x03\x5B")  # push 3; pop ebx
    a.emit(b"\xF7\xFB")  # idiv ebx
    a.emit(b"\x89\x45\xFC")  # mov [ebp-4], eax (targetW)
    a.jmp_label("Map_dst")

    a.label("Map_narrow")
    # Narrow: targetW = sw; targetH = (sw * 3) / 4
    a.emit(b"\x89\x75\xFC")  # mov [ebp-4], esi (targetW)
    a.emit(b"\x99")  # cdq (eax holds sw*3)
    a.emit(b"\x6A\x04\x5B")  # push 4; pop ebx
    a.emit(b"\xF7\xFB")  # idiv ebx
    a.emit(b"\x89\x45\xF8")  # mov [ebp-8], eax (targetH)

    a.label("Map_dst")
    # dstX = (sw - targetW) >> 1; dstY = (sh - targetH) >> 1
    a.emit(b"\x89\xF0\x2B\x45\xFC\xD1\xF8\x89\x45\xF4")  # mov eax,esi; sub eax,[ebp-4]; sar eax,1; mov [ebp-0xc],eax
    a.emit(b"\x89\xF8\x2B\x45\xF8\xD1\xF8\x89\x45\xF0")  # mov eax,edi; sub eax,[ebp-8]; sar eax,1; mov [ebp-0x10],eax

    # --- Map X: dx = *px - dstX; clamp [0, targetW-1]; relX = (dx*640)/targetW ---
    a.emit(b"\x8B\x5D\x08")  # mov ebx, [ebp+8] (px)
    a.emit(b"\x8B\x03")  # mov eax, [ebx]
    a.emit(b"\x2B\x45\xF4")  # sub eax, [ebp-0xc]
    a.emit(b"\x85\xC0")  # test eax, eax
    a.jcc_label(0x8D, "Map_x_ge0")  # jge
    a.emit(b"\x33\xC0")  # xor eax, eax
    a.label("Map_x_ge0")
    a.emit(b"\x8B\x4D\xFC\x49")  # mov ecx, [ebp-4]; dec ecx (targetW-1)
    a.emit(b"\x39\xC8")  # cmp eax, ecx
    a.jcc_label(0x8E, "Map_x_lemax")  # jle
    a.emit(b"\x89\xC8")  # mov eax, ecx
    a.label("Map_x_lemax")
    a.emit(b"\x69\xC0\x80\x02\x00\x00")  # imul eax, eax, 640
    a.emit(b"\x99")  # cdq
    a.emit(b"\xF7\x7D\xFC")  # idiv dword ptr [ebp-4]
    a.emit(b"\x83\x7D\x10\x00")  # cmp dword ptr [ebp+0x10], 0
    a.jcc_label(0x85, "Map_x_store")  # jne
    a.emit(b"\x03\x45\xEC")  # add eax, [ebp-0x14] (stageX)
    a.label("Map_x_store")
    a.emit(b"\x89\x03")  # mov [ebx], eax

    # --- Map Y: dy = *py - dstY; clamp [0, targetH-1]; relY = (dy*480)/targetH ---
    a.emit(b"\x8B\x5D\x0C")  # mov ebx, [ebp+0xc] (py)
    a.emit(b"\x8B\x03")  # mov eax, [ebx]
    a.emit(b"\x2B\x45\xF0")  # sub eax, [ebp-0x10]
    a.emit(b"\x85\xC0")  # test eax, eax
    a.jcc_label(0x8D, "Map_y_ge0")  # jge
    a.emit(b"\x33\xC0")  # xor eax, eax
    a.label("Map_y_ge0")
    a.emit(b"\x8B\x4D\xF8\x49")  # mov ecx, [ebp-8]; dec ecx
    a.emit(b"\x39\xC8")  # cmp eax, ecx
    a.jcc_label(0x8E, "Map_y_lemax")  # jle
    a.emit(b"\x89\xC8")  # mov eax, ecx
    a.label("Map_y_lemax")
    a.emit(b"\x69\xC0\xE0\x01\x00\x00")  # imul eax, eax, 480
    a.emit(b"\x99")  # cdq
    a.emit(b"\xF7\x7D\xF8")  # idiv dword ptr [ebp-8]
    a.emit(b"\x83\x7D\x10\x00")  # cmp dword ptr [ebp+0x10], 0
    a.jcc_label(0x85, "Map_y_store")  # jne
    a.emit(b"\x03\x45\xE8")  # add eax, [ebp-0x18] (stageY)
    a.label("Map_y_store")
    a.emit(b"\x89\x03")  # mov [ebx], eax
    a.jmp_label("Map_done")

    a.label("Map_windowed")
    # Windowed mode (no KOTH_FULLSCREEN_HOST):
    # clientMode == 0 -> keep 1:1 screen coordinates unchanged
    # clientMode == 1 -> subtract (stageX, stageY) clamped to [0..639] x [0..479]
    a.emit(b"\x83\x7D\x10\x00")  # cmp dword ptr [ebp+0x10], 0
    a.jcc_label(0x84, "Map_done")  # je Map_done

    a.emit(b"\x8B\x5D\x08")  # mov ebx, [ebp+8] (px)
    a.emit(b"\x8B\x03")  # mov eax, [ebx]
    a.emit(b"\x2B\x45\xEC")  # sub eax, [ebp-0x14] (stageX)
    a.emit(b"\x85\xC0")  # test eax, eax
    a.jcc_label(0x8D, "MapW_x_ge0")  # jge
    a.emit(b"\x33\xC0")  # xor eax, eax
    a.label("MapW_x_ge0")
    a.emit(b"\x3D\x7F\x02\x00\x00")  # cmp eax, 639
    a.jcc_label(0x8E, "MapW_x_lemax")  # jle
    a.emit(b"\xB8\x7F\x02\x00\x00")  # mov eax, 639
    a.label("MapW_x_lemax")
    a.emit(b"\x89\x03")  # mov [ebx], eax

    a.emit(b"\x8B\x5D\x0C")  # mov ebx, [ebp+0xc] (py)
    a.emit(b"\x8B\x03")  # mov eax, [ebx]
    a.emit(b"\x2B\x45\xE8")  # sub eax, [ebp-0x18] (stageY)
    a.emit(b"\x85\xC0")  # test eax, eax
    a.jcc_label(0x8D, "MapW_y_ge0")  # jge
    a.emit(b"\x33\xC0")  # xor eax, eax
    a.label("MapW_y_ge0")
    a.emit(b"\x3D\xDF\x01\x00\x00")  # cmp eax, 479
    a.jcc_label(0x8E, "MapW_y_lemax")  # jle
    a.emit(b"\xB8\xDF\x01\x00\x00")  # mov eax, 479
    a.label("MapW_y_lemax")
    a.emit(b"\x89\x03")  # mov [ebx], eax

    a.label("Map_done")
    a.emit(b"\x5F\x5E\x5B\x8B\xE5\x5D\xC2\x0C\x00")  # pop edi; pop esi; pop ebx; mov esp,ebp; pop ebp; ret 12

    # =========================================================================
    # EnsurePatched() [stdcall ret 0]
    # Patches IML32.dll (0x70378, 0x703A4, 0x703A8, 0x7046C) & Proj.dll (0xC378, 0xC380)
    # =========================================================================
    a.label("EnsurePatched")
    a.emit(b"\x53\x56\x57")  # push ebx; push esi; push edi

    # Check DIRAPI.dll
    a.emit(b"\x68")
    a.abs32_va(info["str_dirapi_va"])
    a.call_iat(iat["GetModuleHandleA"])
    a.emit(b"\x85\xC0")  # test eax, eax
    a.jcc_label(0x84, "Ensure_iml")  # jz
    a.emit(b"\x89\xC6")  # mov esi, eax (dirapiBase)
    # Check if already patched: cmp byte ptr [esi + 0x2E3D1], 0x54
    a.emit(b"\x80\xBE\xD1\xE3\x02\x00\x54")
    a.jcc_label(0x84, "Ensure_iml")  # je
    # VirtualProtect(esi + 0x2E3D0, 64, 0x40, &g_old_prot)
    a.emit(b"\x68")
    a.abs32_va(g_old_prot_va)
    a.emit(b"\x6A\x40")  # PAGE_EXECUTE_READWRITE
    a.emit(b"\x6A\x40")  # 64 bytes
    a.emit(b"\x8D\x9E\xD0\xE3\x02\x00")  # lea ebx, [esi + 0x2E3D0]
    a.emit(b"\x53")  # push ebx
    a.call_iat(iat["VirtualProtect"])
    a.emit(b"\x85\xC0")
    a.jcc_label(0x84, "Ensure_iml")
    # Write 16 dwords into [ebx]:
    a.emit(b"\xC7\x43\x00" + struct.pack("<I", 0x0824548B))
    a.emit(b"\xC7\x43\x04" + struct.pack("<I", 0x04244C8B))
    a.emit(b"\xC7\x43\x08" + struct.pack("<I", 0x0842BF0F))
    a.emit(b"\xC7\x43\x0C" + struct.pack("<I", 0x2912BF0F))
    a.emit(b"\xC7\x43\x10" + struct.pack("<I", 0x818966D0))
    a.emit(b"\xC7\x43\x14" + struct.pack("<I", 0x0000019E))
    a.emit(b"\xC7\x43\x18" + struct.pack("<I", 0x0824548B))
    a.emit(b"\xC7\x43\x1C" + struct.pack("<I", 0x0C42BF0F))
    a.emit(b"\xC7\x43\x20" + struct.pack("<I", 0x0452BF0F))
    a.emit(b"\xC7\x43\x24" + struct.pack("<I", 0x8966D029))
    a.emit(b"\xC7\x43\x28" + struct.pack("<I", 0x00019C81))
    a.emit(b"\xC7\x43\x2C" + struct.pack("<I", 0x9881C700))
    a.emit(b"\xC7\x43\x30" + struct.pack("<I", 0x00000001))
    a.emit(b"\xC7\x43\x34" + struct.pack("<I", 0xC2000000))
    a.emit(b"\xC7\x43\x38" + struct.pack("<I", 0x90900008))
    a.emit(b"\xC7\x43\x3C" + struct.pack("<I", 0x90909090))

    a.label("Ensure_iml")
    # Check IML32.dll
    a.emit(b"\x68")
    a.abs32_va(info["str_iml32_va"])
    a.call_iat(iat["GetModuleHandleA"])
    a.emit(b"\x85\xC0")  # test eax, eax
    a.jcc_label(0x84, "Ensure_proj")  # jz
    a.emit(b"\x89\xC6")  # mov esi, eax (imlBase)
    a.emit(b"\xB8")
    a.abs32_label("Hook_GetCursorPos")
    a.emit(b"\x39\x86\x78\x03\x07\x00")  # cmp [esi + 0x70378], eax
    a.jcc_label(0x84, "Ensure_proj")  # je (already patched!)

    # VirtualProtect(esi + 0x70378, 0x100, 0x40, &g_old_prot)
    a.emit(b"\x68")
    a.abs32_va(g_old_prot_va)
    a.emit(b"\x6A\x40")  # push 0x40
    a.emit(b"\x68\x00\x01\x00\x00")  # push 0x100 (covers 0x70378 .. 0x70478 including 0x7046C GetAsyncKeyState)
    a.emit(b"\x8D\x9E\x78\x03\x07\x00")  # lea ebx, [esi + 0x70378]
    a.emit(b"\x53")  # push ebx
    a.call_iat(iat["VirtualProtect"])
    a.emit(b"\x85\xC0")
    a.jcc_label(0x84, "Ensure_proj")

    # [esi + 0x70378] = Hook_GetCursorPos
    a.emit(b"\xB8")
    a.abs32_label("Hook_GetCursorPos")
    a.emit(b"\x89\x86\x78\x03\x07\x00")
    # [esi + 0x703A4] = Hook_PeekMessageA
    a.emit(b"\xB8")
    a.abs32_label("Hook_PeekMessageA")
    a.emit(b"\x89\x86\xA4\x03\x07\x00")
    # [esi + 0x703A8] = Hook_GetMessagePos
    a.emit(b"\xB8")
    a.abs32_label("Hook_GetMessagePos")
    a.emit(b"\x89\x86\xA8\x03\x07\x00")
    # [esi + 0x7046C] = Hook_GetAsyncKeyState
    a.emit(b"\xB8")
    a.abs32_label("Hook_GetAsyncKeyState")
    a.emit(b"\x89\x86\x6C\x04\x07\x00")

    a.label("Ensure_proj")
    a.emit(b"\x68")
    a.abs32_va(info["str_proj_va"])
    a.call_iat(iat["GetModuleHandleA"])
    a.emit(b"\x85\xC0")
    a.jcc_label(0x84, "Ensure_done")
    a.emit(b"\x89\xC6")  # mov esi, eax (projBase)
    a.emit(b"\xB8")
    a.abs32_label("Hook_PeekMessageA")
    a.emit(b"\x39\x86\x78\xC3\x00\x00")  # cmp [esi + 0xC378], eax
    a.jcc_label(0x84, "Ensure_done")

    # VirtualProtect(esi + 0xC378, 0x10, 0x40, &g_old_prot)
    a.emit(b"\x68")
    a.abs32_va(g_old_prot_va)
    a.emit(b"\x6A\x40")
    a.emit(b"\x6A\x10")
    a.emit(b"\x8D\x9E\x78\xC3\x00\x00")  # lea ebx, [esi + 0xC378]
    a.emit(b"\x53")
    a.call_iat(iat["VirtualProtect"])
    a.emit(b"\x85\xC0")
    a.jcc_label(0x84, "Ensure_done")

    # [esi + 0xC378] = Hook_PeekMessageA
    a.emit(b"\xB8")
    a.abs32_label("Hook_PeekMessageA")
    a.emit(b"\x89\x86\x78\xC3\x00\x00")
    # [esi + 0xC380] = Hook_DispatchMessageA
    a.emit(b"\xB8")
    a.abs32_label("Hook_DispatchMessageA")
    a.emit(b"\x89\x86\x80\xC3\x00\x00")

    a.label("Ensure_done")
    a.emit(b"\x5F\x5E\x5B\xC3")  # pop edi; pop esi; pop ebx; ret

    # =========================================================================
    # Hook_GetAsyncKeyState(int vKey) [stdcall ret 4]
    # Keeps VK_LBUTTON reported as pressed briefly after WM_LBUTTONDOWN even on fast taps
    # so Director's `repeat while (the mouseDown)` enters at least once.
    # =========================================================================
    a.label("Hook_GetAsyncKeyState")
    a.emit(b"\x55\x8B\xEC")  # push ebp; mov ebp, esp
    a.call_label("EnsurePatched")
    a.emit(b"\xFF\x75\x08")  # push [ebp+8]
    a.call_iat(iat["GetAsyncKeyState"])
    a.emit(b"\x83\x7D\x08\x01")  # cmp dword ptr [ebp+8], 1 (VK_LBUTTON)
    a.jcc_label(0x85, "GAKS_ret")  # jne
    a.emit(b"\x66\xA9\x00\x80")  # test ax, 0x8000
    a.jcc_label(0x85, "GAKS_ret")  # jnz (physically pressed)
    a.emit(b"\x8B\x0D")  # mov ecx, dword ptr [g_lbutton_hold_va]
    a.abs32_va(g_lbutton_hold_va)
    a.emit(b"\x85\xC9")  # test ecx, ecx
    a.jcc_label(0x8E, "GAKS_ret")  # jle
    a.emit(b"\x49")  # dec ecx
    a.emit(b"\x89\x0D")  # mov dword ptr [g_lbutton_hold_va], ecx
    a.abs32_va(g_lbutton_hold_va)
    a.emit(b"\xB8\x00\x80\xFF\xFF")  # mov eax, 0xFFFF8000
    a.label("GAKS_ret")
    a.emit(b"\x5D\xC2\x04\x00")  # pop ebp; ret 4

    # =========================================================================
    # FillLastStageScreenPos(int* px, int* py) [stdcall ret 8]
    # Used only as fallback when GetCursorPos fails (locked desktop) or pt==(0,0) in fullscreen.
    # =========================================================================
    a.label("FillLastStageScreenPos")
    a.emit(b"\x55\x8B\xEC\x53\x56")  # push ebp; mov ebp, esp; push ebx; push esi
    a.emit(b"\x6A\x00")
    a.call_iat(iat["GetSystemMetrics"])
    a.emit(b"\x8D\x88\x80\xFD\xFF\xFF")  # lea ecx, [eax - 640]
    a.emit(b"\xD1\xF9")  # sar ecx, 1
    a.emit(b"\x3D\x80\x02\x00\x00")  # cmp eax, 640
    a.jcc_label(0x8F, "FLS_xok")  # jg
    a.emit(b"\x33\xC9")  # xor ecx, ecx
    a.label("FLS_xok")
    a.emit(b"\x8B\x1D")  # mov ebx, [g_last_gx_va]
    a.abs32_va(g_last_gx_va)
    a.emit(b"\x01\xCB")  # add ebx, ecx
    a.emit(b"\x8B\x55\x08")  # mov edx, [ebp+8] (px)
    a.emit(b"\x89\x1A")  # mov [edx], ebx

    a.emit(b"\x6A\x01")
    a.call_iat(iat["GetSystemMetrics"])
    a.emit(b"\x8D\x88\x20\xFE\xFF\xFF")  # lea ecx, [eax - 480]
    a.emit(b"\xD1\xF9")  # sar ecx, 1
    a.emit(b"\x3D\xE0\x01\x00\x00")  # cmp eax, 480
    a.jcc_label(0x8F, "FLS_yok")  # jg
    a.emit(b"\x33\xC9")  # xor ecx, ecx
    a.label("FLS_yok")
    a.emit(b"\x8B\x1D")  # mov ebx, [g_last_gy_va]
    a.abs32_va(g_last_gy_va)
    a.emit(b"\x01\xCB")  # add ebx, ecx
    a.emit(b"\x8B\x55\x0C")  # mov edx, [ebp+0xc] (py)
    a.emit(b"\x89\x1A")  # mov [edx], ebx
    a.emit(b"\x5E\x5B\x5D\xC2\x08\x00")  # pop esi; pop ebx; pop ebp; ret 8

    # =========================================================================
    # Hook_GetCursorPos(LPPOINT lpPt) [stdcall ret 4]
    # =========================================================================
    a.label("Hook_GetCursorPos")
    a.emit(b"\x55\x8B\xEC")  # push ebp; mov ebp, esp
    a.call_label("EnsurePatched")
    a.emit(b"\x8B\x4D\x08\x85\xC9")  # mov ecx, [ebp+8]; test ecx, ecx
    a.jcc_label(0x85, "GCP_hasptr")
    a.emit(b"\xFF\x75\x08")
    a.call_iat(iat["GetCursorPos"])
    a.jmp_label("GCP_ret")

    a.label("GCP_hasptr")
    a.emit(b"\x51")  # push lpPt
    a.call_iat(iat["GetCursorPos"])
    a.emit(b"\x85\xC0")  # test eax, eax
    a.jcc_label(0x84, "GCP_failed")
    a.emit(b"\x8B\x4D\x08")  # mov ecx, [ebp+8]
    a.emit(b"\x50")  # push eax (preserve BOOL return)
    a.emit(b"\x6A\x00")  # push 0 (screen mode)
    a.emit(b"\x8D\x51\x04\x52")  # lea edx, [ecx+4]; push edx (&y)
    a.emit(b"\x51")  # push ecx (&x)
    a.call_label("MapScreenToStage")
    a.emit(b"\x58")  # pop eax
    a.jmp_label("GCP_ret")

    a.label("GCP_failed")
    a.emit(b"\xA1")  # mov eax, [g_has_last_va]
    a.abs32_va(g_has_last_va)
    a.emit(b"\x85\xC0")
    a.jcc_label(0x84, "GCP_ret_zero")
    a.emit(b"\x8B\x4D\x08")
    a.emit(b"\x8D\x51\x04\x52")
    a.emit(b"\x51")
    a.call_label("FillLastStageScreenPos")
    a.emit(b"\x6A\x01\x58")  # return TRUE
    a.jmp_label("GCP_ret")

    a.label("GCP_ret_zero")
    a.emit(b"\x33\xC0")
    a.label("GCP_ret")
    a.emit(b"\x5D\xC2\x04\x00")  # pop ebp; ret 4

    # =========================================================================
    # Hook_GetMessagePos() [stdcall ret 0]
    # =========================================================================
    a.label("Hook_GetMessagePos")
    a.emit(b"\x55\x8B\xEC\x83\xEC\x08")  # push ebp; mov ebp, esp; sub esp, 8
    a.call_label("EnsurePatched")
    a.call_iat(iat["GetMessagePos"])
    a.emit(b"\x85\xC0")
    a.jcc_label(0x85, "GMP_map")
    a.emit(b"\x8B\x0D")
    a.abs32_va(g_has_last_va)
    a.emit(b"\x85\xC9")
    a.jcc_label(0x84, "GMP_map")
    a.emit(b"\x8D\x45\xF8\x50")
    a.emit(b"\x8D\x45\xFC\x50")
    a.call_label("FillLastStageScreenPos")
    a.jmp_label("GMP_pack")

    a.label("GMP_map")
    a.emit(b"\x0F\xBF\xC8")  # movsx ecx, ax  (x)
    a.emit(b"\xC1\xF8\x10")  # sar eax, 16    (y)
    a.emit(b"\x89\x4D\xFC")  # mov [ebp-4], ecx
    a.emit(b"\x89\x45\xF8")  # mov [ebp-8], eax
    a.emit(b"\x6A\x00")  # push 0 (screen mode)
    a.emit(b"\x8D\x45\xF8\x50")  # lea eax, [ebp-8]; push eax
    a.emit(b"\x8D\x45\xFC\x50")  # lea eax, [ebp-4]; push eax
    a.call_label("MapScreenToStage")
    a.label("GMP_pack")
    a.emit(b"\x8B\x45\xF8\xC1\xE0\x10")  # mov eax, [ebp-8]; shl eax, 16
    a.emit(b"\x0F\xB7\x4D\xFC")  # movzx ecx, word ptr [ebp-4]
    a.emit(b"\x0B\xC1")  # or eax, ecx
    a.emit(b"\x8B\xE5\x5D\xC3")  # mov esp, ebp; pop ebp; ret

    # =========================================================================
    # MaybeRedirectBackdrop(MSG* lpMsg) [stdcall ret 4]
    # If lpMsg->hwnd class is "ImlWinBackdropClass" and GetTopWindow(hwnd)!=0,
    # sets lpMsg->hwnd = topChild. Preserves EAX via stack or void.
    # =========================================================================
    a.label("MaybeRedirectBackdrop")
    a.emit(b"\x55\x8B\xEC\x83\xEC\x24")  # push ebp; mov ebp, esp; sub esp, 0x24 (char cls[36])
    a.emit(b"\x56\x8B\x75\x08")  # push esi; mov esi, [ebp+8] (lpMsg)
    a.emit(b"\x8B\x06\x85\xC0")  # mov eax, [esi] (hwnd); test eax, eax
    a.jcc_label(0x84, "MRB_done")
    a.emit(b"\x6A\x20")  # push 32
    a.emit(b"\x8D\x4D\xDC\x51")  # lea ecx, [ebp-0x24]; push ecx
    a.emit(b"\x50")  # push eax (hwnd)
    a.call_iat(iat["GetClassNameA"])
    a.emit(b"\x85\xC0")
    a.jcc_label(0x84, "MRB_done")
    a.emit(b"\x68")
    a.abs32_va(info["str_backdrop_va"])
    a.emit(b"\x8D\x4D\xDC\x51")
    a.call_label("StrEq")
    a.emit(b"\x85\xC0")
    a.jcc_label(0x84, "MRB_done")
    a.emit(b"\xFF\x36")  # push dword ptr [esi]
    a.call_iat(iat["GetTopWindow"])
    a.emit(b"\x85\xC0")
    a.jcc_label(0x84, "MRB_done")
    a.emit(b"\x89\x06")  # mov [esi], eax (lpMsg->hwnd = stage child)
    a.label("MRB_done")
    a.emit(b"\x5E\x8B\xE5\x5D\xC2\x04\x00")  # pop esi; mov esp, ebp; pop ebp; ret 4

    # =========================================================================
    # Hook_PeekMessageA(lpMsg, hWnd, wMin, wMax, wRemove) [stdcall ret 20]
    # =========================================================================
    a.label("Hook_PeekMessageA")
    a.emit(b"\x55\x8B\xEC\x83\xEC\x08")  # push ebp; mov ebp, esp; sub esp, 8 (cx, cy)
    a.emit(b"\x56")  # push esi
    a.call_label("EnsurePatched")
    a.emit(b"\xFF\x75\x18\xFF\x75\x14\xFF\x75\x10\xFF\x75\x0C\xFF\x75\x08")
    a.call_iat(iat["PeekMessageA"])
    a.emit(b"\x85\xC0")
    a.jcc_label(0x84, "PM_ret")
    a.emit(b"\x8B\x75\x08\x85\xF6")  # mov esi, [ebp+8]; test esi, esi
    a.jcc_label(0x84, "PM_ret")
    a.emit(b"\x50")  # push eax (save PeekMessageA BOOL return)

    # Check if 0x0200 <= lpMsg->message <= 0x0209 BEFORE mapping lpMsg->pt:
    # record last stage coords from lpMsg->lParam and update g_lbutton_hold_va!
    a.emit(b"\x8B\x46\x04")  # mov eax, [esi+4] (lpMsg->message)
    a.emit(b"\x3D\x00\x02\x00\x00")  # cmp eax, 0x200
    a.jcc_label(0x8C, "PM_map_pt")  # jl
    a.emit(b"\x3D\x09\x02\x00\x00")  # cmp eax, 0x209
    a.jcc_label(0x8F, "PM_map_pt")  # jg

    # Record g_last_gx = sx(LOWORD(lParam)), g_last_gy = sx(HIWORD(lParam)), g_has_last = 1
    a.emit(b"\x8B\x4E\x0C")  # mov ecx, [esi+0xc] (lParam)
    a.emit(b"\x0F\xBF\xD1")  # movsx edx, cx
    a.emit(b"\x89\x15")
    a.abs32_va(g_last_gx_va)
    a.emit(b"\xC1\xF9\x10")  # sar ecx, 16
    a.emit(b"\x89\x0D")
    a.abs32_va(g_last_gy_va)
    a.emit(b"\xC7\x05")
    a.abs32_va(g_has_last_va)
    a.emit(struct.pack("<I", 1))

    # Update g_lbutton_hold_va for WM_LBUTTONDOWN / WM_LBUTTONUP
    a.emit(b"\x3D\x01\x02\x00\x00")  # cmp eax, 0x201 (WM_LBUTTONDOWN)
    a.jcc_label(0x85, "PM_chk_lbtnup")  # jne
    a.emit(b"\xC7\x05")  # mov dword ptr [g_lbutton_hold_va], 2
    a.abs32_va(g_lbutton_hold_va)
    a.emit(struct.pack("<I", 2))
    a.jmp_label("PM_redirect")

    a.label("PM_chk_lbtnup")
    a.emit(b"\x3D\x02\x02\x00\x00")  # cmp eax, 0x202 (WM_LBUTTONUP)
    a.jcc_label(0x85, "PM_redirect")  # jne
    a.emit(b"\xF7\x45\x18\x01\x00\x00\x00")  # test dword ptr [ebp+0x18], 1 (PM_REMOVE)
    a.jcc_label(0x84, "PM_redirect")  # jz (leave hold intact on PM_NOREMOVE peek)
    a.emit(b"\xC7\x05")  # mov dword ptr [g_lbutton_hold_va], 0
    a.abs32_va(g_lbutton_hold_va)
    a.emit(struct.pack("<I", 0))

    a.label("PM_redirect")
    # If lpMsg->hwnd is ImlWinBackdropClass, redirect to GetTopWindow(hwnd)
    a.emit(b"\x56")  # push esi
    a.call_label("MaybeRedirectBackdrop")

    a.label("PM_map_pt")
    # Map lpMsg->pt: if pt == (0,0) and g_has_last != 0 (locked desktop), use FillLastStageScreenPos
    a.emit(b"\x8B\x46\x14\x0B\x46\x18")  # mov eax, [esi+0x14]; or eax, [esi+0x18]
    a.jcc_label(0x85, "PM_map_real_pt")  # jnz
    a.emit(b"\xA1")
    a.abs32_va(g_has_last_va)
    a.emit(b"\x85\xC0")
    a.jcc_label(0x84, "PM_map_real_pt")
    a.emit(b"\x8D\x46\x18\x50")
    a.emit(b"\x8D\x46\x14\x50")
    a.call_label("FillLastStageScreenPos")
    a.jmp_label("PM_popret")

    a.label("PM_map_real_pt")
    a.emit(b"\x6A\x00")  # push 0 (screen mode)
    a.emit(b"\x8D\x46\x18\x50")  # lea eax, [esi+0x18]; push eax
    a.emit(b"\x8D\x46\x14\x50")  # lea eax, [esi+0x14]; push eax
    a.call_label("MapScreenToStage")

    a.label("PM_popret")
    a.emit(b"\x58")  # pop eax
    a.label("PM_ret")
    a.emit(b"\x5E\x8B\xE5\x5D\xC2\x14\x00")  # pop esi; mov esp,ebp; pop ebp; ret 20

    # =========================================================================
    # Hook_DispatchMessageA(const MSG* lpMsg) [stdcall ret 4]
    # =========================================================================
    a.label("Hook_DispatchMessageA")
    a.emit(b"\x55\x8B\xEC")  # push ebp; mov ebp, esp
    a.call_label("EnsurePatched")
    a.emit(b"\x8B\x4D\x08\x85\xC9")  # mov ecx, [ebp+8]; test ecx, ecx
    a.jcc_label(0x84, "DM_call")
    a.emit(b"\x8B\x41\x04")  # mov eax, [ecx+4] (message)
    a.emit(b"\x3D\x00\x02\x00\x00")  # cmp eax, 0x200
    a.jcc_label(0x8C, "DM_call")
    a.emit(b"\x3D\x09\x02\x00\x00")  # cmp eax, 0x209
    a.jcc_label(0x8F, "DM_call")
    a.emit(b"\x51")  # push ecx
    a.call_label("MaybeRedirectBackdrop")
    a.label("DM_call")
    a.emit(b"\xFF\x75\x08")  # push [ebp+8]
    a.call_iat(iat["DispatchMessageA"])
    a.emit(b"\x5D\xC2\x04\x00")  # pop ebp; ret 4

    # =========================================================================
    # DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) [stdcall ret 12]
    # =========================================================================
    a.label("DllMain")
    a.emit(b"\x55\x8B\xEC")
    a.emit(b"\x83\x7D\x0C\x01")  # cmp dword ptr [ebp+0xc], 1 (DLL_PROCESS_ATTACH)
    a.jcc_label(0x85, "DM_ok")
    a.emit(b"\xFF\x75\x08")  # push [ebp+8] (hinst)
    a.call_iat(iat["DisableThreadLibraryCalls"])
    a.call_label("EnsurePatched")
    a.label("DM_ok")
    a.emit(b"\x6A\x01\x58")  # push 1; pop eax
    a.emit(b"\x5D\xC2\x0C\x00")  # pop ebp; ret 12

    text_bytes = a.finalize()
    entry_rva = 0x1000 + a.labels["DllMain"]
    return text_bytes, entry_rva, a.relocs


def build_reloc(reloc_rvas):
    """Build PE .reloc section grouped into 4KB page blocks."""
    pages = {}
    for rva in sorted(set(reloc_rvas)):
        page = rva & ~0xFFF
        pages.setdefault(page, []).append(rva & 0xFFF)
    out = bytearray()
    for page, offs in sorted(pages.items()):
        entries = [(3 << 12) | o for o in offs]  # IMAGE_REL_BASED_HIGHLOW
        if len(entries) % 2:
            entries.append(0)  # IMAGE_REL_BASED_ABSOLUTE padding
        block_size = 8 + 2 * len(entries)
        out.extend(struct.pack("<II", page, block_size))
        for e in entries:
            out.extend(struct.pack("<H", e))
    return bytes(out)


def build_winmm_proxy(out_dll, src_winmm=DEFAULT_WINMM):
    exp_symbols, exp_base = read_pe32_exports(src_winmm)

    rdata_rva = 0x2000
    rdata_bytes, info = build_rdata(exp_symbols, exp_base, rdata_rva)
    rdata_vsize = len(rdata_bytes)
    rdata_rsize = align_up(rdata_vsize, FILE_ALIGN)

    data_rva = align_up(rdata_rva + rdata_vsize, SECT_ALIGN)
    data_bytes = b"\x00" * 64
    data_vsize = len(data_bytes)
    data_rsize = align_up(data_vsize, FILE_ALIGN)

    text_bytes, entry_rva, relocs = build_text(info, IMAGE_BASE + data_rva)
    text_vsize = len(text_bytes)
    text_rsize = align_up(text_vsize, FILE_ALIGN)
    assert text_vsize <= 0x1000, f".text too large: {text_vsize}"

    reloc_rva = align_up(data_rva + data_vsize, SECT_ALIGN)
    reloc_bytes = build_reloc(relocs)
    reloc_vsize = len(reloc_bytes)
    reloc_rsize = align_up(reloc_vsize, FILE_ALIGN)

    size_of_headers = 0x400
    text_raw = size_of_headers
    rdata_raw = text_raw + text_rsize
    data_raw = rdata_raw + rdata_rsize
    reloc_raw = data_raw + data_rsize
    size_of_image = align_up(reloc_rva + reloc_vsize, SECT_ALIGN)

    # Assemble DOS Header + Stub + PE Header + 4 Section Headers
    img = bytearray(reloc_raw + reloc_rsize)

    # DOS Header
    struct.pack_into("<H", img, 0, 0x5A4D)  # 'MZ'
    struct.pack_into("<I", img, 0x3C, 0x80)  # e_lfanew = 0x80

    # NT Signature
    struct.pack_into("<I", img, 0x80, 0x00004550)  # 'PE\0\0'
    # FileHeader (Machine=0x14c, NumSections=4, SizeOfOptionalHeader=0xE0, Characteristics=0x2102)
    struct.pack_into("<HHIIIHH", img, 0x84, 0x014C, 4, 0, 0, 0, 0xE0, 0x2102)

    # OptionalHeader32
    opt = 0x98
    struct.pack_into("<HBBIIIIII", img, opt, 0x010B, 14, 0, text_rsize, rdata_rsize + data_rsize, 0, entry_rva, 0x1000, rdata_rva)
    struct.pack_into("<IIIHHHHHHIIIIHHIIIIII", img, opt + 28,
        IMAGE_BASE, SECT_ALIGN, FILE_ALIGN,
        6, 0, 0, 0, 6, 0, 0,
        size_of_image, size_of_headers, 0, 2, 0x0140,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16)

    # DataDirectories (16 entries @ opt + 96)
    dd = opt + 96
    struct.pack_into("<II", img, dd + 0 * 8, info["exp_dir_rva"], info["exp_dir_size"])   # EXPORT
    struct.pack_into("<II", img, dd + 1 * 8, info["imp_dir_rva"], info["imp_dir_size"])   # IMPORT
    struct.pack_into("<II", img, dd + 5 * 8, reloc_rva, reloc_vsize)                      # BASERELOC
    struct.pack_into("<II", img, dd + 12 * 8, info["iat_rva"], info["iat_size"])          # IAT

    # Section Headers (4 * 40 bytes @ opt + 0xE0 = 0x178)
    secs = [
        (b".text\x00\x00\x00", text_vsize, 0x1000, text_rsize, text_raw, 0x60000020),
        (b".rdata\x00\x00", rdata_vsize, rdata_rva, rdata_rsize, rdata_raw, 0x40000040),
        (b".data\x00\x00\x00", data_vsize, data_rva, data_rsize, data_raw, 0xC0000040),
        (b".reloc\x00\x00", reloc_vsize, reloc_rva, reloc_rsize, reloc_raw, 0x42000040),
    ]
    sh = opt + 0xE0
    for i, (nm, vs, va, rs, ra, ch) in enumerate(secs):
        struct.pack_into("<8sIIIIIIHHI", img, sh + i * 40, nm, vs, va, rs, ra, 0, 0, 0, 0, ch)

    img[text_raw:text_raw + text_vsize] = text_bytes
    img[rdata_raw:rdata_raw + rdata_vsize] = rdata_bytes
    img[data_raw:data_raw + data_vsize] = data_bytes
    img[reloc_raw:reloc_raw + reloc_vsize] = reloc_bytes

    with open(out_dll, "wb") as f:
        f.write(img)
    return len(img), len(exp_symbols), entry_rva


def main():
    out_dll = sys.argv[1] if len(sys.argv) > 1 else "WINMM.dll"
    src_winmm = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_WINMM
    size, num_exp, entry_rva = build_winmm_proxy(out_dll, src_winmm)
    print(f"Built {out_dll} ({size} bytes, {num_exp} forwarded exports, EntryPoint=0x{entry_rva:X})")


if __name__ == "__main__":
    main()
