# Generates samples/disasm/reference.json from independent tools: capstone 5 (disassembly),
# pyelftools (ELF), pefile (PE) and macholib (Mach-O). Test time only; the tests read the JSON.
# Usage (from samples/disasm): python3 src/make-reference.py
import json, struct
from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM64, CS_ARCH_ARM, CS_MODE_64, CS_MODE_32, CS_MODE_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile
import pefile
from macholib.MachO import MachO

FUNCS = ["main", "check_password", "classify", "sum_to", "fib", "deep1", "deep2", "deep3"]
STRINGS = ["access granted", "access denied", "revlens-secret-key", "hello from revlens %d\n"]

def cs_for(arch, thumb=False):
    if arch == "x86_64": return Cs(CS_ARCH_X86, CS_MODE_64)
    if arch == "x86": return Cs(CS_ARCH_X86, CS_MODE_32)
    if arch == "arm64": return Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    return Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)

def disasm(arch, code, addr, n, thumb=False):
    out = []
    for i in cs_for(arch, thumb).disasm(code, addr):
        out.append({"addr": i.address, "mnemonic": i.mnemonic, "op_str": i.op_str, "size": i.size})
        if len(out) >= n: break
    return out

def calls_in(arch, insns):
    res = []
    for i in insns:
        m = i["mnemonic"]
        if m in ("call", "bl", "blx") and (i["op_str"].startswith("0x") or i["op_str"].startswith("#0x")):
            res.append({"at": i["addr"], "target": int(i["op_str"].lstrip("#"), 16)})
    return res

def find_bytes(data, needle):
    return data.find(needle)

def elf_ref(path):
    e = ELFFile(open(path, "rb"))
    arch = {"EM_X86_64": "x86_64", "EM_386": "x86", "EM_AARCH64": "arm64", "EM_ARM": "arm"}[e["e_machine"]]
    syms = {}
    st = e.get_section_by_name(".symtab")
    if st:
        for s in st.iter_symbols():
            if s["st_info"]["type"] == "STT_FUNC" and s["st_value"] and s.name in FUNCS + ["_start"]:
                syms[s.name] = {"addr": s["st_value"] & ~1, "size": s["st_size"], "thumb": bool(s["st_value"] & 1) and arch == "arm"}
    imports = []
    for sec in e.iter_sections():
        if sec.name in (".rela.plt", ".rel.plt"):
            dyn = e.get_section(sec["sh_link"])
            for r in sec.iter_relocations():
                imports.append({"name": dyn.get_symbol(r["r_info_sym"]).name, "slot": r["r_offset"]})
    def read_va(va, n):
        for seg in e.iter_segments():
            if seg["p_type"] == "PT_LOAD" and seg["p_vaddr"] <= va < seg["p_vaddr"] + seg["p_filesz"]:
                off = seg["p_offset"] + va - seg["p_vaddr"]
                e.stream.seek(off); return e.stream.read(n)
        return b""
    strings = {}
    for seg in e.iter_segments():
        if seg["p_type"] != "PT_LOAD": continue
        data = seg.data()
        for s in STRINGS:
            k = data.find(s.encode() + b"\0")
            if k >= 0 and s not in strings: strings[s] = seg["p_vaddr"] + k
    funcs = {}
    for name, info in syms.items():
        code = read_va(info["addr"], info["size"] or 256)
        ins = disasm(arch, code, info["addr"], 400, info["thumb"])
        funcs[name] = {**info, "first": ins[:16], "count": len(ins), "calls": calls_in(arch, ins)}
    return {"format": "elf", "arch": arch, "entry": e["e_entry"] & ~1 if arch == "arm" else e["e_entry"], "functions": funcs, "imports": imports, "strings": strings}

def pe_ref(path):
    pe = pefile.PE(path)
    base = pe.OPTIONAL_HEADER.ImageBase
    arch = {0x8664: "x86_64", 0x14c: "x86", 0xaa64: "arm64"}[pe.FILE_HEADER.Machine]
    imports = []
    for d in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in d.imports:
            imports.append({"library": d.dll.decode(), "name": imp.name.decode() if imp.name else None, "slot": imp.address})
    text = [s for s in pe.sections if s.Characteristics & 0x20000000][0]
    tva = base + text.VirtualAddress
    code = text.get_data()
    strings = {}
    for s in pe.sections:
        k = s.get_data().find(b"access granted\0")
        if k >= 0: strings["access granted"] = base + s.VirtualAddress + k
    # linear sweep for rip relative lea to "access granted" and calls through the IAT
    md = cs_for(arch)
    refs = []
    target = strings.get("access granted")
    pos = 0
    md.skipdata = True
    for i in md.disasm(code, tva):
        if "rip +" in i.op_str and i.mnemonic == "lea":
            disp = int(i.op_str.split("rip + ")[1].rstrip("]"), 16)
            if i.address + i.size + disp == target: refs.append(i.address)
    pdata = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXCEPTION"):
        for rf in pe.DIRECTORY_ENTRY_EXCEPTION[:50]:
            pdata.append(base + rf.struct.BeginAddress)
    entry = base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    return {"format": "pe", "arch": arch, "entry": entry, "imports": imports, "strings": strings, "access_granted_refs": refs, "pdata_first": pdata,
            "entry_first": disasm(arch, pe.get_data(pe.OPTIONAL_HEADER.AddressOfEntryPoint, 64), entry, 8)}

def macho_ref(path, want_arch=None):
    m = MachO(path)
    out = None
    for h in m.headers:
        cpu = h.header.cputype
        arch = {7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000c: "arm64"}[cpu]
        if want_arch and arch != want_arch: continue
        f = open(path, "rb"); base_off = h.offset
        text_vm = None; entryoff = None; syms = {}; secs = []
        symtab = None
        for lc, cmd, data in h.commands:
            n = lc.cmd
            if n in (0x19, 0x1):
                if cmd.segname.rstrip(b"\0") == b"__TEXT": text_vm = (cmd.vmaddr, cmd.fileoff)
                for s in data:
                    secs.append((s.sectname.rstrip(b"\0").decode(), s.addr, s.size, s.offset))
            if n == 0x80000028: entryoff = cmd.entryoff
            if n == 0x2: symtab = cmd
        is64 = cpu & 0x01000000
        if symtab:
            f.seek(base_off + symtab.stroff); strtab = f.read(symtab.strsize)
            ent = 16 if is64 else 12
            f.seek(base_off + symtab.symoff); raw = f.read(symtab.nsyms * ent)
            for k in range(symtab.nsyms):
                strx, typ, sect, desc = struct.unpack_from("<IBBH", raw, k * ent)
                val = struct.unpack_from("<Q" if is64 else "<I", raw, k * ent + 8)[0]
                name = strtab[strx:strtab.index(b"\0", strx)].decode()
                if (typ & 0x0e) == 0x0e and not (typ & 0xe0) and name.lstrip("_") in FUNCS: syms[name.lstrip("_")] = val
        def read_va(va, n):
            for name, addr, size, off in secs:
                if addr <= va < addr + size:
                    f.seek(base_off + off + va - addr); return f.read(n)
            return b""
        strings = {}
        for name, addr, size, off in secs:
            if name == "__cstring":
                f.seek(base_off + off); data = f.read(size)
                for s in STRINGS:
                    k = data.find(s.encode() + b"\0")
                    if k >= 0: strings[s] = addr + k
        funcs = {}
        for name, addr in syms.items():
            ins = disasm(arch, read_va(addr, 256), addr, 64)
            funcs[name] = {"addr": addr, "first": ins[:16], "calls": calls_in(arch, ins)}
        stubs = [(a, s) for (n, a, s, o) in secs if n == "__stubs"]
        out = {"format": "macho", "arch": arch, "entry": text_vm[0] + entryoff if entryoff is not None else None, "functions": funcs, "strings": strings, "stubs": stubs, "slice_offset": base_off}
    return out

ref = {}
for name in ["hello-x64.elf", "hello-x64-stripped.elf", "hello-arm64.elf", "hello-x86.elf", "hello-arm32.elf", "hello-thumb-static.elf"]:
    ref[name] = elf_ref(name)
ref["hello-x64.exe"] = pe_ref("hello-x64.exe")
ref["hello-x64.macho"] = macho_ref("hello-x64.macho")
ref["hello-arm64.macho"] = macho_ref("hello-arm64.macho")
ref["hello-fat.macho"] = {"x86_64": macho_ref("hello-fat.macho", "x86_64"), "arm64": macho_ref("hello-fat.macho", "arm64")}
json.dump(ref, open("reference.json", "w"), indent=1, sort_keys=True)
print("wrote reference.json")
