"""
-------------------------------------------------------

This script searches for "deserts" (runs of 0x00 or 0xCC bytes) within the memory of a specified module or range. 
Results are classified into columns:Executable with Read (RX)Writable without Execution (RW)Read/Write/Executable (RWX)
Step-by-step workflow:
Input: Module or address range.
Range Acquisition: Retrieve range via lm m or direct parameters.
Iteration: Scan in chunks using db.Identification: Locate runs of 0x00 / 0xCC where size $\ge$ min_size.Protection 
Query: Check memory protection using !vprot.
Classification: Sort based on protection flags.
Final Report: Display results in separate columns.

Use:
> .load pykd
> !py desert_finder.py SNFS
"""

import sys, struct, pykd

PROTECTION_FLAGS = {
    0x01: "PAGE_NOACCESS",
    0x02: "PAGE_READONLY",
    0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY",
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE",
    0x80: "PAGE_EXECUTE_WRITECOPY",
    0x100: "PAGE_GUARD",
    0x200: "PAGE_NOCACHE",
    0x400: "PAGE_WRITECOMBINE",
}

FILLER = (0x00, 0xCC)


def run(cmd: str) -> str:
    try:
        return pykd.dbgCommand(cmd)
    except Exception as e:
        return f"[!] Error executing {cmd}: {e}"


def get_module_range(module_name: str):
    out = run(f"lm m {module_name}")
    for line in out.splitlines():
        if module_name.lower() in line.lower():
            parts = line.split()
            return int(parts[0], 16), int(parts[1], 16)
    return None, None


def get_protection(addr: int):
    out = run(f"!vprot {addr:#x}")
    for line in out.splitlines():
        if line.strip().startswith("Protect:"):
            try:
                prot_hex = int(line.split()[1], 16)
                return PROTECTION_FLAGS.get(prot_hex, "UNKNOWN"), prot_hex
            except:
                pass
    return "UNKNOWN", 0


def get_text_section(base: int):
    e_lfanew = struct.unpack("<I", bytes(pykd.loadBytes(base+0x3c, 4)))[0]
    nt_hdr = base + e_lfanew
    num_sec = struct.unpack("<H", bytes(pykd.loadBytes(nt_hdr+6, 2)))[0]
    opt_size = struct.unpack("<H", bytes(pykd.loadBytes(nt_hdr+20, 2)))[0]
    first_sec = nt_hdr + 24 + opt_size

    for i in range(num_sec):
        sec = first_sec + i*40
        name = bytes(pykd.loadBytes(sec, 8)).split(b"\x00")[0].decode(errors="ignore")
        vsize = struct.unpack("<I", bytes(pykd.loadBytes(sec+8, 4)))[0]
        vaddr = struct.unpack("<I", bytes(pykd.loadBytes(sec+12, 4)))[0]
        if name == ".text":
            return base+vaddr, base+vaddr+vsize
    return None, None


def scan_memory(start: int, end: int, min_size=0x20, text_range=None):
    deserts = []
    cur, length = None, 0

    for addr in range(start, end, 0x100):
        out = run(f"db {addr:#x} L100")
        for line in out.splitlines():
            parts = line.strip().split()
            if not parts:
                continue
            base = int(parts[0], 16)
            for i, val in enumerate(parts[1:]):
                try:
                    b = int(val, 16)
                except:
                    continue
                abs_addr = base + i
                if b in FILLER:
                    if cur is None:
                        cur, length = abs_addr, 1
                    else:
                        length += 1
                else:
                    if cur and length >= min_size:
                        prot_str, prot_hex = get_protection(cur)
                        deserts.append((cur, length, prot_str, prot_hex,
                                        text_range and text_range[0] <= cur < text_range[1]))
                    cur, length = None, 0

    if cur and length >= min_size:
        prot_str, prot_hex = get_protection(cur)
        deserts.append((cur, length, prot_str, prot_hex,
                        text_range and text_range[0] <= cur < text_range[1]))
    return deserts


def main():
    if len(sys.argv) < 2:
        print("Usage: desert_finder.py <module> OR <start end> [min_size]")
        sys.exit(0)

    min_size = int(sys.argv[-1], 0) if len(sys.argv) > 2 else 0x20
    deserts = []

    if len(sys.argv) == 2:
        mod = sys.argv[1]
        start, end = get_module_range(mod)
        if not start:
            print(f"[!] Module {mod} not found")
            return
        text_start, text_end = get_text_section(start)
        print(f"[INFO] Scanning module {mod} ({start:#x}-{end:#x}, .text {text_start:#x}-{text_end:#x})")
        deserts = scan_memory(start, end, min_size, (text_start, text_end))
    else:
        start = int(sys.argv[1], 0)
        end = int(sys.argv[2], 0)
        print(f"[INFO] Scanning range {start:#x}-{end:#x}")
        deserts = scan_memory(start, end, min_size)

    if not deserts:
        print("[INFO] No deserts found")
        return

    rx, rw, rwx = [], [], []
    for addr, size, prot_str, prot_hex, in_text in deserts:
        sec = ".text" if in_text else "N/A"
        entry = f"{addr:#010x}  size={size:#06x}  prot={prot_str}({prot_hex:#x})  sec={sec}"
        if prot_hex in (0x20, 0x80):  # EXEC+READ
            rx.append(entry)
        elif prot_hex in (0x04, 0x08):  # RW sin EXEC
            rw.append(entry)
        elif prot_hex == 0x40:  # EXEC+RW
            rwx.append(entry)

    print("\n[INFO] Deserts classification:\n")
    print("== Executable + Read ==")
    print("\n".join(rx) if rx else "  None")
    print("\n== Read/Write (no exec) ==")
    print("\n".join(rw) if rw else "  None")
    print("\n== RWX (Exec+Read+Write) ==")
    print("\n".join(rwx) if rwx else "  None")


if __name__ == "__main__":
    main()
