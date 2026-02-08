#!/usr/bin/env python3

import argparse

def generate_badchars(start=1, exclude=None):
    if exclude is None:
        exclude = []
    exclude_bytes = bytes([int(x, 16) for x in exclude])
    return bytes([b for b in range(start, 256) if b not in exclude_bytes])

def format_output(badchars, fmt):
    if fmt == "python":
        lines = [f'shellcode =  b""']
        chunk = ""
        for i, b in enumerate(badchars):
            chunk += f"\\x{b:02x}"
            if (i + 1) % 16 == 0:
                lines.append(f'shellcode += b"{chunk}"')
                chunk = ""
        if chunk:
            lines.append(f'shellcode += b"{chunk}"')
        return "\n".join(lines)

    elif fmt == "c":
        lines = ["unsigned char shellcode[] ="]
        line = '"'
        for i, b in enumerate(badchars):
            line += f"\\x{b:02x}"
            if (i + 1) % 16 == 0:
                lines.append(line + '"')
                line = '"'
        if line != '"':
            lines.append(line + '";')
        else:
            lines[-1] += ";"
        return "\n".join(lines)

    elif fmt == "raw":
        return ''.join(f"\\x{b:02x}" for b in badchars)

    else:
        return "[!] Unknown format."

def format_output_segmented(badchars, fmt, segment_size):
    segments = [badchars[i:i+segment_size] for i in range(0, len(badchars), segment_size)]
    output_blocks = []
    for idx, segment in enumerate(segments):
        comment = f"# Segment {idx + 1}"
        block = format_output(segment, fmt)
        output_blocks.append(f"{comment}\n{block}\n")
    return "\n".join(output_blocks)

def format_output_with_index(badchars):
    lines = []
    for i, b in enumerate(badchars):
        lines.append(f"{i:04d}: \\x{b:02x}")
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="Badchar generator for exploit payloads.")
    parser.add_argument('--exclude', nargs='*', default=[], help="Badchars to exclude (e.g., 00 0a 0d)")
    parser.add_argument('--format', choices=['python', 'c', 'raw'], default='python', help="Output format")
    parser.add_argument('--split', type=int, help="Divide output in segments of N bytes")
    parser.add_argument('--start-from', type=lambda x: int(x, 16), default=1, help="Start from this byte (hex), default is 0x01")
    parser.add_argument('--show-index', action='store_true', help="Show offsets and byte values for visual inspection")
    
    parser.add_argument('--lower', action='store_true', help="Filter only lowercase chars (0x61-0x7a)")
    parser.add_argument('--upper', action='store_true', help="Filter only uppercase chars (0x41-0x5a)")
    parser.add_argument('--numbers', action='store_true', help="Filter only number chars (0x30-0x39)")

    args = parser.parse_args()

    try:
        badchars = generate_badchars(start=args.start_from, exclude=args.exclude)
    except ValueError:
        print("[!] Error: make sure badchars are hex (e.g., 00 0a 20)")
        return

    if args.lower or args.upper or args.numbers:
        allowed = set()
        if args.lower:
            allowed.update(range(0x61, 0x7B))
        if args.upper:
            allowed.update(range(0x41, 0x5B))
        if args.numbers:
            allowed.update(range(0x30, 0x3A))
        
        badchars = bytes([b for b in badchars if b in allowed])

    if args.show_index:
        output = format_output_with_index(badchars)
    elif args.split:
        output = format_output_segmented(badchars, args.format, args.split)
    else:
        output = format_output(badchars, args.format)

    print(output)

if __name__ == "__main__":
    main()