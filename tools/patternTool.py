#!/usr/bin/env python3

import argparse
import sys
from struct import pack
from itertools import product

# Map names to actual character sets
CHARSET_MAP = {
    'upper': "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    'lower': "abcdefghijklmnopqrstuvwxyz",
    'digit': "0123456789",
    'symbol': "!$%&()*+,-./:;<=>?@[\]^_`{|}~"
}

# Generates a pattern of the specified length using the character classes in the given order.
# Single Charset: If only one charset is specified, it repeats its characters until it reaches the length.
# Multiple Charsets: If multiple charsets are provided, it creates tokens via Cartesian product, concatenating one character from each charset.

def create_pattern(length, charsets):
    # validate charsets
    sets = []
    for name in charsets:
        if name not in CHARSET_MAP:
            raise ValueError(f"Charset unknown: {name}")
        sets.append(CHARSET_MAP[name])

    # if only 1 repeat
    if len(sets) == 1:
        charset = sets[0]
        return (charset * ((length // len(charset)) + 1))[:length]

    # if multiple, cartesian product
    token_length = len(sets)
    max_comb = 1
    for s in sets:
        max_comb *= len(s)
    max_length = max_comb * token_length
    if length > max_length:
        raise ValueError(f"Max without reps: {max_length} bytes. Asked {length}.")

    pattern_parts = []
    for combo in product(*sets):
        token = ''.join(combo)
        pattern_parts.append(token)
        if len(pattern_parts) * token_length >= length:
            return ''.join(pattern_parts)[:length]
    return ''.join(pattern_parts)[:length]


def find_offset(substring, max_length, charsets):
    pattern = create_pattern(max_length, charsets)
    try:
        return pattern.index(substring)
    except ValueError:
        return None


def parse_offset_input(p):
    try:
        if p.startswith("0x") and len(p) == 10:
            value = int(p, 16)
            return pack("<I", value).decode("latin-1")
        else:
            return p
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(
        description="OSED off/patt tool with flexible charsets"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--create", type=int, metavar='LENGTH',
        help="Generate pattern with LENGTH"
    )
    group.add_argument(
        "--offset", type=str, metavar='SUBSTR',
        help="Search offset of substring"
    )
    parser.add_argument(
        "--charsets", nargs='+', metavar='SET',
        choices=list(CHARSET_MAP.keys()),
        default=['upper', 'lower', 'digit', 'upper'],
        help=(
            "List of charsets to use: upper, lower, digit, symbol. "
            "The order defines token gen."
        )
    )
    parser.add_argument(
        "--max", type=int, metavar='MAXLEN', default=703040,
        help="Max length (only with --offset)"
    )
    parser.add_argument(
        "--raw", action="store_true",
        help="Binary output (only with --create)"
    )

    args = parser.parse_args()

    if args.create is not None:
        pattern = create_pattern(args.create, args.charsets)
        if args.raw:
            sys.stdout.buffer.write(pattern.encode('latin-1'))
        else:
            print(pattern)

    elif args.offset:
        substr = parse_offset_input(args.offset)
        if substr is None:
            print("[-] Error parsing offset! None!")
            sys.exit(1)
        offset = find_offset(substr, args.max, args.charsets)
        if offset is not None:
            print(f"[!] Offset: {offset}")
        else:
            print("[-] Not found")

if __name__ == "__main__":
    main()
