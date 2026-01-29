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
            raise ValueError(f"Charset desconocido: {name}")
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
        raise ValueError(f"Máximo sin repeticiones: {max_length} bytes. Pediste {length}.")

    pattern_parts = []
    for combo in product(*sets):
        token = ''.join(combo)
        pattern_parts.append(token)
        if len(pattern_parts) * token_length >= length:
            return ''.join(pattern_parts)[:length]
    return ''.join(pattern_parts)[:length]


def find_offset(substring, max_length, charsets):
    """
    Busca la posición de substring en un patrón generado con los mismos charsets y longitud max_length.
    """
    pattern = create_pattern(max_length, charsets)
    try:
        return pattern.index(substring)
    except ValueError:
        return None


def parse_offset_input(p):
    """
    Convierte una entrada hexadecimal a raw bytes o devuelve la cadena tal cual.
    """
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
        description="OSED off/patt tool con charsets flexibles y símbolos seguros"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--create", type=int, metavar='LENGTH',
        help="Generar patrón de longitud LENGTH"
    )
    group.add_argument(
        "--offset", type=str, metavar='SUBSTR',
        help="Buscar offset de SUBSTR en el patrón"
    )
    parser.add_argument(
        "--charsets", nargs='+', metavar='SET',
        choices=list(CHARSET_MAP.keys()),
        default=['upper', 'lower', 'digit', 'upper'],
        help=(
            "Lista de clases a usar: upper, lower, digit, symbol. "
            "El orden define el orden del token."
        )
    )
    parser.add_argument(
        "--max", type=int, metavar='MAXLEN', default=703040,
        help="Longitud máxima para buscar offset (solo con --offset)"
    )
    parser.add_argument(
        "--raw", action="store_true",
        help="Salida binaria (solo con --create)"
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
            print("[-] Error al parsear la entrada de offset")
            sys.exit(1)
        offset = find_offset(substr, args.max, args.charsets)
        if offset is not None:
            print(f"[!] Offset: {offset}")
        else:
            print("[-] No encontrado")

if __name__ == "__main__":
    main()
