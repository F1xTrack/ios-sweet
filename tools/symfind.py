#!/usr/bin/env python3
"""Find the nearest symbol to a given VA in a Mach-O binary (arm64, native endian).
Usage: symfind.py KERNEL VA...
Nearest symbol searched = max(n_value <= VA). Prints name at that address.
"""
import struct, sys

def parse(path):
    data = open(path, 'rb').read()
    # Mach-O 64 header
    magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags = struct.unpack_from('<IiiIIII', data, 0)
    if magic not in (0xfeedfacf, 0xcffaedfe):  # 64-bit (LE/BE)
        raise SystemExit(f"not a 64-bit Mach-O: magic 0x{magic:x}")
    endian = '<' if magic == 0xfeedfacf else '>'
    off = 32
    symoff = symsize = stroff = strsize = 0
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from(endian + 'II', data, off)
        if cmd == 0x2:  # LC_SYMTAB
            symoff, nsyms, stroff, strsize = struct.unpack_from(endian + 'IIII', data, off + 8)
        off += cmdsize
    if not symoff or not nsyms:
        raise SystemExit("no symbol table (kernel may be stripped)")
    # nlist_64: n_strx(4) n_type(1) n_sect(1) n_desc(2) n_value(8) = 16 bytes
    syms = []
    p = symoff
    for i in range(nsyms):
        n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from(endian + 'IBBHQ', data, p)
        p += 16
        syms.append((n_value, n_strx, n_type))
    strs = data[stroff:stroff+strsize]
    def name(n_strx):
        if n_strx == 0 or n_strx >= len(strs):
            return ''
        end = strs.find(b'\0', n_strx)
        return strs[n_strx:end].decode('utf-8', 'replace')
    return [(v, name(s)) for v, s, t in syms]

def main():
    path = sys.argv[1]
    addrs = [int(a, 16) if a.lower().startswith('0x') else int(a) for a in sys.argv[2:]]
    syms = parse(path)
    syms.sort()
    for va in addrs:
        # nearest symbol with n_value <= va (and > 0)
        best = None
        for v, n in syms:
            if v > 0 and v <= va:
                best = (v, n)
            elif v > va:
                break
        if best:
            print(f"0x{va:x} -> {best[0]:#x} {best[1]}  (+0x{va-best[0]:x})")
        else:
            print(f"0x{va:x} -> (no symbol)")

main()
