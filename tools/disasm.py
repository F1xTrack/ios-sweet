#!/usr/bin/env python3
"""Disassemble around a symbol in a Mach-O, or at an exact file offset.
Usage: disasm.py KERNEL FUNC_VA OFFSET
Disassembles FUNC_VA+OFFSET-16 .. FUNC_VA+OFFSET+32 from __TEXT.
A simpler approach: given the symbol VA of _sweet_adreno_bringup (0xfffffe0007931874)
and panic pc (+0x4b0 -> 0xfffffe0007931d24), extract the VA range and map to file.
We'll instead compute virtual->file via the loaded __TEXT vmaddr.
"""
import struct, sys
from capstone import *
from capstone.arm64 import *

def load_segments(path):
    data = open(path,'rb').read()
    magic, = struct.unpack_from('<I', data, 0)
    endian = '<' if magic == 0xfeedfacf else '>'
    _, cputype, _, _, ncmds, _, _ = struct.unpack_from(endian+'IiiIIII', data, 0)
    off = 32
    segs=[]
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from(endian+'II', data, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = data[off+8:off+24].rstrip(b'\0').decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(endian+'QQQQ', data, off+24)
            segs.append((segname, vmaddr, vmsize, fileoff, filesize))
        off += cmdsize
    return data, segs, endian

def main():
    path = sys.argv[1]
    func_va = int(sys.argv[2],16)
    target = int(sys.argv[3],16)  # absolute VA to disassemble around
    data, segs, endian = load_segments(path)
    # map target VA -> file offset via __TEXT
    fileoff=None
    for segname, vmaddr, vmsize, fo, fs in segs:
        if vmaddr <= target < vmaddr+vmsize:
            fileoff = fo + (target - vmaddr)
            baseva = vmaddr
            break
    if fileoff is None:
        print("target VA not in any segment"); return
    start = target - 32
    soff = fileoff - 32
    code = data[soff:soff+80]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    print(f"seg __TEXT base_va={baseva:#x}  target={target:#x}  fileoff={fileoff:#x}")
    for ins in md.disasm(code, start):
        mark = "  <<< PC" if ins.address == target else ""
        print(f"  0x{ins.address:x}:  {ins.mnemonic:12s} {ins.op_str}{mark}")

main()
