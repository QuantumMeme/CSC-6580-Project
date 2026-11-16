#!/usr/bin/env python3
"""CSC 6580 Project 4: basic blocks -> Structure Theorem primes.

Usage: python3 ./main.py <elf-file> [leader ...]
"""

import struct
import sys

from capstone import (Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64,
                      CS_GRP_JUMP, CS_GRP_RET, CS_GRP_IRET, CS_GRP_CALL)
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

SHF_EXECINSTR = 0x4
SHT_NOBITS = 8
SHT_RELA = 4
PT_LOAD = 1
PF_X = 0x1
R_X86_64_RELATIVE = 8


# --------------------------------------------------------------------------
# ELF parsing (minimal, no external library needed)
# --------------------------------------------------------------------------

class Elf:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        if d[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        self.is64 = d[4] == 2
        self.end = "<" if d[5] == 1 else ">"
        e = self.end
        if self.is64:
            (self.entry, phoff, shoff) = struct.unpack_from(e + "QQQ", d, 0x18)
            (phentsize, phnum, shentsize, shnum, shstrndx) = \
                struct.unpack_from(e + "HHHHH", d, 0x36)
        else:
            (self.entry, phoff, shoff) = struct.unpack_from(e + "III", d, 0x18)
            (phentsize, phnum, shentsize, shnum, shstrndx) = \
                struct.unpack_from(e + "HHHHH", d, 0x2A)

        # Program headers.
        self.segments = []
        for i in range(phnum):
            off = phoff + i * phentsize
            if self.is64:
                (p_type, p_flags, p_offset, p_vaddr, _, p_filesz, _, _) = \
                    struct.unpack_from(e + "IIQQQQQQ", d, off)
            else:
                (p_type, p_offset, p_vaddr, _, p_filesz, _, p_flags, _) = \
                    struct.unpack_from(e + "IIIIIIII", d, off)
            self.segments.append(dict(type=p_type, flags=p_flags,
                                      offset=p_offset, vaddr=p_vaddr,
                                      size=p_filesz))

        # Section headers.
        self.sections = []
        if shoff and shnum:
            raw = []
            for i in range(shnum):
                off = shoff + i * shentsize
                if self.is64:
                    (name, typ, flags, addr, offset, size, _, _, _, entsize) = \
                        struct.unpack_from(e + "IIQQQQIIQQ", d, off)
                else:
                    (name, typ, flags, addr, offset, size, _, _, _, entsize) = \
                        struct.unpack_from(e + "IIIIIIIIII", d, off)
                raw.append((name, typ, flags, addr, offset, size, entsize))
            strtab = raw[shstrndx] if shstrndx < len(raw) else None
            for (name, typ, flags, addr, offset, size, entsize) in raw:
                nm = ""
                if strtab:
                    s = strtab[4] + name
                    nm = d[s:d.index(b"\0", s)].decode(errors="replace")
                self.sections.append(dict(name=nm, type=typ, flags=flags,
                                          addr=addr, offset=offset,
                                          size=size, entsize=entsize))

        # Executable regions: executable sections if we have them,
        # otherwise executable loadable segments.
        self.code = []
        for s in self.sections:
            if (s["flags"] & SHF_EXECINSTR and s["type"] != SHT_NOBITS
                    and s["addr"] and s["size"]):
                self.code.append((s["addr"], s["addr"] + s["size"],
                                  s["offset"], s["name"]))
        if not self.code:
            for p in self.segments:
                if p["type"] == PT_LOAD and p["flags"] & PF_X and p["size"]:
                    self.code.append((p["vaddr"], p["vaddr"] + p["size"],
                                      p["offset"], "<segment>"))
        self.code.sort()

    def region(self, addr):
        """Executable region containing addr, or None."""
        for r in self.code:
            if r[0] <= addr < r[1]:
                return r
        return None

    def in_bounds(self, addr):
        return self.region(addr) is not None

    def code_bytes(self, addr):
        """Bytes from addr to the end of its executable region."""
        r = self.region(addr)
        if r is None:
            return b""
        start = r[2] + (addr - r[0])
        return self.data[start:r[2] + (r[1] - r[0])]

    def read_ptr(self, addr):
        """Read a pointer-sized value from any loaded address, else None."""
        size = 8 if self.is64 else 4
        fmt = self.end + ("Q" if self.is64 else "I")
        for p in self.segments:
            if p["type"] == PT_LOAD and p["vaddr"] <= addr and \
                    addr + size <= p["vaddr"] + p["size"]:
                return struct.unpack_from(fmt, self.data,
                                          p["offset"] + addr - p["vaddr"])[0]
        return None

    def relative_reloc(self, addr):
        """Addend of an R_X86_64_RELATIVE relocation at addr, else None."""
        if not self.is64:
            return None
        for s in self.sections:
            if s["type"] != SHT_RELA:
                continue
            ent = s["entsize"] or 24
            for off in range(s["offset"], s["offset"] + s["size"], ent):
                r_off, r_info, r_add = struct.unpack_from(
                    self.end + "QQq", self.data, off)
                if r_off == addr and (r_info & 0xffffffff) == R_X86_64_RELATIVE:
                    return r_add
        return None


# --------------------------------------------------------------------------
# Disassembly helpers
# --------------------------------------------------------------------------

class Disasm:
    def __init__(self, elf):
        self.elf = elf
        self.md = Cs(CS_ARCH_X86, CS_MODE_64 if elf.is64 else CS_MODE_32)
        self.md.detail = True
        self.cache = {}

    def at(self, addr):
        """Decode the single instruction at addr (or None)."""
        if addr in self.cache:
            return self.cache[addr]
        code = self.elf.code_bytes(addr)[:16]
        insn = next(self.md.disasm(code, addr, 1), None) if code else None
        self.cache[addr] = insn
        return insn


LOOPS = ("loop", "loope", "loopne", "loopz", "loopnz")


def is_jump(insn):
    return (insn.group(CS_GRP_JUMP) or insn.mnemonic.startswith("j")
            or insn.mnemonic in LOOPS)


def is_terminator(insn):
    return (is_jump(insn) or insn.group(CS_GRP_RET)
            or insn.group(CS_GRP_IRET)
            or insn.mnemonic in ("hlt", "ud2", "ljmp"))


def is_conditional(insn):
    return is_jump(insn) and insn.mnemonic not in ("jmp", "ljmp")


def direct_target(insn):
    """Immediate target of a jump/call, or None if indirect."""
    if insn.operands and insn.operands[0].type == X86_OP_IMM:
        return insn.operands[0].imm
    return None


# --------------------------------------------------------------------------
# Finding the start location
# --------------------------------------------------------------------------

def find_main(elf, dis, entry):
    """If entry is a standard _start that calls __libc_start_main
    (call followed by hlt), return the address passed as main."""
    insns = []
    addr = entry
    for _ in range(64):
        insn = dis.at(addr)
        if insn is None:
            return None
        insns.append(insn)
        if is_terminator(insn):
            break
        addr += insn.size
    if len(insns) < 2 or insns[-1].mnemonic != "hlt" or \
            not insns[-2].group(CS_GRP_CALL):
        return None

    before = insns[:-2]
    if elf.is64:
        # Last write to rdi/edi before the call.
        for insn in reversed(before):
            ops = insn.operands
            if len(ops) != 2 or ops[0].type != X86_OP_REG:
                continue
            if insn.reg_name(ops[0].reg) not in ("rdi", "edi"):
                continue
            src = ops[1]
            nxt = insn.address + insn.size
            if src.type == X86_OP_IMM and insn.mnemonic == "mov":
                return src.imm & 0xffffffffffffffff
            if src.type == X86_OP_MEM and src.mem.base == X86_REG_RIP:
                ea = nxt + src.mem.disp
                if insn.mnemonic == "lea":
                    return ea
                if insn.mnemonic == "mov":
                    # Pointer to main stored in the GOT.
                    val = elf.relative_reloc(ea)
                    if val is None:
                        val = elf.read_ptr(ea)
                    return val or None
            return None
    else:
        # i386: main is the last immediate pushed before the call.
        for insn in reversed(before):
            if insn.mnemonic == "push" and insn.operands and \
                    insn.operands[0].type == X86_OP_IMM:
                return insn.operands[0].imm & 0xffffffff
    return None


# --------------------------------------------------------------------------
# Basic block extraction
# --------------------------------------------------------------------------

def sweep(dis, elf, leader):
    """Linear sweep from leader to the first terminator.
    Returns (instructions, successor addresses that become leaders)."""
    insns, succ = [], []
    addr = leader
    while True:
        insn = dis.at(addr)
        if insn is None:
            break
        insns.append(insn)
        nxt = addr + insn.size
        if insn.group(CS_GRP_CALL):
            t = direct_target(insn)
            if t is not None:
                succ.append(t)
        if is_terminator(insn):
            if is_jump(insn):
                t = direct_target(insn)
                if t is not None:
                    succ.append(t)
                if is_conditional(insn):
                    succ.append(nxt)
            return insns, succ
        if not elf.in_bounds(nxt):
            break
        addr = nxt
    # Ran off the code (or hit undecodable bytes).
    if insns:
        succ.append(insns[-1].address + insns[-1].size)
    return insns, succ


def find_leaders(dis, elf, initial):
    leaders = set()
    work = [a for a in initial if elf.in_bounds(a)]
    while work:
        a = work.pop()
        if a in leaders or not elf.in_bounds(a):
            continue
        leaders.add(a)
        _, succ = sweep(dis, elf, a)
        work.extend(s for s in succ if elf.in_bounds(s) and s not in leaders)
    return leaders


def build_blocks(dis, elf, leaders):
    """Return {leader: (insns, kind, targets)} where kind is 'seq' or 'if'.
    For 'seq', targets = (next,). For 'if', targets = (taken, fallthrough).
    Unknown / out-of-bounds targets are 0."""
    def known(a):
        return a if (a is not None and a in leaders) else 0

    blocks = {}
    for lead in leaders:
        insns = []
        addr = lead
        result = None
        while True:
            insn = dis.at(addr)
            if insn is None:
                result = ("seq", (0,))
                break
            insns.append(insn)
            nxt = addr + insn.size
            if is_terminator(insn):
                if is_conditional(insn):
                    result = ("if", (known(direct_target(insn)), known(nxt)))
                elif is_jump(insn):
                    result = ("seq", (known(direct_target(insn)),))
                else:                       # ret, hlt, iret, ud2
                    result = ("seq", (0,))
                break
            if nxt in leaders:
                result = ("seq", (nxt,))
                break
            if not elf.in_bounds(nxt):
                result = ("seq", (0,))
                break
            addr = nxt
        blocks[lead] = (insns,) + result
    return blocks


# --------------------------------------------------------------------------
# Primes and the Structure Theorem
# --------------------------------------------------------------------------
# A prime is a list: ["seq", addr, insns, next] or
#                    ["if",  addr, insns, then, else]
# where each of next/then/else is either an int (L := value) or a prime.

def make_primes(blocks):
    primes = {}
    for addr, (insns, kind, targets) in blocks.items():
        primes[addr] = [kind, addr, insns] + list(targets)
    return primes


def slots(prime):
    """Indices of the L slots of a prime."""
    return (3,) if prime[0] == "seq" else (3, 4)


def count_refs(prime, counts):
    for i in slots(prime):
        v = prime[i]
        if isinstance(v, int):
            counts[v] = counts.get(v, 0) + 1
        else:
            count_refs(v, counts)


def find_ref(prime, target):
    """Return (container, index) of the slot holding L := target."""
    for i in slots(prime):
        v = prime[i]
        if isinstance(v, int):
            if v == target:
                return prime, i
        else:
            r = find_ref(v, target)
            if r:
                return r
    return None


def reduce_primes(primes, first):
    changed = True
    while changed:
        changed = False
        counts = {}
        for p in primes.values():
            count_refs(p, counts)
        for target in sorted(counts):
            if counts[target] != 1 or target == 0 or target == first:
                continue
            if target not in primes:
                continue        # already inlined or not a block
            for root, p in primes.items():
                if root == target:
                    continue    # would inline a block into itself
                r = find_ref(p, target)
                if r:
                    container, idx = r
                    container[idx] = primes.pop(target)
                    changed = True
                    break
            if changed:
                break
    return primes


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def fmt_insn(insn, addr_width):
    """Fixed-width columns as in the assignment's example output:
    address field 16 wide in sequences, 12 wide in if-predicates;
    mnemonic field 8 wide."""
    addr = f"{insn.address:#x}:"
    return f"{addr:<{addr_width}}{insn.mnemonic:<8}{insn.op_str}".rstrip()


def emit(prime, depth, out):
    pad = "    " * depth

    def emit_slot(v, d):
        if isinstance(v, int):
            out.append("    " * d + f"L := {v:#x}")
        else:
            emit(v, d, out)

    kind, _, insns = prime[0], prime[1], prime[2]
    if kind == "seq":
        for insn in insns:
            out.append(pad + fmt_insn(insn, 16))
        emit_slot(prime[3], depth)
    else:
        out.append(pad + "if")
        for insn in insns:
            out.append(pad + "    " + fmt_insn(insn, 12))
        out.append(pad + "then")
        emit_slot(prime[3], depth + 1)
        out.append(pad + "else")
        emit_slot(prime[4], depth + 1)
        out.append(pad + "fi")


# --------------------------------------------------------------------------

def main(argv):
    if len(argv) < 2:
        print(f"usage: {argv[0]} <elf-file> [leader ...]", file=sys.stderr)
        return 1
    try:
        elf = Elf(argv[1])
    except (OSError, ValueError, struct.error) as e:
        print(f"error: {argv[1]}: {e}", file=sys.stderr)
        return 1
    try:
        given = [int(a, 0) for a in argv[2:]]
    except ValueError as e:
        print(f"error: bad leader address: {e}", file=sys.stderr)
        return 1

    dis = Disasm(elf)
    if given:
        initial = given
    else:
        start = elf.entry
        if not elf.in_bounds(start):
            print(f"error: entry point {start:#x} is not in executable code",
                  file=sys.stderr)
            return 1
        m = find_main(elf, dis, start)
        if m is not None and elf.in_bounds(m):
            start = m
        initial = [start]
    first = initial[0]

    leaders = find_leaders(dis, elf, initial)
    if not leaders:
        print("error: no leaders within the ELF file", file=sys.stderr)
        return 1
    blocks = build_blocks(dis, elf, leaders)
    primes = reduce_primes(make_primes(blocks), first)

    out = []
    for addr in sorted(primes):
        emit(primes[addr], 0, out)
        out.append("")
    print("\n".join(out).rstrip())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
