#!/usr/bin/env python3
"""CSC 6580 Project 5: basic block extraction with live-on-entry registers.

Usage: python3 ./main.py ELF_FILE [LEADER ...]

Leaders may be given in any base Python understands (0x401000, 4198400, ...).
Requires: capstone, pyelftools  (pip install capstone pyelftools)
"""

import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CsError
from capstone import x86_const as X
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import SH_FLAGS, P_FLAGS
from elftools.elf.relocation import RelocationSection


# ---------------------------------------------------------------------------
# Register normalization
# ---------------------------------------------------------------------------

def _build_reg_map():
    m = {}
    legacy = {
        'rax': ['eax', 'ax', 'ah', 'al'],
        'rbx': ['ebx', 'bx', 'bh', 'bl'],
        'rcx': ['ecx', 'cx', 'ch', 'cl'],
        'rdx': ['edx', 'dx', 'dh', 'dl'],
        'rsi': ['esi', 'si', 'sil'],
        'rdi': ['edi', 'di', 'dil'],
        'rbp': ['ebp', 'bp', 'bpl'],
        'rsp': ['esp', 'sp', 'spl'],
        'rip': ['eip', 'ip'],
        'rflags': ['eflags', 'flags'],
    }
    for full, subs in legacy.items():
        for s in subs:
            m[s] = full
    for n in range(8, 16):
        for suf in ('d', 'w', 'b'):
            m[f'r{n}{suf}'] = f'r{n}'
    return m


REG_MAP = _build_reg_map()


def normalize(name):
    return REG_MAP.get(name, name)


# ---------------------------------------------------------------------------
# ELF loading
# ---------------------------------------------------------------------------

class Region:
    """A contiguous chunk of executable bytes mapped at a virtual address."""

    def __init__(self, name, vaddr, data):
        self.name = name
        self.vaddr = vaddr
        self.data = data

    def contains(self, addr):
        return self.vaddr <= addr < self.vaddr + len(self.data)


class Binary:
    def __init__(self, path):
        self.fh = open(path, 'rb')
        self.elf = ELFFile(self.fh)
        machine = self.elf['e_machine']
        if machine == 'EM_X86_64':
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)
            self.bits = 64
        elif machine == 'EM_386':
            self.md = Cs(CS_ARCH_X86, CS_MODE_32)
            self.bits = 32
        else:
            raise SystemExit(f'Unsupported architecture: {machine}')
        self.md.detail = True
        self.entry = self.elf['e_entry']
        self.regions = self._exec_regions()
        self.got_names = self._got_symbols()

    def _exec_regions(self):
        regions = []
        for sec in self.elf.iter_sections():
            if (sec['sh_flags'] & SH_FLAGS.SHF_EXECINSTR
                    and sec['sh_type'] != 'SHT_NOBITS' and sec['sh_size']):
                regions.append(Region(sec.name or '<unnamed>',
                                      sec['sh_addr'], sec.data()))
        if not regions:  # no section headers: fall back to segments
            for seg in self.elf.iter_segments():
                if seg['p_type'] == 'PT_LOAD' and seg['p_flags'] & P_FLAGS.PF_X:
                    regions.append(Region('<segment>', seg['p_vaddr'],
                                          seg.data()))
        return regions

    def _got_symbols(self):
        """Map GOT slot address -> symbol name using dynamic relocations."""
        names = {}
        for sec in self.elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            symtab_idx = sec['sh_link']
            if not symtab_idx:
                continue
            symtab = self.elf.get_section(symtab_idx)
            for rel in sec.iter_relocations():
                idx = rel['r_info_sym']
                if idx:
                    sym = symtab.get_symbol(idx)
                    if sym and sym.name:
                        names[rel['r_offset']] = sym.name
        return names

    def region_for(self, addr):
        for r in self.regions:
            if r.contains(addr):
                return r
        return None

    def decode(self, addr):
        """Decode one instruction at addr, or None if impossible."""
        r = self.region_for(addr)
        if r is None:
            return None
        off = addr - r.vaddr
        for insn in self.md.disasm(r.data[off:off + 16], addr, 1):
            return insn
        return None


# ---------------------------------------------------------------------------
# Instruction helpers
# ---------------------------------------------------------------------------

JUMP_GROUPS = {X.X86_GRP_JUMP}
CALL_GROUPS = {X.X86_GRP_CALL}
RET_GROUPS = {X.X86_GRP_RET, X.X86_GRP_IRET}
UNCOND_JUMPS = {'jmp', 'ljmp'}
STOP_MNEMONICS = {'hlt', 'ud2', 'ud1', 'ud0'}


def is_jump(i):
    return any(g in JUMP_GROUPS for g in i.groups)


def is_call(i):
    return any(g in CALL_GROUPS for g in i.groups)


def is_ret(i):
    return any(g in RET_GROUPS for g in i.groups)


def is_terminator(i):
    return (is_jump(i) or is_call(i) or is_ret(i)
            or i.mnemonic in STOP_MNEMONICS)


def falls_through(i):
    """Does execution possibly continue at the next instruction?"""
    if is_ret(i) or i.mnemonic in STOP_MNEMONICS:
        return False
    if is_jump(i) and i.mnemonic in UNCOND_JUMPS:
        return False
    return True


def direct_target(i):
    """Immediate target of a jump/call, else None."""
    if len(i.operands) == 1 and i.operands[0].type == X.X86_OP_IMM:
        return i.operands[0].imm
    return None


def mem_address(i, op):
    """Absolute address of a memory operand if statically known."""
    m = op.mem
    if m.index != 0:
        return None
    if m.base in (X.X86_REG_RIP, X.X86_REG_EIP):
        return i.address + i.size + m.disp
    if m.base == 0:
        return m.disp & 0xFFFFFFFFFFFFFFFF
    return None


# ---------------------------------------------------------------------------
# Locating main
# ---------------------------------------------------------------------------

def resolve_call_name(binary, call):
    """Best-effort name of the function a call goes to (via GOT / PLT)."""
    if not call.operands:
        return None
    op = call.operands[0]
    if op.type == X.X86_OP_MEM:  # call [rip+X]  (-fno-plt / PIE)
        addr = mem_address(call, op)
        return binary.got_names.get(addr) if addr is not None else None
    if op.type == X.X86_OP_IMM:  # call stub@plt -> jmp [GOT]
        addr = op.imm
        for _ in range(3):  # allow endbr64 / bnd prefixes before the jmp
            insn = binary.decode(addr)
            if insn is None:
                return None
            if insn.mnemonic.endswith('jmp') and insn.operands \
                    and insn.operands[0].type == X.X86_OP_MEM:
                slot = mem_address(insn, insn.operands[0])
                return binary.got_names.get(slot) if slot is not None else None
            addr += insn.size
    return None


def find_main(binary, start):
    """If start looks like a standard _start, return main's address."""
    main_candidate = None
    addr = start
    for _ in range(64):
        insn = binary.decode(addr)
        if insn is None:
            return None
        ops = insn.operands
        if binary.bits == 64:
            # main is passed in rdi
            if insn.mnemonic in ('mov', 'lea') and len(ops) == 2 \
                    and ops[0].type == X.X86_OP_REG \
                    and normalize(insn.reg_name(ops[0].reg)) == 'rdi':
                if ops[1].type == X.X86_OP_IMM:
                    main_candidate = ops[1].imm
                elif ops[1].type == X.X86_OP_MEM and insn.mnemonic == 'lea':
                    main_candidate = mem_address(insn, ops[1])
                else:
                    main_candidate = None
        else:
            # main is the last thing pushed before the call
            if insn.mnemonic == 'push' and ops:
                main_candidate = ops[0].imm if ops[0].type == X.X86_OP_IMM \
                    else None

        if is_call(insn):
            name = resolve_call_name(binary, insn)
            nxt = binary.decode(insn.address + insn.size)
            looks_standard = (name == '__libc_start_main' or
                              (name is None and nxt is not None
                               and nxt.mnemonic == 'hlt'))
            if looks_standard and main_candidate is not None \
                    and binary.region_for(main_candidate):
                return main_candidate
            return None
        if is_terminator(insn):
            return None
        addr += insn.size
    return None


# ---------------------------------------------------------------------------
# Basic block extraction
# ---------------------------------------------------------------------------

def find_leaders(binary, initial):
    """Recursive traversal from the initial leaders, collecting all leaders."""
    leaders = set()
    work = [a for a in initial if binary.region_for(a)]
    explored = set()
    leaders.update(work)
    while work:
        addr = work.pop()
        if addr in explored:
            continue
        explored.add(addr)
        while True:
            insn = binary.decode(addr)
            if insn is None:
                break
            if is_terminator(insn):
                targets = []
                if is_jump(insn) or is_call(insn):
                    t = direct_target(insn)
                    if t is not None:
                        targets.append(t)
                if falls_through(insn):
                    targets.append(insn.address + insn.size)
                for t in targets:
                    if binary.region_for(t):
                        leaders.add(t)
                        if t not in explored:
                            work.append(t)
                break
            addr += insn.size
            if addr in leaders and addr in explored:
                break
    return leaders


def build_blocks(binary, leaders):
    """Return {leader: [instructions]} cutting at terminators and leaders."""
    blocks = {}
    for start in sorted(leaders):
        insns = []
        addr = start
        while True:
            insn = binary.decode(addr)
            if insn is None:
                break
            insns.append(insn)
            if is_terminator(insn):
                break
            addr += insn.size
            if addr in leaders:
                break
        if insns:
            blocks[start] = insns
    return blocks


def regs_of(insn):
    try:
        read, written = insn.regs_access()
    except CsError:
        read, written = insn.regs_read, insn.regs_write
    r = {normalize(insn.reg_name(x)) for x in read}
    w = {normalize(insn.reg_name(x)) for x in written}
    r.discard(None)
    w.discard(None)
    return r, w


def live_on_entry(insns):
    live, written = set(), set()
    for insn in insns:
        r, w = regs_of(insn)
        live |= (r - written)
        written |= w
    return sorted(live)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv):
    if len(argv) < 2:
        print(f'Usage: {argv[0]} ELF_FILE [LEADER ...]', file=sys.stderr)
        return 1
    try:
        binary = Binary(argv[1])
    except (OSError, Exception) as e:
        print(f'Error: cannot read ELF file {argv[1]}: {e}', file=sys.stderr)
        return 1

    leaders = set()
    for arg in argv[2:]:
        try:
            leaders.add(int(arg, 0))
        except ValueError:
            print(f'Error: bad leader address {arg!r}', file=sys.stderr)
            return 1

    if not leaders:
        start = binary.entry
        if binary.region_for(start) is None:
            print(f'Error: entry point 0x{start:x} is not in an executable '
                  f'section', file=sys.stderr)
            return 1
        main_addr = find_main(binary, start)
        if main_addr is not None:
            start = main_addr
        leaders.add(start)

    blocks = build_blocks(binary, find_leaders(binary, leaders))
    for addr in sorted(blocks):
        print(f'0x{addr:08x}: {", ".join(live_on_entry(blocks[addr]))}')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv))
    except BrokenPipeError:
        sys.stderr.close()
        sys.exit(0)
