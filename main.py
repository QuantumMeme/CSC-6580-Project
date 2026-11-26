#!/usr/bin/env python3

import sys

from capstone import CS_ARCH_X86, CS_MODE_64, Cs, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_GRP_IRET
from capstone.x86 import *
from elftools.elf.elffile import ELFFile, ELFError
from elftools.elf.sections import SymbolTableSection
from elftools.elf.constants import SH_FLAGS
from elftools.elf.relocation import RelocationSection

# CApstone converts immediate displacents as neg python ints
MASK64 = (1 << 64) - 1

# list of non returning fucntions
NORETURN = {"__libc_start_main", "exit", "_exit", "_Exit", "abort",
            "__stack_chk_fail", "__assert_fail", "__fortify_fail",
            "__chk_fail", "err", "errx", "pthread_exit", "longjmp",
            "__cxa_throw", "_Unwind_Resume"}

# Predicate detection
LOOPS = {X86_INS_LOOP, X86_INS_LOOPE, X86_INS_LOOPNE}
COND_JUMPS =  {X86_INS_JCXZ, X86_INS_JECXZ, X86_INS_JRCXZ}

#LOOP_IS_PREDICATE = False
LOOP_IS_PREDICATE = True

def make_cs(elf:ELFFile):
    """Create a Capstone disassembler for the ELF's architecture."""
    arch = CS_ARCH_X86
    mode = CS_MODE_64

    md = Cs(arch, mode) # Capstone object(architecture, mode)
    md.detail = True    # for groups and operands

    return md


#######################################
# Finding code sections that may or may not be in .text
def code_regions(elf:ELFFile):
    """
    Return every executable, file-backed piece of the program as a list of
        (start, end, data, name).  Code may live in several sections
        (.init, .plt, .plt.sec, .text, .fini, ...).
    """
    regs = []

    for sec in elf.iter_sections():
        if not sec["sh_flags"] & SH_FLAGS.SHF_EXECINSTR:
            continue

        # empty sections or no-bytes (.bss) section
        if sec["sh_type"] == "SHT_NOBITS" or sec["sh_size"]  == 0:
            continue

        start = sec["sh_addr"]      # virt addr where it is loaded
        data = sec.data()
        regs.append((start, start + len(data), data, sec.name))


    # some binaries might be stripped of section names, so we can
    # use program headers instead: loadable (PT_LOAD) segments
    # with execute permission (PF_X == 1)
    if not regs:
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_LOAD" and seg["p_flags"] & 1:   # PF_X
                start = seg["p_vaddr"]
                # Only the part present in the file (p_filesz) is real code
                data = seg.data()[:seg["p_filesz"]]
                regs.append((start, start + len(data), data, "segment@0x%x" % start))

    # sorting by start address
    regs.sort()
    return regs

#########################################
# checking if addr in the provided ELF
def find_region(regs, addr):
    """ Return the code region containing addr, or None"""
    if addr is None:
        return None
    for reg in regs:
        # reg = (start, end, data, name)
        if reg[0] <= addr < reg[1]:
            return reg
    return None

########################################
# decode one insn at a time
def decode(md, regs, addr, cache):
    """
    Disassemble the one instruction at addr (None if not code/invalid).
    """
    # to avoid decodin the same address, we cache results per address
    if addr in cache:
        return cache[addr]
    insn = None
    reg = find_region(regs, addr)
    if reg is not None:
        start, _, data, _ = reg
        off = addr - start
        # an x86 insn is atmost 15 bytes, so 16 byte sare enough to decode
        insn = next(md.disasm(data[off:off + 16], addr, 1), None)
    cache[addr]  = insn
    return insn


##################################
def build_symbol_map(elf:ELFFile, md, regs) -> dict:
    """
    Return names: a single {address: name} dictionary holding
    """
    names = {}

    # Function symbols: address of the function -> its name.
    for sec in elf.iter_sections():
        if not isinstance(sec, SymbolTableSection):
            continue
        for sym in sec.iter_symbols():
            # Skip unnamed symbols, imports with no address, non-functions.
            if sym.name and sym["st_value"] and sym["st_info"]["type"] in ("STT_FUNC", "STT_GNU_IFUNC"):
                # Strip version suffixes such as "@GLIBC_2.34".
                names.setdefault(sym["st_value"], sym.name.split("@")[0])

    # GOT symbol names
    for sec in elf.iter_sections():
        if not isinstance(sec, RelocationSection) or not sec["sh_link"]:
            continue
        # sh_link points at the symbol table the relocations refer to.
        symtab = elf.get_section(sec["sh_link"])
        if not isinstance(symtab, SymbolTableSection):
            continue
        for rel in sec.iter_relocations():
            if rel["r_info_sym"]:                 # 0 means "no symbol"
                sym = symtab.get_symbol(rel["r_info_sym"])
                if sym.name:
                    names.setdefault(rel["r_offset"], sym.name.split("@")[0])

    # PLT stub names
    cache = {}
    for start, end, _, sec_name in regs:
        if not sec_name.startswith(".plt"):      # .plt, .plt.sec, .plt.got
            continue
        addr, prev = start, None
        while addr < end:
            insn = decode(md, regs, addr, cache)
            if insn is None:                     # undecodable byte: skip
                addr, prev = addr + 1, None
                continue
            # if jump to memory type
            if insn.id == X86_INS_JMP and insn.operands and insn.operands[0].type == X86_OP_MEM:
                slot = mem_address(insn, insn.operands[0])
                if slot in names:
                    # The stub starts at a preceding endbr64, if any.
                    stub = prev.address if prev is not None and prev.id == X86_INS_ENDBR64 else insn.address
                    names.setdefault(stub, names[slot])
            prev = insn
            addr += insn.size
    return names

######################################
# Direct and indirect calls and jumps
######################################

def mem_address(insn, op):
    """Address of a [rip + disp] or [disp] memory operand, else None."""
    mem = op.mem
    # An index register (e.g. [rax*8 + table]) or a segment override
    # (fs:/gs:) depends on run-time values, so we cannot compute it.
    if mem.index != X86_REG_INVALID or mem.segment != X86_REG_INVALID:
        return None
    # RIP-relative: the address is relative to the *next* instruction.
    if mem.base == X86_REG_RIP:
        return (insn.address + insn.size + mem.disp) & MASK64
    # No base register: an absolute address.
    if mem.base == X86_REG_INVALID:
        return mem.disp & MASK64
    # Any other base register (rax, rbx, ...) is unknown statically.
    return None

def call_target(insn, names):
    """
    Classify a call or jump.  Returns (kind, address, name):
      ("direct",   target, name or None)   e.g. call 0x401136
      ("indirect", None,   name or None)   e.g. call [rip+X], call rax
    Indirect targets are not resolved; we only look up a name for the
    GOT slot they go through, if there is one.
    """
    op = insn.operands[0] if insn.operands else None
    # Direct: the target address is an immediate in the instruction.
    if op is not None and op.type == X86_OP_IMM:
        target = op.imm & MASK64
        return "direct", target, names.get(target)
    # Indirect through memory: name the slot (e.g. __libc_start_main@GOT).
    if op is not None and op.type == X86_OP_MEM:
        return "indirect", None, names.get(mem_address(insn, op))
    # Indirect through a register: nothing known.
    return "indirect", None, None


###################################
# conditional blocks
###############################
def is_conditional(insn):
    """ True for jcc, loop*, j*cxz: predicate detection"""
    if insn.id in LOOPS:
        return LOOP_IS_PREDICATE
    if insn.id in COND_JUMPS:
        return True
    return insn.group(CS_GRP_JUMP) and insn.id not in (X86_INS_JMP, X86_INS_LJMP)


#########################################
# Entry point
#########################
def find_start(elf, md, regs, names):
    """
    start = e_entry (default)_
    else: if  entry code to glibc _start calling __libc_start_main(main, ...)
        we return  'main' (first arg)
    """
    # entry provided by the ELF
    start = elf.header["e_entry"]

    # locate the section that contains the e_entry
    if find_region(regs, start) is None:
        raise ValueError("Entry point 0x%x is not an executable code" %start)

    # walk from the entry point to confirm we are not in _start
    cache, rdi, addr = {}, None, start
    for _ in range(64):     # _start is small, so capping it early
        insn = decode(md, regs, addr, cache)
        if insn is None:
            break
        ops = insn.operands

        # check first "call"
        if insn.group(CS_GRP_CALL):
            if call_target(insn, names)[2] == "__libc_start_main":
                # std entry: cech 'rdi'
                if find_region(regs, rdi) is not None:
                    return rdi
                # else we fall back to "main" symbol
                main_sym = next((a for a, n in names.items() if n == "main"), None)
                if find_region(regs, main_sym) is not None:
                    return main_sym
            break

        # if there is Jump/return/hlt, we are not in _start
        if insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_RET) or insn.id == X86_INS_HLT:
            break

        # tracking what is loaded in 'rdi'/'edi'
        if len(ops) == 2 and ops[0].type == X86_OP_REG and insn.reg_name(ops[0].reg) in ("rdi", "edi") :
            src = ops[1]
            # if mov to an immediate value: eg. mov rdi, 0x1234
            if insn.id == X86_INS_MOV and src.type == X86_OP_IMM:
                rdi = src.imm & MASK64
            # else if we load eff address: e.g lea rdi, [rip+disp]
            elif insn.id == X86_INS_LEA:
                rdi = mem_address(insn, src)
            else:
                rdi = None

        # next instruction
        addr = insn.address + insn.size

    # if neither _start, nor "main" found: return e_entry
    return start


#################################
# basic block + leaders(basic blocks)
#################################
def control_flow(insn, names):
    """
    Returns: (end_block, successors) for one instruction
    successors -> leaders:
    """
    nxt = insn.address + insn.size  # next instruciton

    # loop: also matches CS_GRP_JMP, so filter out first
    if insn.id in LOOPS and not LOOP_IS_PREDICATE:
        return False, []

    # ret/iret/htl/ud2: block ends
    if insn.group(CS_GRP_RET) or insn.group(CS_GRP_IRET) or insn.id in (X86_INS_HLT, X86_INS_UD2):
        return True, []

    # call: the block continues -> callee is new  leaders
    # No return calls end the block
    if insn.group(CS_GRP_CALL):
        _, target, name = call_target(insn, names)
        succ = [target] if target is not None else [] # indirect: not a target
        return name in NORETURN, succ

    # jmp, jcc, loops: the block ends
    # Direct target is leader
    # NOTE: important when LOOP_IS_PREDICATE flag is set
    if insn.group(CS_GRP_JUMP) or insn.id in LOOPS or insn.id in COND_JUMPS:
        _, target, _ = call_target(insn, names)
        succ = [target] if target is not None else []
        if is_conditional(insn):    # more detailed conditional INSN check using ID
            succ.append(nxt)
        return True, succ

    # if none of the above cases: block continues
    return False, []

def extract_blocks(md, regs, start, names, extra_leaders=None):
    """
    Extract blocks starting at the entry point and any additional leaders.
    """
    cache = {}
    leaders = {start}

    for addr in extra_leaders or []:
        if find_region(regs, addr) is not None:
            leaders.add(addr)

    work = list(leaders)    # leaders still not explored
    seen = set()            # leaders already explored

    # First pass: leader discovery pass
    while work:
        addr = work.pop()

        # if already extracted
        if addr in seen:
            continue
        # otherwise updte the "seen" set
        seen.add(addr)

        # walking the block insn by insn
        while True:
            insn = decode(md, regs, addr, cache)
            if insn is None:        # exit code/ invalid bytes
                break

            ends, succ = control_flow(insn, names)
            # 'call' returns (False, [callee]): the block continues
            # but the callee is still a new leader
            # Keep each successor within the ELF's code
            # targets outside ELF are dropped
            for s in succ:
                if find_region(regs, s) is not None and s not in leaders:
                    leaders.add(s)
                    work.append(s)
            if ends:
                # block ends
                break

            # next insn
            addr = insn.address + insn.size
            if addr in leaders:     # ran into another block
                break

    # Second Pass: block builder
    # running a block from leader till split
    blocks = {}
    for lead in sorted(leaders):
        block, addr = [], lead

        while True:
            insn = decode(md, regs, addr, cache)
            if insn is None:
                break
            block.append(insn)

            if control_flow(insn, names)[0]:    # control flow ends a block
                break

            # next insn
            addr = insn.address + insn.size
            if addr in leaders:     # next leader ends block
                break

        if block:
            blocks[lead] = block     # keyed in by first address

    return blocks

##################################
# Register normalization
##################################
def normalize_register(reg):
    """Normalize register names to their 64-bit equivalents."""

    register_map = {
        "al": "rax", "ah": "rax", "ax": "rax", "eax": "rax",
        "bl": "rbx", "bh": "rbx", "bx": "rbx", "ebx": "rbx",
        "cl": "rcx", "ch": "rcx", "cx": "rcx", "ecx": "rcx",
        "dl": "rdx", "dh": "rdx", "dx": "rdx", "edx": "rdx",
        "sil": "rsi", "si": "rsi", "esi": "rsi",
        "dil": "rdi", "di": "rdi", "edi": "rdi",
        "bpl": "rbp", "bp": "rbp", "ebp": "rbp",
        "spl": "rsp", "sp": "rsp", "esp": "rsp",
        "ip": "rip", "eip": "rip",
        "flags": "rflags", "eflags": "rflags"
    }

    # Normalize traditional x86 registers.
    if reg in register_map:
        return register_map[reg]

    # Normalize extended registers (r8-r15).
    for i in range(8, 16):
        if reg in (f"r{i}b", f"r{i}w", f"r{i}d"):
            return f"r{i}"

    # Registers that do not require normalization.
    return reg

##################################
# Register access
##################################
def get_register_access(insn):
    """Return normalized sets of registers read and written."""

    regs_read, regs_written = insn.regs_access()

    read = {normalize_register(insn.reg_name(reg)) for reg in regs_read}
    written = {normalize_register(insn.reg_name(reg)) for reg in regs_written}

    return read, written

##################################
# Live-on-entry analysis
##################################
def get_live_on_entry(block):
    """Return registers read before being written in a basic block."""

    live_on_entry = set()
    written = set()

    for insn in block:
        regs_read, regs_written = get_register_access(insn)

        # Registers read before being written are live on entry.
        for reg in regs_read:
            if reg not in written:
                live_on_entry.add(reg)

        # Track registers written by this instruction.
        written.update(regs_written)

    return live_on_entry


def main() -> int:
    # Require an ELF executable; optional arguments are block leaders.
    if len(sys.argv) < 2:
        sys.stderr.write("usage: %s <elf-executable> [block-leaders...]\n" % sys.argv[0])
        return 1

    try:
        extra_leaders = [int(addr, 0) for addr in sys.argv[2:]]
    except ValueError:
        sys.stderr.write("error: block leaders must be valid addresses\n")
        return 1
    try:
        # The file must stay open while pyelftools reads section data.
        with open(sys.argv[1], "rb") as f:
            # open ELF file
            elf = ELFFile(f)
            # S1: create Capstone class obj
            md = make_cs(elf)
            # S2: code regions (.txt, .start, etc.)
            regs = code_regions(elf)
            # S3: symbol table for mapping addresses
            names = build_symbol_map(elf, md, regs)
            # S4: find correct start point
            # S5: extract basic blocks
            if extra_leaders:
                start = min(extra_leaders)
                blocks = extract_blocks(md, regs, start, names, extra_leaders)
            else:
                start = find_start(elf, md, regs, names)
                blocks = extract_blocks(md, regs, start, names)

            if not blocks:
                raise ValueError("No valid basic blocks found")
    except (OSError, ValueError, ELFError) as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 1

    # Print live-on-entry registers for each basic block.
    for addr in sorted(blocks):
        live_on_entry = get_live_on_entry(blocks[addr])
        registers = ", ".join(sorted(live_on_entry))
        print(f"0x{addr:08x}: {registers}".rstrip())

    return 0


if __name__ == "__main__":
    sys.exit(main())
