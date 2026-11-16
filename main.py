#!/usr/bin/env python3

import sys

from capstone import CS_ARCH_X86, CS_MODE_64, Cs, CsInsn, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86 import X86_INS_JMP, X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile, ELFError
from typing import List, Optional, Tuple


# instruction groups that end blocks (calls return, so they don't)
BLOCK_TERMS = [CS_GRP_JUMP, CS_GRP_RET]

def error(msg) -> None:
    """Print an error message."""
    print(f"ERROR: {msg}")


def find_section(sections: List[Tuple[int, bytes]], address: int) -> Optional[Tuple[int, bytes]]:
    """Return the (addr, data) section containing address, or None."""
    for addr, data in sections:
        if addr <= address < (addr + len(data)):
            return addr, data
    return None


def decode(md: Cs, sections: List[Tuple[int, bytes]], address: int) -> Optional[CsInsn]:
    """Disassemble the one instruction at address, or None."""
    section = find_section(sections, address)
    if not section:
        return None

    offset: int = address - section[0]
    chunk = section[1][offset:offset + 15] # x86 instructions are 15b

    insns = list(md.disasm(chunk, address, count=1))
    return insns[0] if insns else None


def is_predicate(insn: CsInsn) -> bool:
    """True for conditionals (jg, js, loop, ...)."""
    return (CS_GRP_JUMP in insn.groups and insn.id != X86_INS_JMP) or insn.mnemonic.startswith("loop")


def ends_block(insn: CsInsn) -> bool:
    """True if instruction is a block terminator."""
    for g in insn.groups:
        if g in BLOCK_TERMS:
            return True
    # capstone doesn't group these
    return insn.mnemonic in ("hlt", "ud2") or insn.mnemonic.startswith("loop")


def get_leaders(insn: CsInsn) -> List[int]:
    """New block leaders from a call or jump. Only direct targets are known."""
    if not (ends_block(insn) or CS_GRP_CALL in insn.groups):
        return []

    leaders: List[int] = []
    if insn.operands and insn.operands[0].type == X86_OP_IMM:
        leaders.append(insn.operands[0].imm)
    if is_predicate(insn):
        leaders.append(insn.address + insn.size) # fall through
    return leaders


def get_block(md: Cs, sections: List[Tuple[int, bytes]], address: int, leaders: set) -> List[CsInsn]:
    """Disassemble from address until a block terminator or the next leader."""
    block: List[CsInsn] = []
    while True:
        insn = decode(md, sections, address)
        if not insn:
            break
        block.append(insn)

        address += insn.size
        if ends_block(insn) or address in leaders:
            break
    return block


def get_l(insn: CsInsn):
    """
    What the last instruction of a block sets L to.
    (then, else) for predicates, one address for functions. 0 when unknown.
    """
    next_address: int = insn.address + insn.size
    op = insn.operands[0] if insn.operands else None

    target: int = 0
    if op and op.type == X86_OP_IMM:
        target = op.imm
    elif op and op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
        target = next_address + op.mem.disp # rip relative is from the next instruction

    if is_predicate(insn):
        return target, next_address
    if insn.id == X86_INS_JMP:
        return target
    if ends_block(insn):
        return 0 # ret, hlt, ...
    return next_address # ran into the next leader


def disassemble_text(elf: ELFFile) -> None:
    """
    Disassemble ELF file and extracts .text section.
    """

    # https://www.capstone-engine.org/lang_python.html
    md = Cs(CS_ARCH_X86, CS_MODE_64)  # Capstone object(architecture, mode)
    md.detail = True

    text = elf.get_section_by_name(".text")
    if text is None:
        raise ELFError("No .text section")

    code: bytes = text.data()
    address: int = text["sh_addr"]

    for i in md.disasm(code, address):
        print(f"{i.address:x}\t {i.mnemonic}\t {i.op_str}")


def print_entry(elf: ELFFile) -> None:

    md = Cs(CS_ARCH_X86, CS_MODE_64)  # Capstone object(architecture, mode)
    md.detail = True

    entrypoint = elf.header["e_entry"]
    # print(f"Entrypoint @ 0x{entrypoint:x}\n")

    # code can be in any executable section (.text, .plt, .init, ...)
    sections: List[Tuple[int, bytes]] = []
    for section in elf.iter_sections():
        if section["sh_flags"] & SH_FLAGS.SHF_EXECINSTR and section["sh_type"] != "SHT_NOBITS":
            sections.append((section["sh_addr"], section.data()))

    if not find_section(sections, entrypoint):
        raise ELFError("No entrypoint found.")

    # standard _start: rdi = main, call __libc_start_main, hlt (it never returns)
    start: int = entrypoint
    rdi: Optional[int] = None
    entry_block = get_block(md, sections, entrypoint, set())
    for i, insn in enumerate(entry_block):
        if CS_GRP_CALL in insn.groups:
            if i + 1 < len(entry_block) and entry_block[i + 1].mnemonic == "hlt" and rdi and find_section(sections, rdi):
                start = rdi
            break

        # track what gets loaded into rdi
        ops = insn.operands
        if len(ops) == 2 and ops[0].type == X86_OP_REG and insn.reg_name(ops[0].reg) in ("rdi", "edi"):
            if insn.mnemonic == "mov" and ops[1].type == X86_OP_IMM: # mov rdi, 0x401136
                rdi = ops[1].imm
            elif insn.mnemonic == "lea" and ops[1].mem.base == X86_REG_RIP: # lea rdi, [rip + X]
                rdi = insn.address + insn.size + ops[1].mem.disp
            else:
                rdi = None

    # extract blocks and find leaders until no new ones show up
    leaders = {start}
    work: List[int] = [start]
    while work:
        for insn in get_block(md, sections, work.pop(), leaders):
            for leader in get_leaders(insn):
                # only leaders inside the ELF's code
                if leader not in leaders and find_section(sections, leader):
                    leaders.add(leader)
                    work.append(leader)

    # a leader found later can split an earlier block, so build them all again
    block_list: List[Tuple[int, List[CsInsn]]] = []
    for leader in leaders:
        block = get_block(md, sections, leader, leaders)
        if block:
            block_list.append((leader, block))

    block_list.sort()

    for n, i in enumerate(block_list):
        if n:
            print()

        l = get_l(i[1][-1])
        if isinstance(l, tuple): # predicate -> if-then-else prime
            print("if")
            for j in i[1]:
                print(f"\t0x{j.address:x}:\t{j.mnemonic}\t{j.op_str}".rstrip())
            print(f"then\n\tL := 0x{l[0]:x}\nelse\n\tL := 0x{l[1]:x}\nfi")
        else: # function -> sequence prime
            for j in i[1]:
                print(f"0x{j.address:x}:\t{j.mnemonic}\t{j.op_str}".rstrip())
            print(f"L := 0x{l:x}")


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} [path to ELF file]")
        return -1
    try:
        with open(sys.argv[1], "rb") as file:
            elf = ELFFile(file)
            # disassemble_text(elf)
            print_entry(elf)
        return 0
    except FileNotFoundError:
        error(f"File not found ({sys.argv[1]})")
    except IsADirectoryError:
        error("Provided path is a directory")
    except PermissionError:
        error("Cannot read file")
    except ELFError as err:
        error(f"Invalid ELF file: {err}")
    return -1


if __name__ == "__main__":
    sys.exit(main())
