#!/usr/bin/env python3
"""Find and print the basic blocks reachable from an x86-64 ELF's start location.

Usage: python3 ./main.py <elf-executable>
"""

import os
import sys

from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_MODE_64, Cs
from capstone.x86 import (
    X86_GRP_IRET,
    X86_INS_HLT,
    X86_INS_INT3,
    X86_INS_JMP,
    X86_INS_LEA,
    X86_INS_LJMP,
    X86_INS_LOOP,
    X86_INS_LOOPE,
    X86_INS_LOOPNE,
    X86_INS_MOV,
    X86_INS_MOVABS,
    X86_INS_UD2,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_REG_DI,
    X86_REG_DIL,
    X86_REG_EDI,
    X86_REG_INVALID,
    X86_REG_RDI,
    X86_REG_RIP,
)
from elftools.common.exceptions import ELFError
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

# The assignment describes a block "ending with call and hlt", so a call does
# not end a basic block. Set this to True to treat calls as block terminators.
CALL_ENDS_BLOCK = False

LIBC_START_MAIN = "__libc_start_main"
RDI_REGISTERS = {X86_REG_RDI, X86_REG_EDI, X86_REG_DI, X86_REG_DIL}
# Capstone decodes a whole window up front, so keep it small.
DISASSEMBLY_WINDOW = 256
MAX_PLT_STUB_INSTRUCTIONS = 4


class Image:
    """Executable sections, symbols, and relocations from an ELF file."""

    def __init__(self, elf):
        self.entry = elf.header["e_entry"]
        self.sections = []
        self.data_sections = []
        self.symbols = {}
        self.relocations = {}
        self.has_symbol_tables = any(
            isinstance(section, SymbolTableSection) and section.num_symbols() > 1
            for section in elf.iter_sections()
        )

        for section in elf.iter_sections():
            self._load_section(section)
        for section in elf.iter_sections():
            if isinstance(section, RelocationSection):
                self._load_relocations(elf, section)

        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True

    def _load_section(self, section):
        flags = section["sh_flags"]
        if flags & SH_FLAGS.SHF_ALLOC and section["sh_type"] != "SHT_NOBITS":
            record = (section["sh_addr"], section["sh_size"], section.data())
            self.data_sections.append(record)
            if flags & SH_FLAGS.SHF_EXECINSTR:
                self.sections.append(record)

        if isinstance(section, SymbolTableSection):
            for symbol in section.iter_symbols():
                if symbol["st_value"] and symbol.name:
                    self.symbols.setdefault(symbol["st_value"], set()).add(symbol.name)

    def _load_relocations(self, elf, section):
        symbol_table = elf.get_section(section["sh_link"])
        has_symbols = isinstance(symbol_table, SymbolTableSection)
        for relocation in section.iter_relocations():
            symbol = None
            symbol_index = relocation["r_info_sym"]
            if has_symbols and symbol_index:
                symbol = symbol_table.get_symbol(symbol_index)
            addend = relocation["r_addend"] if relocation.is_RELA() else 0
            self.relocations[relocation["r_offset"]] = (symbol, addend)

    def has_code_at(self, address):
        return self._find(self.sections, address) is not None

    @staticmethod
    def _find(sections, address):
        for record in sections:
            if record[0] <= address < record[0] + record[1]:
                return record
        return None

    def disassemble_from(self, address):
        """Yield instructions until the section ends or decoding fails."""
        record = self._find(self.sections, address)
        if record is None:
            return
        section_start, _, data = record
        current = address
        while True:
            offset = current - section_start
            window = data[offset:offset + DISASSEMBLY_WINDOW]
            if not window:
                return
            decoded = 0
            for insn in self.md.disasm(window, current):
                decoded += 1
                current = insn.address + insn.size
                yield insn
            if decoded == 0:
                return

    def read_pointer(self, address):
        """Return the value stored in a GOT slot, or None if it is unknown."""
        relocation = self.relocations.get(address)
        if relocation is not None:
            symbol, addend = relocation
            if symbol is None:
                return addend
            if symbol["st_value"]:
                return symbol["st_value"] + addend
            return None

        record = self._find(self.data_sections, address)
        if record is None:
            return None
        offset = address - record[0]
        raw = record[2][offset:offset + 8]
        value = int.from_bytes(raw, "little") if len(raw) == 8 else 0
        return value or None

    def slot_is_libc_start_main(self, address):
        relocation = self.relocations.get(address)
        return (
            relocation is not None
            and relocation[0] is not None
            and is_libc_start_main_name(relocation[0].name)
        )


def is_libc_start_main_name(name):
    return name.split("@")[0].startswith(LIBC_START_MAIN)


def memory_address(insn, operand):
    """Return the address of a memory operand if it can be computed statically."""
    memory = operand.mem
    if memory.index != X86_REG_INVALID or memory.segment != X86_REG_INVALID:
        return None
    if memory.base == X86_REG_RIP:
        return insn.address + insn.size + memory.disp
    if memory.base == X86_REG_INVALID:
        return memory.disp & 0xFFFFFFFFFFFFFFFF
    return None


def direct_target(insn):
    """Return the immediate target of a direct jump or call, if there is one."""
    if insn.operands and insn.operands[0].type == X86_OP_IMM:
        return insn.operands[0].imm & 0xFFFFFFFFFFFFFFFF
    return None


def is_call(insn):
    return insn.group(CS_GRP_CALL)


def is_jump(insn):
    return insn.group(CS_GRP_JUMP) or insn.id in (X86_INS_LOOP, X86_INS_LOOPE, X86_INS_LOOPNE)


def is_unconditional_jump(insn):
    return insn.id in (X86_INS_JMP, X86_INS_LJMP)


def is_stop(insn):
    """Return True if execution does not continue to the next instruction."""
    return (
        insn.group(CS_GRP_RET)
        or insn.group(X86_GRP_IRET)
        or insn.id in (X86_INS_HLT, X86_INS_UD2, X86_INS_INT3)
    )


def ends_block(insn):
    return is_jump(insn) or is_stop(insn) or (CALL_ENDS_BLOCK and is_call(insn))


def rdi_value(image, insn):
    """Return the known value an instruction writes to rdi, or None."""
    if len(insn.operands) != 2:
        return None
    source = insn.operands[1]
    if insn.id == X86_INS_LEA and source.type == X86_OP_MEM:
        return memory_address(insn, source)
    if insn.id in (X86_INS_MOV, X86_INS_MOVABS):
        if source.type == X86_OP_IMM:
            return source.imm & 0xFFFFFFFFFFFFFFFF
        if source.type == X86_OP_MEM:
            slot = memory_address(insn, source)
            return image.read_pointer(slot) if slot is not None else None
    return None


def calls_libc_start_main(image, call):
    """Return True if a call reaches __libc_start_main directly or through the GOT."""
    target = direct_target(call)
    if target is None:
        operand = call.operands[0] if call.operands else None
        if operand is None or operand.type != X86_OP_MEM:
            return False
        slot = memory_address(call, operand)
        if slot is None:
            return False
        if image.slot_is_libc_start_main(slot):
            return True
        target = image.read_pointer(slot)
        if target is None:
            return False

    if any(is_libc_start_main_name(name) for name in image.symbols.get(target, ())):
        return True

    # A direct call may reach a PLT stub that jumps through a GOT slot.
    for count, insn in enumerate(image.disassemble_from(target)):
        if count >= MAX_PLT_STUB_INSTRUCTIONS:
            break
        if is_jump(insn):
            operand = insn.operands[0] if insn.operands else None
            if operand is not None and operand.type == X86_OP_MEM:
                slot = memory_address(insn, operand)
                if slot is not None and image.slot_is_libc_start_main(slot):
                    return True
            break
        if ends_block(insn):
            break

    # Without symbols the target cannot be named, so rely on the call/hlt pattern.
    return not image.has_symbol_tables


def find_main(image):
    """Return main's address for a standard entry point, or None otherwise."""
    rdi = None
    last_call = None
    rdi_at_call = None

    for insn in image.disassemble_from(image.entry):
        if insn.id == X86_INS_HLT:
            if last_call is not None and calls_libc_start_main(image, last_call):
                return rdi_at_call
            return None

        if is_call(insn):
            last_call = insn
            rdi_at_call = rdi
            rdi = None
            continue

        last_call = None
        if ends_block(insn):
            return None

        _, written = insn.regs_access()
        if RDI_REGISTERS.intersection(written):
            rdi = rdi_value(image, insn)
    return None


def successors(image, insn):
    """Return the known leader addresses created by an instruction."""
    leaders = []
    target = direct_target(insn) if is_jump(insn) or is_call(insn) else None
    if target is not None and image.has_code_at(target):
        leaders.append(target)

    falls_through = (is_jump(insn) and not is_unconditional_jump(insn)) or (
        CALL_ENDS_BLOCK and is_call(insn)
    )
    following = insn.address + insn.size
    if falls_through and image.has_code_at(following):
        leaders.append(following)
    return leaders


def find_leaders(image, start):
    """Find every leader reachable from the start location."""
    leaders = {start}
    pending = [start]
    while pending:
        leader = pending.pop()
        for insn in image.disassemble_from(leader):
            if insn.address != leader and insn.address in leaders:
                break
            for discovered in successors(image, insn):
                if discovered not in leaders:
                    leaders.add(discovered)
                    pending.append(discovered)
            if ends_block(insn):
                break
    return sorted(leaders)


def extract_block(image, leader, next_leader):
    """Return a block's instructions, stopping at a terminator or the next leader."""
    block = []
    for insn in image.disassemble_from(leader):
        if next_leader is not None and insn.address >= next_leader:
            break
        block.append(insn)
        if ends_block(insn):
            break
    return block


def print_blocks(image, leaders):
    """Print each block and return how many were printed."""
    printed = 0
    for index, leader in enumerate(leaders):
        following = leaders[index + 1] if index + 1 < len(leaders) else None
        block = extract_block(image, leader, following)
        if not block:
            continue
        if printed:
            print()
        for insn in block:
            print(f"{insn.address:#x}: {insn.mnemonic} {insn.op_str}".rstrip())
        printed += 1
    return printed


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    return 1


def main(argv):
    if len(argv) != 2:
        print(f"usage: python3 {argv[0]} <elf-executable>", file=sys.stderr)
        return 1

    try:
        with open(argv[1], "rb") as handle:
            elf = ELFFile(handle)
            if elf.header["e_machine"] != "EM_X86_64":
                return fail("only x86-64 ELF files are supported")
            image = Image(elf)
    except OSError as exc:
        return fail(f"cannot read {argv[1]}: {exc.strerror}")
    except ELFError as exc:
        return fail(f"{argv[1]} is not a valid ELF file: {exc}")

    if not image.has_code_at(image.entry):
        return fail(f"no executable section contains the entry point {image.entry:#x}")

    start = find_main(image)
    found_main = start is not None and image.has_code_at(start)
    if not found_main:
        start = image.entry

    try:
        count = print_blocks(image, find_leaders(image, start))
        sys.stdout.flush()
        # The summary goes to stderr so stdout keeps the assignment's exact format.
        label = "main" if found_main else "entry point"
        print(
            f"\nEntry point: {image.entry:#x}\n"
            f"Start: {start:#x} ({label})\n"
            f"Basic blocks: {count}",
            file=sys.stderr,
        )
    except BrokenPipeError:
        # The reader closed early (for example, `| head`). Stop quietly.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
