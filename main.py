#!/usr/bin/env python3

import sys

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RDI, X86_REG_RIP
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFError, ELFFile


def error(msg) -> None:
    """Print an error message."""
    print(f"ERROR: {msg}")

def get_instruction(elf: ELFFile, md: Cs, address: int):
    """Find and disassemble one instruction at the given address."""

    for section in elf.iter_sections():
        if not section["sh_flags"] & SH_FLAGS.SHF_EXECINSTR:
            continue

        if section["sh_type"] == "SHT_NOBITS":
            continue

        start = section["sh_addr"]
        end = start + section["sh_size"]

        if start <= address < end:
            code = section.data()[address - start:]
            instructions = list(md.disasm(code, address, count=1))

            if instructions:
                return instructions[0]

    return None

def discover_basic_blocks(elf: ELFFile, md: Cs, start: int):
    """Discover reachable instructions and organize them into basic blocks."""

    pending = [start]
    instructions = {}
    leaders = {start}
    endings = set()

    while pending:
        address = pending.pop()

        while address not in instructions:
            instruction = get_instruction(elf, md, address)

            if instruction is None:
                break

            instructions[address] = instruction
            next_address = instruction.address + instruction.size
            mnemonic = instruction.mnemonic

            if mnemonic.startswith("j") or mnemonic.startswith("loop"):
                endings.add(address)

                if instruction.operands and instruction.operands[0].type == X86_OP_IMM:
                    target = instruction.operands[0].imm

                    if get_instruction(elf, md, target) is not None:
                        leaders.add(target)
                        pending.append(target)

                if mnemonic != "jmp":
                    if get_instruction(elf, md, next_address) is not None:
                        leaders.add(next_address)
                        pending.append(next_address)

                break

            if mnemonic == "call":
                if instruction.operands and instruction.operands[0].type == X86_OP_IMM:
                    target = instruction.operands[0].imm

                    if get_instruction(elf, md, target) is not None:
                        leaders.add(target)
                        pending.append(target)

            if mnemonic in ("ret", "retf", "hlt", "ud2"):
                endings.add(address)
                break

            address = next_address

        blocks = {}
        assigned = set()

        for leader in sorted(leaders):
            if leader not in instructions:
                continue

            block = []
            address = leader

            while address in instructions and address not in assigned:
                instruction = instructions[address]
                block.append(instruction)
                assigned.add(address)

                if address in endings:
                    break

                next_address = address + instruction.size

                if next_address in leaders:
                    break

                address = next_address

            if block:
                blocks[leader] = block

        return blocks

def disassemble(elf: ELFFile) -> None:
    """Discover and print basic blocks from an ELF executable."""

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    entry_point = elf.header["e_entry"]
    start_address = entry_point

    # Identify the standard C runtime startup sequence.
    address = entry_point
    main_address = None
    startup_call = False

    for _ in range(30):
        instruction = get_instruction(elf, md, address)

        if instruction is None:
            break

        if len(instruction.operands) == 2:
            dest, src = instruction.operands

            if dest.type == X86_OP_REG and dest.reg == X86_REG_RDI:
                if instruction.mnemonic == "lea" and src.type == X86_OP_MEM:
                    if src.mem.base == X86_REG_RIP:
                        main_address = instruction.address + instruction.size + src.mem.disp

                elif instruction.mnemonic == "mov" and src.type == X86_OP_IMM:
                    main_address = src.imm

        if instruction.mnemonic == "call":
            next_address = instruction.address + instruction.size
            next_instruction = get_instruction(elf, md, next_address)

            if next_instruction is not None and next_instruction.mnemonic == "hlt":
                startup_call = True

            break

        if instruction.mnemonic in ("jmp", "ret", "hlt"):
            break

        address = instruction.address + instruction.size

    if startup_call and main_address is not None:
        if get_instruction(elf, md, main_address) is not None:
            start_address = main_address

    blocks = discover_basic_blocks(elf, md, start_address)

    for address in sorted(blocks):
        for instruction in blocks[address]:
            print(f"0x{instruction.address:x}: {instruction.mnemonic} {instruction.op_str}".rstrip())

        print()

def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} [path to ELF file]")
        return -1
    try:
        with open(sys.argv[1], "rb") as file:
            elf = ELFFile(file)
            disassemble(elf)
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
