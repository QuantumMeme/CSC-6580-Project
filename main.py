#!/usr/bin/env python3

import sys

from capstone import CS_ARCH_X86, CS_MODE_64, Cs, CsInsn, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from elftools.elf.elffile import ELFFile, ELFError
from typing import List, Tuple


# instruction groups that end blocks
BLOCK_TERMS = [CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET]

def error(msg) -> None:
    """Print an error message."""
    print(f"ERROR: {msg}")


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
    print(f"Entrypoint @ 0x{entrypoint:x}\n")

    target_section = None
    for section in elf.iter_sections():
        addr: int = section["sh_addr"]
        size: int = section["sh_size"]

        if addr <= entrypoint < (addr + size):
            print(f"Name: {section.name}\tAddr: {addr:x}\tSize: {size}b")
            target_section = section
            break

    if not target_section:
        raise ELFError("No entrypoint found.")

    section_data: bytes = target_section.data()
    offset: int = entrypoint - target_section["sh_addr"]
    current_address: int = entrypoint

    block_list: List[Tuple[int, List[CsInsn]]] = []
    block: List[CsInsn] = []

    while offset < len(section_data):

        chunk = section_data[offset:offset + 15] # x86 instructions are 15b

        insns = list(md.disasm(chunk, current_address, count=1))

        if not insns:
            offset += 1
            current_address += 1
            continue

        insn = insns[0]
        block.append(insn)

        # checking if instruction is a block terminator
        end = False
        for g in insn.groups:
            if g in BLOCK_TERMS:
                end = True
                break

        offset += insn.size
        current_address += insn.size

        if end:
            block_list.append((block[0].address, block))
            block = []

    if block:
        block_list.append((block[0].address, block))

    # TODO test if this works how i think it does
    block_list.sort()

    for i in block_list:
        print(f"\n--------\nStart 0x{i[0]:x}\n--------\n")
        for j in i[1]:
            print(f"{j.address:x}\t {j.mnemonic}\t {j.op_str}")


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
