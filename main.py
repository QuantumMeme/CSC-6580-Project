#!/usr/bin/env python3

import sys

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from elftools.elf.elffile import ELFFile, ELFError

def error(msg) -> None:
    """Print an error message."""
    print(f"ERROR: {msg}")


def disassemble(elf: ELFFile) -> None:
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

    found = False
    for section in elf.iter_sections():
        addr = section["sh_addr"]
        size = section["sh_size"]

        if addr <= entrypoint < (addr + size):
            print(f"Name: {section.name}\tAddr: {addr:x}\tSize: {size}b")
            found = True
            break

    if not found:
        raise ELFError("No entrypoint found.")


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} [path to ELF file]")
        return -1
    try:
        with open(sys.argv[1], "rb") as file:
            elf = ELFFile(file)
            #disassemble(elf)
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
