#!/usr/bin/env python3

import sys

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from elftools.elf.elffile import ELFFile, ELFError


# Error logging
def error(msg) -> None:
    """Print an error message."""
    print(f"ERROR: {msg}")

# disassemble binary code:
##  I/P: ELFFile Obj
##  O/P: DICT of disassembled ops
def disassemble(elf: ELFFile) -> dict:
    """
    Disassemble ELF file and extracts .text section.
    Return: `dict` of disassembled object codes
    """

    # https://www.capstone-engine.org/lang_python.html
    md = Cs(CS_ARCH_X86, CS_MODE_64)  # Capstone object(architecture, mode)
    md.detail = True

    text = elf.get_section_by_name(".text")
    if text is None:
        raise ELFError("No .text section")

    code: bytes = text.data()
    address: int = text["sh_addr"]

    disassembly_dict = {}
    for i in md.disasm(code, address):
        # print(f"{i.address:#06x}\t {i.mnemonic}\t {i.op_str}")
        addr_key = f"{i.address:#06x}"
        disassembly_dict[addr_key] = {
            "mnemonic": i.mnemonic,
            "op_str": i.op_str
        }

    return disassembly_dict

def block_slice(disasm:dict) -> dict:
    """
    Create basic-block slices 
    Return: `dict` of control-flow
    """
    basic_blocks_dict = {}
    
    ## TODO: 

    return basic_blocks_dict


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} [path to ELF file]")
        return -1
    try:
        with open(sys.argv[1], "rb") as file:
            elf = ELFFile(file)
            disassembly_dict =  disassemble(elf)

            # print disassemble code
            for addr, info in disassembly_dict.items():
                print(f"{addr}\t {info['mnemonic']}\t {info['op_str']}")
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
