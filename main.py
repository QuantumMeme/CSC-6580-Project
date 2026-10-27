#!/usr/bin/env python3

import sys
from elftools.elf.elffile import ELFFile, ELFError

class TextSectionError(Exception):
    pass

def error(msg) -> None:
    """Print an error message."""
    print(f"ERROR: {msg}")

def disassemble(elf: ELFFile) -> None:
    text = elf.get_section_by_name(".text")
    if text is None:
        raise TextSectionError()

    code: bytes = text.data()
    address: int = text["sh_addr"]


def main() -> int:
    """Entry point when run from the prompt. The only
    argument should be the path to the ELF file."""
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} [path to ELF file]")
        return 0
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
    except TextSectionError:
        error("No .text section")
    return -1

if __name__ == "__main__":
    sys.exit(main())