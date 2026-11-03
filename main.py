#!/usr/bin/env python3

import sys

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from elftools.elf.elffile import ELFFile, ELFError
from elftools.elf.sections import SymbolTableSection

####################
# Error logging
def error(msg) -> None:
    """Print an error message."""
    print(f"ERROR: {msg}")


####################
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
        addr_key = f"{i.address:#016x}"

        ## TODO: Maybe we can save the op_str with #016x padding
        ##          if mnemonic in [jmp, call, ...] ops. 
        disassembly_dict[addr_key] = {
            "mnemonic": i.mnemonic,
            "op_str": i.op_str
        }

    return disassembly_dict


####################
def symbol_table(elf:ELFFile) -> dict:
    symtab = elf.get_section_by_name('.symtab')
    if not isinstance(symtab, SymbolTableSection):
        return None
    return symtab
    


####################
def block_slice(elf:ELFFile, disasm:dict) -> dict:
    """
    Create basic-block slices 
    Return: `dict` of control-flow
    """
    bb_dict = {}
    
    # find entry point with 0 padding
    entry = f"{elf['e_entry']:#016x}" 
    # Convert dictionary keys to a list to enable index lookup and slicing
    addrs = list(disasm.keys())
    
    if entry in addrs:
        start_idx = addrs.index(entry)
        # Slice from the entry point up to the next 10 instructions
        end_idx = min(start_idx + 11, len(addrs))
        
        for idx in range(start_idx, end_idx):
            addr = addrs[idx]
            bb_dict[addr] = disasm[addr]
    else:
        print(f"Entry point {entry} not found in disassembly dict")


    ## TODO: 

    return bb_dict


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} [path to ELF file]")
        return -1
    try:
        with open(sys.argv[1], "rb") as file:
            # read ELF binary
            elf = ELFFile(file)
            
            # Disassemble code section
            disassembly_dict =  disassemble(elf)
            
            # basic block slicing
            basic_block_dict = block_slice(elf, disassembly_dict)

            # print disassemble code
            print("\n--------------------- DISASM ---------------")
            for addr, info in disassembly_dict.items():
                print(f"{addr}\t {info['mnemonic']}\t {info['op_str']}")
            
    
            print("\n--------------------- ENTRY & NEXT 10 INSTRUCTIONS ---------------")
            for addr, info in basic_block_dict.items():
                # Highlight the entry point row for clarity
                print(f"{addr}\t {info['mnemonic']}\t {info['op_str']}")    
            
            # for key in basic_block_dict.keys():
            #    print(f"Key: {key}, Type: {type(key)}")
            
            # print(f"DWARF_INFO: {elf.get_dwarf_info}")
            

            print("\n--------- MAIN -----------")
            sym_table = symbol_table(elf)
            if sym_table is not None:
                main = sym_table.get_symbol_by_name('main')
                if main is not None:
                    print(f"main -> {main[0]['st_value']:#016x}, size -> {main[0]['st_size']}")
                else:
                    print("Main not found")
            else:
                print("Symbol Table  not found")
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
