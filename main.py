#!/usr/bin/env python3

import sys

from capstone import CS_ARCH_X86, CS_MODE_64, Cs, CsInsn, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86 import X86_INS_JMP, X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile, ELFError
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from typing import Dict, List, Optional, Tuple


# instruction groups that end blocks (calls return, so they don't)
BLOCK_TERMS = [CS_GRP_JUMP, CS_GRP_RET]

# functions that never return, so calling one does end the block
NORETURN = ["__libc_start_main", "exit", "_exit", "_Exit", "abort",
            "__stack_chk_fail", "__assert_fail", "__fortify_fail",
            "__chk_fail", "err", "errx", "pthread_exit", "longjmp",
            "__cxa_throw", "_Unwind_Resume"]

def error(msg) -> None:
    """Print an error message."""
    print(f"ERROR: {msg}")


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


def get_target(insn: CsInsn) -> Optional[int]:
    """Where a call or jump goes: an address, a [rip + X] slot, or None if unknown (e.g. jmp rax)."""
    op = insn.operands[0] if insn.operands else None
    if op and op.type == X86_OP_IMM:
        return op.imm
    if op and op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
        return insn.address + insn.size + op.mem.disp # rip relative is from the next instruction
    return None


def get_l(insn: CsInsn):
    """
    What the last instruction of a block sets L to.
    (then, else) for predicates, one address for functions. 0 when unknown.
    """
    next_address: int = insn.address + insn.size
    target: int = get_target(insn) or 0

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


class Disassembler:
    """Basic blocks of an ELF file, starting from main."""

    def __init__(self, elf: ELFFile):
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)  # Capstone object(architecture, mode)
        self.md.detail = True

        self.entrypoint: int = elf.header["e_entry"]
        self.start: int = self.entrypoint
        self.sections: List[Tuple[int, bytes]] = [] # executable (addr, data)
        self.names: Dict[int, str] = {} # address -> function name
        self.leaders: set = set()
        self.block_list: List[Tuple[int, List[CsInsn]]] = []

        plt_sections: List[Tuple[int, bytes]] = []
        for section in elf.iter_sections():
            if section["sh_flags"] & SH_FLAGS.SHF_EXECINSTR and section["sh_type"] != "SHT_NOBITS":
                self.sections.append((section["sh_addr"], section.data()))
                if section.name.startswith(".plt"): # .plt, .plt.sec, .plt.got
                    plt_sections.append(self.sections[-1])

            # function symbols (static and unstripped binaries)
            elif isinstance(section, SymbolTableSection):
                for sym in section.iter_symbols():
                    if sym.name and sym["st_value"] and sym["st_info"]["type"] in ("STT_FUNC", "STT_GNU_IFUNC"):
                        name = sym.name.split("@")[0] # strip "@GLIBC_2.34"

                        if name in NORETURN or sym["st_value"] not in self.names:
                            self.names[sym["st_value"]] = name

            # relocations name the GOT slots, and they survive stripping
            elif isinstance(section, RelocationSection) and section["sh_link"]:
                symtab = elf.get_section(section["sh_link"])
                if not isinstance(symtab, SymbolTableSection):
                    continue
                for rel in section.iter_relocations():
                    if rel["r_info_sym"]: # 0 means no symbol
                        sym = symtab.get_symbol(rel["r_info_sym"])
                        if sym.name:
                            self.names.setdefault(rel["r_offset"], sym.name.split("@")[0])

        if not self.find_section(self.entrypoint):
            raise ELFError("No entrypoint found.")

        self.name_plt_stubs(plt_sections)

    def find_section(self, address: int) -> Optional[Tuple[int, bytes]]:
        """Return the (addr, data) section containing address, or None."""
        for addr, data in self.sections:
            if addr <= address < (addr + len(data)):
                return addr, data
        return None

    def decode(self, address: int) -> Optional[CsInsn]:
        """Disassemble the one instruction at address, or None."""
        section = self.find_section(address)
        if not section:
            return None

        offset: int = address - section[0]
        chunk = section[1][offset:offset + 15] # x86 instructions are 15b

        insns = list(self.md.disasm(chunk, address, count=1))
        return insns[0] if insns else None

    def name_plt_stubs(self, plt_sections: List[Tuple[int, bytes]]) -> None:
        """PLT stubs ([endbr64] jmp [rip + X]) get the name of the GOT slot they jump through."""
        for addr, data in plt_sections:
            address: int = addr
            prev: Optional[CsInsn] = None
            while address < addr + len(data):
                insn = self.decode(address)
                if not insn:
                    address += 1
                    prev = None
                    continue

                if insn.id == X86_INS_JMP and insn.operands[0].type == X86_OP_MEM and get_target(insn) in self.names:
                    stub = prev.address if prev and prev.mnemonic == "endbr64" else insn.address
                    self.names.setdefault(stub, self.names[get_target(insn)])

                prev = insn
                address += insn.size

    def is_noreturn(self, insn: CsInsn) -> bool:
        """True if insn calls a function that never returns."""
        return CS_GRP_CALL in insn.groups and self.names.get(get_target(insn)) in NORETURN

    def get_block(self, address: int, noreturn: bool = True) -> List[CsInsn]:
        """Disassemble from address until a block terminator, a call that never returns, or the next leader."""
        block: List[CsInsn] = []
        while True:
            insn = self.decode(address)
            if not insn:
                break
            block.append(insn)

            address += insn.size
            if ends_block(insn) or (noreturn and self.is_noreturn(insn)) or address in self.leaders:
                break
        return block

    def find_start(self) -> int:
        """Start at main if _start is the standard: rdi = main, call __libc_start_main, hlt."""
        rdi: Optional[int] = None
        entry_block = self.get_block(self.entrypoint, noreturn=False) # don't stop before the hlt
        for i, insn in enumerate(entry_block):
            if CS_GRP_CALL in insn.groups:
                if i + 1 < len(entry_block) and entry_block[i + 1].mnemonic == "hlt" and rdi and self.find_section(rdi):
                    self.start = rdi
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
        return self.start

    def find_blocks(self) -> List[Tuple[int, List[CsInsn]]]:
        """Extract blocks from start and find leaders until no new ones show up."""
        self.leaders = {self.start}
        work: List[int] = [self.start]
        while work:
            for insn in self.get_block(work.pop()):
                for leader in get_leaders(insn):
                    # only leaders inside the ELF's code
                    if leader not in self.leaders and self.find_section(leader):
                        self.leaders.add(leader)
                        work.append(leader)

        # a leader found later can split an earlier block, so build them all again
        self.block_list = []
        for leader in self.leaders:
            block = self.get_block(leader)
            if block:
                self.block_list.append((leader, block))

        self.block_list.sort()
        return self.block_list

    def print_blocks(self) -> None:
        """Print each block and what it sets L to (if/then/else when it ends in a conditional)."""
        for n, i in enumerate(self.block_list):
            if n:
                print()

            last = i[1][-1]
            l = 0 if self.is_noreturn(last) else get_l(last) # nothing comes after
            if isinstance(l, tuple): # ends in a conditional -> if/then/else
                print("if")
                for j in i[1]:
                    print(f"\t0x{j.address:x}:\t{j.mnemonic}\t{j.op_str}".rstrip())
                print(f"then\n\tL := 0x{l[0]:x}\nelse\n\tL := 0x{l[1]:x}\nfi")
            else: # otherwise -> instructions, then L
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
            disassembler = Disassembler(elf)
            
        disassembler.find_start()
        disassembler.find_blocks()
        disassembler.print_blocks()
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
