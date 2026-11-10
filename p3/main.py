#!/usr/bin/env python3
"""CSC 6580 Project, Assignment 3.

Find the program start (main when the entry point follows the standard
__libc_start_main pattern), discover every reachable basic block, and print
each block as a Structure Theorem prime that sets the counter L.
"""

import struct
import sys
from dataclasses import dataclass, field

from capstone import CS_ARCH_X86, CS_MODE_64, Cs, CsError, CsInsn
from capstone import x86_const as x86
from elftools.common.exceptions import ELFError
from elftools.elf.constants import P_FLAGS, SH_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

# Longest possible x86 instruction; used to bound each single-instruction decode.
MAX_INSN_LEN = 15

# Instructions that end a block and are conditional (two successors).
# The loop family is deliberately left out: the assignment's sample output for
# block_test keeps "loop" inside its block and adds no leaders for it.
COND_IDS = {x86.X86_INS_JRCXZ, x86.X86_INS_JECXZ, x86.X86_INS_JCXZ}
# Instructions that end a block with no fall-through successor.
UNCOND_JMP_IDS = {x86.X86_INS_JMP, x86.X86_INS_LJMP}
STOP_IDS = {x86.X86_INS_HLT, x86.X86_INS_UD2, x86.X86_INS_UD1, x86.X86_INS_UD0}


def error(msg: str) -> None:
    """Print an error message."""
    print(f"ERROR: {msg}")


@dataclass
class Region:
    """A run of executable bytes loaded at a virtual address."""

    name: str
    start: int
    data: bytes

    @property
    def end(self) -> int:
        """First address past the region."""
        return self.start + len(self.data)

    def contains(self, addr: int) -> bool:
        """True when addr lies inside this region."""
        return self.start <= addr < self.end


@dataclass
class Block:
    """A basic block: its instructions and how control leaves it."""

    leader: int
    insns: list[CsInsn] = field(default_factory=list)
    # "pred" for a conditional ending, "func" otherwise.
    kind: str = "func"
    # For a function: the next L. For a predicate: the taken target.
    target: int = 0
    # For a predicate: the fall-through address.
    fallthrough: int = 0


class Program:
    """An ELF executable plus the helpers needed to decode and analyze it."""

    def __init__(self, elf: ELFFile) -> None:
        if elf.get_machine_arch() != "x64":
            raise ELFError(f"unsupported architecture {elf.get_machine_arch()}")
        self.elf = elf
        self.regions = self._exec_regions()
        if not self.regions:
            raise ELFError("no executable code found")
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        # Map GOT slot address -> symbol name, for recognizing __libc_start_main
        # in stripped binaries (dynamic relocations survive stripping).
        self.got_syms, self.relative = self._relocations()

    # ----- ELF layout -------------------------------------------------------

    def _exec_regions(self) -> list[Region]:
        """Collect executable sections; fall back to executable segments if the
        file has no section headers. NOBITS sections have no bytes and are skipped."""
        regions = [
            Region(sec.name, sec["sh_addr"], sec.data())
            for sec in self.elf.iter_sections()
            if sec["sh_flags"] & SH_FLAGS.SHF_EXECINSTR
            and sec["sh_type"] != "SHT_NOBITS" and sec["sh_addr"]
        ]
        if not regions:
            regions = [
                Region(f"segment@{seg['p_vaddr']:#x}", seg["p_vaddr"],
                       seg.data()[: seg["p_filesz"]])
                for seg in self.elf.iter_segments()
                if seg["p_type"] == "PT_LOAD" and seg["p_flags"] & P_FLAGS.PF_X
            ]
        return regions

    def _relocations(self) -> tuple[dict[int, str], dict[int, int]]:
        """Return (slot -> symbol name) for symbol relocations and
        (slot -> addend) for R_X86_64_RELATIVE relocations."""
        named: dict[int, str] = {}
        relative: dict[int, int] = {}
        for sec in self.elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            symtab = (self.elf.get_section(sec["sh_link"])
                      if sec["sh_link"] else None)
            for rel in sec.iter_relocations():
                rtype = rel["r_info_type"]
                if rtype == 8 and rel.is_RELA():  # R_X86_64_RELATIVE
                    relative[rel["r_offset"]] = rel["r_addend"]
                elif rel["r_info_sym"] and isinstance(symtab, SymbolTableSection):
                    named[rel["r_offset"]] = symtab.get_symbol(rel["r_info_sym"]).name
        return named, relative

    def region_of(self, addr: int) -> Region | None:
        """The executable region holding addr, if any."""
        for region in self.regions:
            if region.contains(addr):
                return region
        return None

    def read_qword(self, addr: int) -> int | None:
        """Read the 8-byte value stored at addr in the file image (honoring
        RELATIVE relocations for PIE). Returns None if it cannot be read."""
        if addr in self.relative:
            return self.relative[addr]
        for seg in self.elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            off = addr - seg["p_vaddr"]
            if 0 <= off and off + 8 <= seg["p_filesz"]:
                return struct.unpack("<Q", seg.data()[off:off + 8])[0]
        return None

    # ----- decoding ---------------------------------------------------------

    def decode(self, addr: int) -> CsInsn | None:
        """Decode the single instruction at addr, or None if it is outside
        executable code or is not a valid instruction."""
        region = self.region_of(addr)
        if region is None:
            return None
        off = addr - region.start
        try:
            return next(self.md.disasm(region.data[off:off + MAX_INSN_LEN], addr, 1),
                        None)
        except CsError:
            return None

    @staticmethod
    def imm_target(insn: CsInsn) -> int | None:
        """Direct (immediate) target of a branch/call, else None."""
        ops = insn.operands
        if len(ops) == 1 and ops[0].type == x86.X86_OP_IMM:
            return ops[0].imm & 0xFFFFFFFFFFFFFFFF
        return None

    @staticmethod
    def rip_mem(insn: CsInsn) -> int | None:
        """Effective address of a [rip + disp] operand, else None."""
        for op in insn.operands:
            if (op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_RIP
                    and op.mem.index == 0):
                return (insn.address + insn.size + op.mem.disp) & 0xFFFFFFFFFFFFFFFF
        return None

    # ----- start location ---------------------------------------------------

    def find_start(self) -> int:
        """Start at the entry point; if the entry block is the standard
        _start that hands main (in rdi) to __libc_start_main, return main."""
        entry = self.elf.header["e_entry"]
        if self.region_of(entry) is None:
            raise ELFError(f"entry point {entry:#x} is not in executable code")
        rdi: int | None = None
        addr = entry
        while (insn := self.decode(addr)) is not None:
            rdi = self._track_rdi(insn, rdi)
            if insn.id == x86.X86_INS_CALL:
                nxt = self.decode(insn.address + insn.size)
                if self._is_libc_start_main(insn) or (
                        nxt is not None and nxt.id == x86.X86_INS_HLT):
                    if rdi is not None and self.region_of(rdi) is not None:
                        return rdi
                break
            if self._ends_block(insn):
                break
            addr += insn.size
        return entry

    def _track_rdi(self, insn: CsInsn, rdi: int | None) -> int | None:
        """Follow the value placed in rdi/edi by simple constant loads."""
        ops = insn.operands
        if not ops or ops[0].type != x86.X86_OP_REG or ops[0].reg not in (
                x86.X86_REG_RDI, x86.X86_REG_EDI):
            return rdi
        if insn.id == x86.X86_INS_LEA:
            return self.rip_mem(insn)
        if insn.id == x86.X86_INS_MOV and len(ops) == 2:
            if ops[1].type == x86.X86_OP_IMM:
                return ops[1].imm & 0xFFFFFFFFFFFFFFFF
            slot = self.rip_mem(insn)
            if slot is not None:
                return self.read_qword(slot)
        return None

    def _is_libc_start_main(self, insn: CsInsn) -> bool:
        """True when a call goes (via GOT slot or PLT stub) to __libc_start_main."""
        slot = self.rip_mem(insn)
        target = self.imm_target(insn)
        if slot is None and target is not None:
            stub = self.decode(target)  # PLT stub: jmp [rip + x]
            if stub is not None and stub.id in UNCOND_JMP_IDS:
                slot = self.rip_mem(stub)
        return slot is not None and self.got_syms.get(slot, "").startswith(
            "__libc_start_main")

    @staticmethod
    def _ends_block(insn: CsInsn) -> bool:
        """True for any instruction that ends a basic block."""
        return (insn.id in COND_IDS or insn.id in UNCOND_JMP_IDS
                or insn.id in STOP_IDS or insn.group(x86.X86_GRP_JUMP)
                or insn.group(x86.X86_GRP_RET) or insn.group(x86.X86_GRP_IRET))

    # ----- block discovery --------------------------------------------------

    def is_conditional(self, insn: CsInsn) -> bool:
        """True for jcc and jrcxz-style branches (Capstone's jump group,
        minus unconditional jmp)."""
        return insn.id in COND_IDS or (
            insn.group(x86.X86_GRP_JUMP) and insn.id not in UNCOND_JMP_IDS)

    def find_leaders(self, start: int) -> set[int]:
        """Worklist search: decode from each leader to the end of its block,
        adding branch/call targets and fall-throughs that land in executable
        code. Runs until no new leaders appear."""
        leaders = {start}
        work = [start]
        while work:
            addr = work.pop()
            found: list[int] = []
            while (insn := self.decode(addr)) is not None:
                nxt = insn.address + insn.size
                target = self.imm_target(insn)
                if insn.id == x86.X86_INS_CALL and target is not None:
                    found.append(target)
                if self.is_conditional(insn):
                    found += [t for t in (target, nxt) if t is not None]
                    break
                if insn.id in UNCOND_JMP_IDS:
                    if target is not None:
                        found.append(target)
                    break
                if self._ends_block(insn):
                    break
                addr = nxt
            for leader in found:
                if leader not in leaders and self.region_of(leader) is not None:
                    leaders.add(leader)
                    work.append(leader)
        return leaders

    def build_block(self, leader: int, leaders: set[int]) -> Block:
        """Decode one block from its leader, stopping at a block-ending
        instruction or just before the next leader (an implicit fall-through).
        Any unknown successor (ret, hlt, indirect jump, bad bytes) is L = 0."""
        block = Block(leader)
        addr = leader
        while (insn := self.decode(addr)) is not None:
            block.insns.append(insn)
            nxt = insn.address + insn.size
            target = self.imm_target(insn)
            if self.is_conditional(insn):
                block.kind = "pred"
                block.target = target or 0
                block.fallthrough = nxt
                return block
            if insn.id in UNCOND_JMP_IDS:
                # A jump through a [rip + x] slot reports the slot address.
                block.target = target if target is not None else (self.rip_mem(insn) or 0)
                return block
            if self._ends_block(insn):
                return block
            if nxt in leaders:
                block.target = nxt
                return block
            addr = nxt
        return block  # Ran into undecodable bytes or left executable code.


def format_block(block: Block) -> str:
    """Render a block as a sequence prime or an if-then-else prime."""
    # Columns are tab-separated to line up like the assignment's sample output.
    body = [f"{i.address:#x}:\t{i.mnemonic}\t{i.op_str}".rstrip() for i in block.insns]
    if block.kind == "pred":
        ind = "    "
        return "\n".join(["if", *(ind + line for line in body), "then",
                          f"{ind}L := {block.target:#x}", "else",
                          f"{ind}L := {block.fallthrough:#x}", "fi"])
    return "\n".join([*body, f"L := {block.target:#x}"])


def analyze(path: str) -> None:
    """Open the ELF file, find the start, discover blocks, and print primes."""
    with open(path, "rb") as file:
        program = Program(ELFFile(file))
        start = program.find_start()
        leaders = program.find_leaders(start)
        # Primes are printed in address order, separated by blank lines.
        primes = [format_block(b) for b in
                  (program.build_block(l, leaders) for l in sorted(leaders)) if b.insns]
        print("\n\n".join(primes))


def main() -> int:
    """Entry point when run from the prompt. The only argument should be the
    path to the ELF file."""
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} [path to ELF file]")
        return 0
    try:
        analyze(sys.argv[1])
        return 0
    except FileNotFoundError:
        error(f"File not found ({sys.argv[1]})")
    except IsADirectoryError:
        error("Provided path is a directory")
    except PermissionError:
        error("Cannot read file")
    except ELFError as err:
        error(f"Invalid ELF file: {err}")
    except BrokenPipeError:
        # Output was piped into something like head that exited early.
        sys.stdout = None  # type: ignore[assignment]
        return 0
    except (OSError, ValueError, MemoryError, struct.error,
            KeyError, IndexError, TypeError, AttributeError) as err:
        # Corrupt headers make pyelftools seek or allocate nonsense sizes.
        error(f"Invalid or corrupt ELF file: {type(err).__name__}: {err}")
    return -1


if __name__ == "__main__":
    sys.exit(main())
