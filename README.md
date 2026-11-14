# CSC-6580-Project: Team "Hamilton"

## Team Members

- Brian Kemp
- David Pesin
- Rajat Bisht
- Behnjamin Barlow

## Python

* Use Python 3.14.4 or later + type hinting
* External libraries:
  * The Python interface to the [Capstone](https://www.capstone-engine.org/): `sudo apt install python3-capstone`
  * The [pyelftools](https://github.com/eliben/pyelftools): `sudo apt install python3-pyelftools`
* Example 'starter' program that opens an ELF binary using `pyelftools`.

### Installation

Create and activate a Python virtual environment, then install the required dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## P1 – ELF Disassembly

The first project introduced ELF file parsing and x86-64 disassembly using Python.

**Implementation:**

- Accept an ELF executable as a command-line argument.
- Open and parse the ELF file using `pyelftools`.
- Locate and extract the `.text` section.
- Disassemble the instructions in the `.text` section using Capstone.
- Print instruction addresses, mnemonics, and operands.

## P2 – Basic Block Extraction

The second project extended the ELF disassembler to identify and extract basic blocks from executable code.

**Implementation:**

- Locate the ELF executable's entry point.
- Identify the executable section containing the entry point, even if it is not named `.text`.
- Detect standard C runtime startup code that invokes `__libc_start_main` and identify the `main` function when possible.
- Extract basic blocks by following control-flow instructions and discovering additional block leaders.
- Continue extracting reachable basic blocks until no additional blocks are found.
- Support executable code located across multiple ELF sections.
- Follow direct jumps and calls without requiring resolution of indirect calls.
- Print the extracted basic blocks in ascending address order.

## P3 – Structure Theorem and Prime Generation

The third project extended basic block extraction by applying the constructive proof of the Structure Theorem.

**Implementation:**

- Continue identifying the program's starting address and extracting reachable basic blocks.
- Classify basic blocks based on their ending instructions:
  - **Predicate blocks:** Blocks ending in conditional branches, including instructions such as `jg`, `js`, and `loop`.
  - **Function blocks:** All other basic blocks.
- Convert function blocks into sequence primes.
- Convert predicate blocks into `if-then-else` primes.
- Introduce the counter variable `L` to represent the next block address.
- Assign `L := 0x0` when the next address cannot be determined.
- Print the resulting primes in ascending address order.
- Preserve all primes without performing reductions or substitutions.

## P4 – Prime Substitution and Basic Block Restructuring

The fourth project builds on P3 by implementing prime substitution as described in the constructive proof of the Structure Theorem.

**Implementation:**

- Support optional basic block leader addresses supplied through command-line arguments.
- Use the supplied leaders as starting points when provided; otherwise, automatically determine the program's starting address.
- Extract reachable basic blocks from the specified starting points.
- Convert basic blocks into sequence and predicate primes.
- Store primes in an internal structure to support nested substitutions.
- Count references to block addresses through assignments to `L`.
- Substitute primes whose addresses are referenced exactly once.
- Repeat substitutions until no additional substitutions are possible.
- Preserve the initial block and prevent direct self-referencing substitutions.
- Support nested sequence and `if-then-else` primes.
- Preserve loop back-edges without constructing structured loops.
- Print the remaining primes in ascending address order, including nested substitutions.
- Report an error when no valid basic blocks are found.

## Usage

### Run with an ELF executable

```bash
python3 ./main.py /usr/bin/ls
```

### Build the provided assembly test

```bash
nasm -f elf64 block-test-1.asm -o block-test-1.o
gcc -no-pie block-test-1.o -o block-test-1
```

### Run with automatic starting-address detection

```bash
python3 ./main.py ./block-test-1
```

### Run with a specified basic block leader

```bash
python3 ./main.py ./block-test-1 0x401170
```

### Run with multiple basic block leaders

```bash
python3 ./main.py ./block-test-1 0x40113b 0x401170
```

### Save output to a file

```bash
python3 ./main.py /usr/bin/ls > output.txt
```

The program uses `pyelftools` to read ELF information and Capstone to disassemble x86-64 instructions. Basic blocks are discovered through control-flow analysis, converted into primes, and restructured through substitutions before the remaining primes are printed.