# CSC-6580-Project: Team "Hamilton"
Team Members: 
* Brian Kemp
* David Pesin
* Rajat Bisht
* Behnjamin Barlow

## Python

* Use Python 3.14.4 or later + type hinting
* External libraries:
  * The Python interface to the [Capstone](https://www.capstone-engine.org/): `sudo apt install python3-capstone`
  * The [pyelftools](https://github.com/eliben/pyelftools): `sudo apt install python3-pyelftools`
* Example 'starter' program that opens an ELF binary using `pyelftools`.

```py
#!/usr/bin/env python3
# Example to open an ELF file.

import sys
from elftools.elf.elffile import ELFFile, ELFError

def error(msg) -> None:
    # Print an error message
    print(f"ERROR: {msg}")

def open_elf(path:str) -> None:
    # open the given file as an ELF file and report some info
    with open(path, "rb") as file:
        elf = ELFFile(file)
        ## Do something with the file
def main() -> int:
    # Entry point when run from the prompt
    # The only argument should be the path to the ELF file.
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} [Path to ELF file]") 
        return 0
    
    try:
        open_elf(argv[1])
        return 0
    except FileNotFoundError:
        error(f"File not found ({sys.argv[1]})")
    except IsADirectoryError:
        error(f"Provided path is a directory")
    except PermissionError:
        error(f"Cannot read file")
    except ELFError as err:
        error(f"Invalid ELF file: {err}")
    return -1

if __name__ == "__main__":
    sys.exit(main())

```

## First Assignment
Requirements:

* Exactly one command line argument specifying an ELF executable containing object code (example above)
* open(ELF-file) -> locate and extract `.text` section. (if not found, issue an error message using `pyelftools`, and stop)
* Print a disassembly of code in `.text` section (using Capstone).
* Example execution:
```sh
$ ./main.py hello | head -10
0x0000000000001050: endbr64
0x0000000000001054: xor ebp, ebp
0x0000000000001056: mov r9, rdx
0x0000000000001059: pop rsi
0x000000000000105a: mov rdx, rsp
0x000000000000105d: and rsp, 0xfffffffffffffff0
0x0000000000001061: push rax
0x0000000000001062: push rsp
0x0000000000001063: lea r8, [rip + 0x166]
0x000000000000106a: lea rcx, [rip + 0xef]

$ objdump -d -Mintel -j.text --no-show-raw-insn hello | head -17
hello-main: file format elf64-x86-64
Disassembly of section .text:
0000000000001050 <_start>:
1050: endbr64
1054: xor ebp,ebp
1056: mov r9,rdx
1059: pop rsi
105a: mov rdx,rsp
105d: and rsp,0xfffffffffffffff0
1061: push rax
1062: push rsp
1063: lea r8,[rip+0x166] # 11d0 <__libc_csu_fini>
106a: lea rcx,[rip+0xef] # 1160 <__libc_csu_init>
```

## Second Assignment

Requirements:

* Exactly one command line argument specifying an ELF executable containing object code.
* Open the ELF file and locate its entry point.
* Identify the section containing the entry point. The section does not have to be named `.text`.
* If the executable uses the standard C runtime startup sequence that invokes `__libc_start_main`, identify the address of the `main` function and use it as the starting address.
* Extract basic blocks using Capstone, identifying new basic block leaders through control-flow instructions.
* Continue discovering basic blocks until no additional reachable blocks are found.
* Support basic blocks located in different executable sections.
* Follow direct jumps and calls. Resolving indirect calls is not required.
* Print each basic block once, sorted in ascending order by its starting address.
* Separate basic blocks with a single blank line.

### Installation

Install the required Python dependencies using `requirements.txt`:

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Example Execution

Run the program against an ELF executable:

```sh
python3 ./main.py /usr/bin/ls
```

To save the output to a file:

```sh
python3 ./main.py /usr/bin/ls > output.txt
```

Example output:

```text
0x46b0: endbr64
0x46b4: jmp qword ptr [rip + 0x1e8d6]

0x46c0: endbr64
0x46c4: jmp qword ptr [rip + 0x1e8ee]

0x46d0: endbr64
0x46d4: jmp qword ptr [rip + 0x1e8fe]
```

The program uses `pyelftools` to read ELF information and Capstone to disassemble x86-64 instructions. Basic blocks are discovered by following control flow and are printed in ascending address order.