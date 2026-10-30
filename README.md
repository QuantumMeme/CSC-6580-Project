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

Create a program, written in Python, that operates as follows.
- Require exactly one command line argument that must specify an ELF executable
containing object code.
- Open the given ELF file and locate the entry point by any method. Consider this
the start location.
- Locate the section that contains the start location. It need not be named .text.
- Determine if the program has a "standard" entry point that invokes
__libc_start_main. If it does, change start to the address of the main
function.
- Extract the basic block at start. Identify any basic block leaders as you do, and
then extract those basic blocks. This process of leader discovery and basic block
extraction continues until no further basic blocks are found. Consider only basic
blocks whose location is known and that are within the ELF file.
- Print each basic block once, in ascending order by the first address. Skip a single
blank line between basic blocks.