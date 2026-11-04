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
