#!/usr/bin/env bash
set -e

echo "[-] Generating source files..."

cat << 'EOF' > 00_hello_dynamic.c
#include <stdio.h>
int main() { printf("ELF Dynamic Test\n"); return 0; }
EOF

cat << 'EOF' > 01_hello_static.c
#include <stdio.h>
int main() { printf("ELF Static Test\n"); return 0; }
EOF

cat << 'EOF' > 02_data_bss.c
int global_initialized = 42;
int global_uninitialized;
int main() { return global_initialized + global_uninitialized; }
EOF

cat << 'EOF' > 03_custom_section.c
__attribute__((section(".my_custom_sec"))) int custom_var = 1337;
int main() { return custom_var; }
EOF

cat << 'EOF' > 04_libsample.c
int compute_sum(int a, int b) { return a + b; }
EOF

cat << 'EOF' > 05_hello_stripped.c
#include <stdio.h>
int main() { printf("Stripped ELF\n"); return 0; }
EOF

cat << 'EOF' > 06_constructor_test.c
#include <stdio.h>
__attribute__((constructor)) void before_main() { printf("Constructor\n"); }
__attribute__((destructor)) void after_main() { printf("Destructor\n"); }
int main() { printf("Main function\n"); return 0; }
EOF

cat << 'EOF' > 07_minimal.c
void _start() {
    __asm__ volatile (
        "movq $60, %%rax\n\t"
        "movq $0, %%rdi\n\t"
        "syscall"
        : : : "rax", "rdi"
    );
}
EOF

echo "[+] Done! All 8 source files have been generated."
