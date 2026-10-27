void _start() {
    __asm__ volatile (
        "movq $60, %%rax\n\t"
        "movq $0, %%rdi\n\t"
        "syscall"
        : : : "rax", "rdi"
    );
}
