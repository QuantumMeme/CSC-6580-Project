#include <stdio.h>
__attribute__((constructor)) void before_main() { printf("Constructor\n"); }
__attribute__((destructor)) void after_main() { printf("Destructor\n"); }
int main() { printf("Main function\n"); return 0; }
