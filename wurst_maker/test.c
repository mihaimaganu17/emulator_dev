#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <windows.h>
#include <Winternl.h>

int main(void)
{
    void *buff = calloc(1, 32 * 1024);
    if (!buff) {
        perror("malloc() error ");
        return -1;
    }

    FILE *fd = fopen("shellcode.bin", "rb");
    if (!fd) {
        perror("fopen() error ");
        return -1;
    }
    intptr_t bread = fread(buff, 1, 32 * 1024, fd);
    if(bread <= 0) {
        perror("fread() error ");
        return -1;
    }

    printf("Shellcode is %zd bytes\n", bread);

    void *addr = VirtualAllocEx(
            GetCurrentProcess(), NULL, 4096, MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

    printf("%p\n", addr);
    return 0;
}
