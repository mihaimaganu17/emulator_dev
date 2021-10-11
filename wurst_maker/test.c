#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include <Winternl.h>

extern uint64_t shellcode();

typedef OBJECT_ATTRIBUTES *POBJ_ATTR;

int main(void)
{
    printf("%d\n", FILE_ATTRIBUTE_NORMAL);
    fflush(stdout);
    printf("0x%I64x\n", shellcode());
    return 0;
}
