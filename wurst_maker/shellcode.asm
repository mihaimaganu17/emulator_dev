section .text

struc UNICODE_STRING
    .length: resw 1
    .max_length: resw 1
    .padding: resb 4
    .ptr: resq 1
endstruc

struc OBJECT_ATTRIBUTES
    .length: resd 1
    ; All object on windows x64 are 8-byte aligned
    .padding: resd 1
    .root_directory: resq 1
    .object_name: resq 1
    .attributes: resd 1
    .padding1: resd 1
    .security_desc: resq 1
    .security_qos: resq 1
endstruc

; "AA"
foop: db 0x41, 0x00, 0x41, 0x00

global shellcode
shellcode:
    ; Make a struct containing local values
    struc locals
        ; Output Handle(Pointer to memory) from `NtCreateFile()`
        .handle: resq 1
        .iosb: resq 2
        .objattr: resb OBJECT_ATTRIBUTES_size
        .allocation_size: resq 1
        .filename: resb UNICODE_STRING_size
    endstruc

    ; Make some space on the stack
    sub rsp, 0x100

    ; Calling convention Win10 x64
    ; rcx (r10)     - 1st arg
    ; rdx           - 2nd arg
    ; r8            - 3rd arg
    ; r9            - 4rth arg
    ; [rsp + 0x20]  - 5th arg+

    ; Get the pointer to the data stored in foop for filename
    lea rax, [rel foop]

    ; Populate the UNICODE_STRING structure
    mov word [rsp + locals.filename + UNICODE_STRING.length], 4
    mov word [rsp + locals.filename + UNICODE_STRING.max_length], 4
    mov qword [rsp + locals.filename + UNICODE_STRING.ptr], rax

    ; Put the address for the filename structure in rax
    lea rax, [rsp + locals.filename]

    ; Populate the OJBECT_ATTRIBUTES structure
    mov dword [rsp + locals.objattr + OBJECT_ATTRIBUTES.length], OBJECT_ATTRIBUTES_size
    mov qword [rsp + locals.objattr + OBJECT_ATTRIBUTES.root_directory], 0
    mov qword [rsp + locals.objattr + OBJECT_ATTRIBUTES.object_name], rax
    mov dword [rsp + locals.objattr + OBJECT_ATTRIBUTES.attributes], 0
    mov qword [rsp + locals.objattr + OBJECT_ATTRIBUTES.security_desc], 0
    mov qword [rsp + locals.objattr + OBJECT_ATTRIBUTES.security_qos], 0

    mov qword [rsp + locals.allocation_size], 0
    ;int3

    mov rbp, rsp

    ; Make more space on the stack
    sub rsp, 0x58
    ; Put the first parameter in r10
    lea r10, [rbp + locals.handle]
    ; Pass the DesiredAcess(FILE_GENERIC_WRITE)
    mov rdx, 0x120116
    ; Pass ObjectAttributes
    lea r8, [rbp + locals.objattr]
    ; Pass IoStatusBlock
    lea r9, [rbp + locals.iosb]
    ; Pass AllocationSize
    lea rax, [rbp + locals.allocation_size]
    mov qword [rsp + 0x20], rax
    ; FileAttributes (FILE_ATTRIBUTES_NORMAL)
    mov qword [rsp + 0x28], 0x80
    ; ShareAccess
    mov qword [rsp + 0x30], 0
    ; CreateDisposition (FILE_CREATE)
    mov qword [rsp + 0x38], 2
    ; CreateOptions
    mov qword [rsp + 0x40], 0
    ; EaBuffer
    mov qword [rsp + 0x48], 0
    ; EaLength
    mov qword [rsp + 0x50], 0

    ; Call NtCreateFile
    mov eax, 0x55
    syscall

    int3

    ;int3

    ; Call ZwTerminateProcess(GetCurrentProcess(), 0x13371337)
    ; Put the first parameter in r10 (Handle to process we want to exit)
    ; We use all f's because it is a shortcut for the current process
    mov r10, ~0
    ; Put the second argument in rdx
    mov rdx, 0x13371337

    ; Provide the necessary syscall
    mov eax, 0x2c
    syscall

    add rsp, 0x100
