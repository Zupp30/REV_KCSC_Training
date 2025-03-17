section .data
    caption db "API_Resolve_ASM", 0
    message db "Hello from API_Resolve_ASM", 0

section .text
    global main
    extern MessageBoxA
    extern ExitProcess

main:
    ; Set up the stack frame
    sub rsp, 0x28

    mov rcx, 0
    mov rdx, message
    mov r8, caption
    mov r9d, 0
    call MessageBoxA

    mov ecx, 0
    call ExitProcess