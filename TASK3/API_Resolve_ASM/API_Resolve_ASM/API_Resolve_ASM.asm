.386
.model flat, stdcall
.stack 4096
assume fs:nothing

.data
    loadLibraryA BYTE "LoadLibraryA", 0
    messageBoxA BYTE "MessageBoxA", 0
    user32 BYTE "user32.dll", 0

    caption BYTE "API_Resolve_ASM", 0
    msg BYTE "Hello from API_Resolve_ASM", 0
    MB_OK EQU 0

.code
main PROC
    push ebp
    mov ebp, esp

    sub esp, 24h                      ; Reserve space for local variables
    xor eax, eax
    
    mov [ebp - 04h], eax              ; Export functions
    mov [ebp - 08h], eax              ; Export address table (EAT)
    mov [ebp - 0Ch], eax              ; Export name table
    mov [ebp - 10h], eax              ; Export ordinal table
    mov [ebp - 14h], eax              ; Null terminated string "GetProcAddress"
    mov [ebp - 18h], eax              ; Address to the function "GetProcAddress"
    mov [ebp - 1Ch], eax              ; Reserved1 -> LoadLibraryA
    mov [ebp - 20h], eax              ; Reserved2 -> user32.dll
    mov [ebp - 24h], eax              ; Reserved3 -> MessageBoxA

    ; Push "GetProcAddress" to the stack
    push 00007373h				  ; "ss\0\0"
    push 65726464h				  ; "erdd"
    push 41636f72h				  ; "Acor"
    push 50746547h				  ; "PteG"
    mov [ebp - 14h], esp          ; pointer to "GetProcAddress"

    ; Get the address of the kernel32.dll
    mov eax, [fs:30h]               ; PEB
    mov eax, [eax + 0Ch]            ; Ldr
    mov eax, [eax + 14h]            ; InMemoryOrderModuleList
    mov eax, [eax]	                ; this program's module
    mov eax, [eax]  	            ; ntdll module
	mov eax, [eax + 10h]	        ; kernel32.dll
    mov ebx, eax                    ; Save in ebx
    
    ; Get address of PE signature
    mov eax, [eax + 3Ch]            ; e_lfanew
    add eax, ebx

    ; Get the address of the Export Table
    mov eax, [eax + 78h]            
    add eax, ebx

    ; Get number of exported functions
    mov ecx, [eax + 14h]
    mov [ebp - 04h], ecx
    
    ; Get the address of the Export Address Table (EAT)
    mov ecx, [eax + 1Ch]            ; RVA of EAT
    add ecx, ebx
    mov [ebp - 08h], ecx

    ; Get the address of the Export Name Table
    mov ecx, [eax + 20h]            ; RVA of ENT
    add ecx, ebx
    mov [ebp - 0Ch], ecx
    
    ; Get the address of the Export Ordinal Table
    mov ecx, [eax + 24h]            ; RVA of EOT
    add ecx, ebx
    mov [ebp - 10h], ecx

    ; Loop through the export name table
    xor eax, eax
    xor ecx, ecx

    findGetProcAddressPosition:
        mov esi, [ebp - 14h]
        mov edi, [ebp - 0Ch]
        cld
        mov edi, [edi + eax * 4]    ; get RVA of next function name
        add edi, ebx                ; get VA of next function name

        mov cx, 0Dh				    ; length of "GetProcAddress"
        repe cmpsb                  ; compare "GetProcAddress" with the current function name

        jz functionFound
        inc eax
        cmp eax, [ebp - 04h]        ; check if reaching the end of the export name table
        jne findGetProcAddressPosition

    functionFound:
        mov ecx, [ebp - 10h]        ; ecx = ordinal table
        mov edx, [ebp - 08h]        ; edx = EAT

        ; Get address of GetProcAddress ordinal
        mov ax, [ecx + eax * 2]     ; get ordinal
        mov eax, [edx + eax * 4]    ; get RVA
        add eax, ebx                ; get VA

        jmp invokeGetProcAddress

    invokeGetProcAddress:
        mov [ebp - 18h], eax        ; save the address of GetProcAddress
    
        ; Get address of LoadLibraryA
        push offset loadLibraryA
        push ebx                    ; kernel32.dll base address
        call eax                    ; call GetProcAddress
        test eax, eax               ; check if GetProcAddress succeeded
        jz error_exit
        mov [ebp - 1Ch], eax        ; save the address of LoadLibraryA
    
        ; Load user32.dll
        push offset user32
        call dword ptr [ebp - 1Ch]  ; call LoadLibraryA
        test eax, eax               ; check if LoadLibraryA succeeded
        jz error_exit
        mov [ebp - 20h], eax        ; save the address of user32.dll
    
        ; Get address of MessageBoxA
        push offset messageBoxA
        push dword ptr [ebp - 20h]  ; user32.dll base address
        call dword ptr [ebp - 18h]  ; call GetProcAddress
        test eax, eax               ; check if GetProcAddress succeeded
        jz error_exit
        mov [ebp - 24h], eax        ; save the address of MessageBoxA
    
        ; Call MessageBoxA
        push MB_OK
        push offset caption
        push offset msg
        push 0
        call dword ptr [ebp - 24h]  ; call MessageBoxA
    
        ; Normal exit
        add esp, 24h + 4h           ; 24h for local variables, 4h for the "GetProcAddress"
        mov esp, ebp
        pop ebp
        ret

    error_exit:
main ENDP
END main