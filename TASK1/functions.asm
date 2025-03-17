;----------------------------------------
; void sLen(String message)
; String length calculation function
sLen:
    push ebx
    mov ebx, esi

    nextChar_sLen:
        cmp byte [esi], 0
        jz finished_sLen
        cmp byte [esi], 0xa
        jz finished_sLen
        inc esi
        jmp nextChar_sLen
    
    finished_sLen:
        sub esi, ebx
        pop ebx
        ret

;----------------------------------------
; void sPrint(String message)
; String printing function
; Source: esi
sPrint:
    push eax
    push ebx
    push ecx
    push edx
    
    push esi
    call sLen
    mov edx, esi

    pop esi
    mov ecx, esi
    mov ebx, 1
    mov eax, 4
    int 0x80

    pop edx
    pop ecx
    pop ebx
    pop eax
    ret

;----------------------------------------
; void iPrint(Integer number)
; Integer printing function (itoa)
; Source: eax
iPrint:
    push eax
    push ebx
    push ecx
    push edx
    push esi

    mov ebx, 0  ;sign
    mov ecx, 0

    test eax, eax
    jns divideLoop_iPrint
    mov ebx, 1
    neg eax

    divideLoop_iPrint:
        inc ecx
        mov edx, 0
        mov esi, 10
        idiv esi
        add edx, "0"
        push edx
        cmp eax, 0
        jnz divideLoop_iPrint
    
    pre_printLoop_iPrint:
        cmp ebx, 1
        jne printLoop_iPrint
        push "-"
        inc ecx
    printLoop_iPrint:
        dec ecx
        mov esi, esp
        call sPrint
        pop eax
        cmp ecx, 0
        jnz printLoop_iPrint
    
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax
    ret

;----------------------------------------
; void hexPrint(hex string)
; Hex printing function (%x)
; Source: eax
hexPrint:
    push eax
    push ebx
    push ecx
    push edx
    push esi

    cmp eax, 0xa
    jl exception

    mov ecx, 0
    divideLoop_hexPrint:                ; base convert
        inc ecx
        mov edx, 0
        mov esi, 16
        div esi
        cmp edx, 0xa
        jnl setLetter_hexPrint
        jmp continue
    setLetter_hexPrint:
        add edx, 0x27
    continue:
        add edx, "0"
        push edx
        cmp eax, 0
        jnz divideLoop_hexPrint

    printLoop_hexPrint:
        dec ecx
        mov esi, esp
        call sPrint
        pop eax
        cmp ecx, 0
        jnz printLoop_hexPrint
        jmp end_hexPrint
    

    exception:
        push eax
        mov eax, 0
        call iPrint
        pop eax
        call iPrint
    end_hexPrint:
        pop esi
        pop edx
        pop ecx
        pop ebx
        pop eax
    ret

;----------------------------------------
; void sScan(String message)
; Get the message from output
; Source: esi
sScan:
    push eax
    push ebx
    push ecx
    push edx

    mov edx, 100
    mov ecx, esi
    mov ebx, 0
    mov eax, 3
    int 0x80

    pop edx
    pop ecx 
    pop ebx
    pop eax

    ret

;----------------------------------------
; void exit()
; Exit program and restore resources
quit:
    mov ebx, 0
    mov eax, 1
    int 0x80
    ret