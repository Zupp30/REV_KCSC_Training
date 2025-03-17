global _start
%include "./functions.asm"

section .bss
    pt: resb 255
    key: resb 255
    keystream: resb 255
    ct: resb 255
    S_array: times 256 resb 1

section .data
    format_Pt: db "Plaintext: ", 0
    format_Key: db "Key: ", 0
    ; space: db " ", 0

section .text
_start:
    push key
    push pt
    call getInput   ; getInput(pt, key)
    add esp, 0x8

    push key
    call KSA        ; KSA(key)
    add esp, 0x4

    push keystream
    push pt
    call PRGA       ; PRGA(pt, keystream)
    add esp, 0x8

    push ct
    push keystream
    push pt
    call xoring     ; xoring(pt, keystream, ct)
    add esp, 0xc

    push ct
    call showOutput ; showOutput(ct)
    add esp, 0x4

    call quit
    
    
getInput:
    push ebp
    mov ebp, esp
    push esi

    lea esi, [format_Pt]
    call sPrint             ; Print "Plaintext: "
    mov esi, [ebp + 0x8]
    call sScan              ; Get the plaintext

    lea esi, [format_Key]
    call sPrint             ; Print "Key: "
    mov esi, [ebp + 0xc]
    call sScan              ; Get the key

    pop esi
    mov esp, ebp
    pop ebp
ret

mod_EBX: ;(a) -> a % EBX
        ;[ret]   ;[ret]
        ;[a]     ;[a % EBX]
    push ebp
    mov ebp, esp
    push eax
    push edx

    ; Code:
    mov eax, [ebp + 0x8]
    xor edx, edx
    div ebx
    mov [ebp + 0x8], edx

    pop edx
    pop eax
    mov esp, ebp
    pop ebp
ret

swap_ESI_ECX: ;(S[ESI], S[ECX]) -> (S[ECX], S[ESI])
    push eax
    push edx

    mov al, [S_array + esi]
    mov dl, [S_array + ecx]
    mov [S_array + esi], dl
    mov [S_array + ecx], al

    pop edx
    pop eax
ret

KSA:
    push ebp
    mov ebp, esp
    sub esp, 0x4

    push eax
    push ebx
    push ecx
    push edx
    push esi

    mov eax, [ebp + 0x8]        ; eax = key
    mov esi, eax
    call sLen
    mov [ebp - 0x4], esi
    ; mov ebx, esi                ; ebx = len(key)
    
    xor esi, esi
    init_S:                     ; S = [i for i in range(256)]
        mov [S_array + esi], esi
        inc esi
        cmp esi, 256
        jnz init_S

    xor esi, esi                ; esi = i = 0
    xor ecx, ecx                ; ecx = j = 0
    start_KSA:
        add cl, [S_array + esi] ; j += S[i]
        push esi
        mov ebx, [ebp - 0x4]     ; ebx = key_len
        call mod_EBX
        pop edx                 ; edx = i%key_len
        add cl, [eax + edx]     ; j += key[edx]

        and cl, 0xFF            ; j = j%256

        call swap_ESI_ECX       ; swap S[i], S[j]

        inc esi
        cmp esi, 256
        jne start_KSA

    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax
    
    add esp, 0x4
    mov esp, ebp
    pop ebp
ret

PRGA:
    push ebp
    mov ebp, esp
    sub esp, 0x4                ; length
    
    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi

    xor esi, esi                ; i
    xor edi, edi                ; index
    xor ecx, ecx                ; j
    xor eax, eax                ; byte

    mov ebx, [ebp + 0x8]        ; pt
    mov edx, [ebp + 0xc]        ; keystream
    push esi
    mov esi, ebx
    call sLen
    mov [ebp - 0x4], esi        ; length
    pop esi
    start_PRGA:
        inc esi
        and esi, 0xff           ; (i+1) % 256

        mov al, [S_array + esi]
        add ecx, eax
        and ecx, 0xff           ; (j + S[i]) % 256

        call swap_ESI_ECX       ; swap S[i], S[j]
        mov al, [S_array + esi]
        add al, [S_array + ecx] ; t = (S[i] + S[j])
        and eax, 0xff           ; t %= 256

    mov al, [S_array + eax]
    mov [keystream + edi], al   ; K[index] = S[t]
    inc edi
    cmp edi, [ebp - 0x4]
    jnz start_PRGA

    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax

    add esp, 0x4
    mov esp, ebp
    pop ebp
ret

xoring:
    push ebp
    mov ebp, esp

    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov esi, [ebp + 0x8]        ; pt
    mov ebx, [ebp + 0xc]        ; keystream
    mov edi, [ebp + 0x10]       ; ct
    push esi
    call sLen
    mov edx, esi                ; edx = len(pt)
    pop esi

    xor eax, eax        ; byte
    xor ecx, ecx        ; index
    start_xoring:
        mov al, [esi + ecx]          ; pt[i]
        xor al, [ebx + ecx]          ; keystream[i]
        mov [edi + ecx], al          ; ct[i] = pt[i] ^ keystream[i]
        inc ecx
        cmp ecx, edx
        jnz start_xoring

    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax

    mov esp, ebp
    pop ebp
ret

showOutput:
    push ebp
    mov ebp, esp

    mov esi, [ebp + 0x8]        ; ct
    push esi
    call sLen
    mov ebx, esi                ; ebx = len(ct)
    pop esi

    xor edi, edi
    xor eax, eax
    start_showOutput:
        mov al, [esi + edi]
        call hexPrint

    inc edi
    cmp edi, ebx
    jne start_showOutput

    mov esp, ebp
    pop ebp
ret