
# Task 1: RC4
- Cũng đã qua một khoảng thời gian khá lâu mình không code lại asm nên hơi choke chút nhưng vẫn hoàn thành được. Đối với nhiệm vụ code thuật toán RC4 bằng asm, mình có 2 hướng tiếp cận là code trực tiếp và code gen từ C.

## Code trực tiếp
- Code này làm mình mất khá nhiều thời gian, tuy nhiên sau khi xâu chuỗi lại logic của RC4 thì mình thấy không quá khó. Dưới đây là hình minh họa thuật toán RC4:
![image](https://hackmd.io/_uploads/ryWVZRm5Jg.png)
- Thuật toán mình sử dụng trong bài sẽ khởi tạo `S_array` theo dạng `S[i] = [i for i in range(256)]`. RC4 là một loại khóa dòng, phép mã hóa và giải mã được thực hiện với thuật toán tương tự nhau, với `key` được gen qua hai bước hoán vị là `KSA` và `PRGA`. Dưới đây là mã giả minh họa:
```
[KSA]
for i from 0 to 255
    S[i] := i
endfor
j := 0
for i from 0 to 255
    j := (j + S[i] + key[i mod keylength]) mod 256
    swap values of S[i] and S[j]
endfor
```

```
[PRGA]
i := 0
j := 0
while GeneratingOutput:
    i := (i + 1) mod 256
    j := (j + S[i]) mod 256
    swap values of S[i] and S[j]
    t := (S[i] + S[j]) mod 256
    K := S[t]
    output K
endwhile
```
- Về logic bài thì không khó, mình chia thành 5 phase chính:
![image](https://hackmd.io/_uploads/H1lrGRX9ye.png)
- Các section khởi tạo của mình như sau:
![image](https://hackmd.io/_uploads/Bk_d4RQckx.png)
- Với `pt` và `key` là chuỗi nhập vào, chương trình sinh khóa dòng `keystream` sau bước KSA và PRGA. Cuối cùng, `ct` là kết quả của phép xor giữa `pt` và `keystream`. Bên cạnh đó còn có `S_array` là mảng hoán vị, gọi là `S box` cũng được.
### Phase 1: getInput
- Phase này khá dễ, do nhiệm vụ cần mô phỏng RC4 nên các tham số mình cần truyền vào là `Plaintext - pt` và `Key - key`, yêu cầu nhập vào là mã ASCII nên mình không gặp nhiều vấn đề lắm. Dưới đây là code của mình, mình có sử dụng một số hàm đã định nghĩa sẵn trong file `functions.asm` sẽ để ở cuối bài:
::: spoiler getInput
```asm
getInput:
    lea esi, [format_Pt]
    call sPrint             ; Print "Plaintext: "
    lea esi, [pt]
    call sScan              ; Get the plaintext
    lea esi, [pt]
    call sLen               ; Get the length of the plaintext
    mov [pt_len], esi

    lea esi, [format_Key]
    call sPrint             ; Print "Key: "
    lea esi, [key]
    call sScan              ; Get the key
    lea esi, [key]
    call sLen               ; Get the length of the key
    mov [key_len], esi
ret
```
:::
### Phase 2: KSA
- Đây là bước để sinh ra Key Scheduling (hay còn gọi là chu trình khóa). Với mã giả được ghi rõ ở trên, mình có thể dễ dàng mô phỏng lại thuật toán, sử dụng thêm vài hàm tự định nghĩa như `swap_ESI_ECX` hay `mod_EBX`:
::: spoiler KSA
```asm
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
    mov al, [S_array + esi]
    mov dl, [S_array + ecx]
    mov [S_array + esi], dl
    mov [S_array + ecx], al
ret

KSA:
    ; push eax
    ; push ebx
    ; push ecx
    ; push edx
    ; push esi
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
        mov ebx, [key_len]
        push esi
        call mod_EBX
        pop edx                 ; edx = i%key_len
        add cl, [key + edx]     ; j += key[edx]

        mov ebx, 256
        push ecx
        call mod_EBX
        pop ecx                 ; j %= 256

        call swap_ESI_ECX       ; swap S[i], S[j]

        inc esi
        cmp esi, 256
        jne start_KSA
    ; pop eax
    ; pop ebx
    ; pop ecx
    ; pop edx
    ; pop esi
ret
```
:::
- Để giữ đúng tư duy calling conventions thì mình sẽ tạm comment các dòng kia lại, dù nó không cần thiết lắm :v

### Phase 3: PRGA
- Đây cũng là một phase giúp hoán vị các phần tử của `Key` tính theo bytes, mình có tham khảo được một vài video giới thiệu thuật toán khá dễ hiểu và trực quan ở [đây](https://www.youtube.com/watch?v=1UP56WM4ook). Dựa vào mã giả ở trên, kết hợp với các hàm tính toán viết sẵn, mình có code:
::: spoiler PRGA
```asm
PRGA:
    ; push esi
    ; push edi
    ; push eax
    ; push ebx
    ; push ecx
    xor esi, esi                ; i
    xor edi, edi                ; index
    xor eax, eax
    mov ebx, 256
    xor ecx, ecx                ; j
    start_PRGA:
        inc esi
        push esi
        call mod_EBX            ; (i+1) % 256
        pop esi

        mov al, [S_array + esi]
        add ecx, eax
        push ecx
        call mod_EBX            ; (j + S[i]) % 256
        pop ecx

        call swap_ESI_ECX       ; swap S[i], S[j]
        mov al, [S_array + esi]
        add al, [S_array + ecx] ; t = (S[i] + S[j])
        push eax
        call mod_EBX            ; t %= 256
        pop eax

    mov al, [S_array + eax]
    mov [keystream + edi], al   ; K[index] = S[t]
    inc edi
    cmp edi, [pt_len]
    jnz start_PRGA
    ; pop esi
    ; pop edi
    ; pop eax
    ; pop ebx
    ; pop ecx
ret
```
:::
### Phase 4: xoring
- Phần này tư duy khá đơn giản, hầu như không có gì phải lưu ý:
::: spoiler xoring
```asm
xoring:
    xor eax, eax        ; byte
    xor ecx, ecx        ; index
    start_xoring:
        mov al, [pt + ecx]          ; pt[i]
        xor al, [keystream + ecx]   ; keystream[i]
        mov [ct + ecx], al          ; ct[i] = pt[i] ^ keystream[i]
        inc ecx
        cmp ecx, [pt_len]
        jnz start_xoring
ret
```
:::
- Sau khi xor, kết quả chuỗi trả về nằm trong `ct`. Tuy nhiên, yêu cầu của mentor là in ra chuỗi `Hex` nên mình có phase 5 ở dưới, cũng là phase lấy của mình nhiều thời gian nhất.

### Phase 5: showOutput
- Với yêu cầu trả về chuỗi hexa, mình có khá nhiều cách để thực hiện trong asm, tuy nhiên, trong bài mình sẽ sử dụng tư duy chuyển đổi cơ số cơ bản từ dec sang hex. Tuy nhiên, có vài vấn đề cần lưu ý như các số từ 10-15 được thay bằng A-F. Để khắc phục điều này, mình đã làm như dưới đây:
![image](https://hackmd.io/_uploads/SkZ8U0m9yl.png)
- Khi sử dụng instruction div trong asm, với ngữ cảnh đang xét, phần dư sẽ nằm trong edx và phần nguyên nằm ở eax. Tại đây mình chỉ xét phần dư, khi phần dư lớn hơn 10, tức kí tự đó phải là một trong các chữ A-F (hoặc a-f). Mình đã cộng thêm phần dư đó với thêm một magic number nữa là 0x27. Kết quả chuỗi của mình sẽ gồm các hex với chữ cái in thường. Trong trường hợp muốn trở thành chữ cái in hoa thì magic number sẽ là 0x7.
- Tuy nhiên mình lại vấp phải một vấn đề nữa, khi chuyển hệ các số nhỏ hơn 10, ví dụ `4` thì chuỗi trả về là `4` chứ không phải là `04`. Khắc phục điều này, mình làm như sau:
```asm
cmp eax, 0xa
jl exception
exception:
    push eax
    mov eax, 0
    call iPrint
    pop eax
    call iPrint
```
- Trông hơi đụt chút nhưng fix được :smile_cat:.
- Cuối cùng, khi ghép tất cả lại, chúng ta được code hoàn chỉnh:
:::spoiler Test.asm
```asm
global _start
%include "./functions.asm"

section .bss
    pt: resb 255
    pt_len: resd 1
    key: resb 255
    key_len: resd 1
    keystream: resb 255
    ct: resb 255
    S_array: times 256 resb 1

section .data
    format_Pt: db "Plaintext: ", 0
    format_Key: db "Key: ", 0
    ; space: db " ", 0

section .text
_start:
    call getInput
    call KSA
    call PRGA
    call xoring
    call showOutput
    call quit


getInput:
    lea esi, [format_Pt]
    call sPrint             ; Print "Plaintext: "
    lea esi, [pt]
    call sScan              ; Get the plaintext
    lea esi, [pt]
    call sLen               ; Get the length of the plaintext
    mov [pt_len], esi

    lea esi, [format_Key]
    call sPrint             ; Print "Key: "
    lea esi, [key]
    call sScan              ; Get the key
    lea esi, [key]
    call sLen               ; Get the length of the key
    mov [key_len], esi
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
    mov al, [S_array + esi]
    mov dl, [S_array + ecx]
    mov [S_array + esi], dl
    mov [S_array + ecx], al
ret

KSA:
    ; push eax
    ; push ebx
    ; push ecx
    ; push edx
    ; push esi
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
        mov ebx, [key_len]
        push esi
        call mod_EBX
        pop edx                 ; edx = i%key_len
        add cl, [key + edx]     ; j += key[edx]

        mov ebx, 256
        push ecx
        call mod_EBX
        pop ecx                 ; j %= 256

        call swap_ESI_ECX       ; swap S[i], S[j]

        inc esi
        cmp esi, 256
        jne start_KSA
    ; pop eax
    ; pop ebx
    ; pop ecx
    ; pop edx
    ; pop esi
ret

PRGA:
    ; push esi
    ; push edi
    ; push eax
    ; push ebx
    ; push ecx
    xor esi, esi                ; i
    xor edi, edi                ; index
    xor eax, eax
    mov ebx, 256
    xor ecx, ecx                ; j
    start_PRGA:
        inc esi
        push esi
        call mod_EBX            ; (i+1) % 256
        pop esi

        mov al, [S_array + esi]
        add ecx, eax
        push ecx
        call mod_EBX            ; (j + S[i]) % 256
        pop ecx

        call swap_ESI_ECX       ; swap S[i], S[j]
        mov al, [S_array + esi]
        add al, [S_array + ecx] ; t = (S[i] + S[j])
        push eax
        call mod_EBX            ; t %= 256
        pop eax

    mov al, [S_array + eax]
    mov [keystream + edi], al   ; K[index] = S[t]
    inc edi
    cmp edi, [pt_len]
    jnz start_PRGA
    ; pop esi
    ; pop edi
    ; pop eax
    ; pop ebx
    ; pop ecx
ret

xoring:
    xor eax, eax        ; byte
    xor ecx, ecx        ; index
    start_xoring:
        mov al, [pt + ecx]          ; pt[i]
        xor al, [keystream + ecx]   ; keystream[i]
        mov [ct + ecx], al          ; ct[i] = pt[i] ^ keystream[i]
        inc ecx
        cmp ecx, [pt_len]
        jnz start_xoring
ret

showOutput:
    xor edi, edi
    xor eax, eax
    start_showOutput:
        mov al, [ct + edi]
        call hexPrint

    inc edi
    cmp edi, [pt_len]
    jne start_showOutput
ret
```
:::
- Còn đây là file `functions.asm` của mình (đã lược đi vài hàm phức tạp như sort hay sumBigNum, chỉ giữ lại hàm thao tác với input, output):
:::spoiler functions.asm
```javascript
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
```
:::
- Test với `steal` trong giải TTV:
![image](https://hackmd.io/_uploads/HkoCFRX9yl.png)
![image](https://hackmd.io/_uploads/r1Ty5R7ckg.png)
#### Another code
- Phía trên là chương trình của mình, viết ra để phục vụ cho input cố định, tức là không truyền vào hàm tham số, khiến cho code khó tái sử dụng. Dưới đây là chương trình mình code lại với mong muốn có thể tái sử dụng lại các hàm:
:::spoiler Real.asm
```asm
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

    push key
    call KSA        ; KSA(key)

    push keystream
    push pt
    call PRGA       ; PRGA(pt, keystream)

    push ct
    push keystream
    push pt
    call xoring     ; xoring(pt, keystream, ct)

    push ct
    call showOutput ; showOutput(ct)

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

    push eax
    push ebx
    push ecx
    push edx
    push esi

    mov eax, [ebp + 0x8]        ; eax = key
    mov esi, eax
    call sLen
    mov ebx, esi                ; ebx = len(key)
    
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

    mov esp, ebp
    pop ebp
ret

PRGA:
    push ebp
    mov ebp, esp
    
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
    push esi
    mov esi, [ebp + 0x8]
    call sLen
    cmp edi, esi
    pop esi
    jnz start_PRGA

    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax

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
```
:::
## Code gen từ C
- Đây là code thuật toán RC4 của mình:
:::spoiler RC4.c
```c=
#include <stdio.h>
#include <string.h>

unsigned char pt[256];
unsigned char key[256];
unsigned char s[256];

void swap(unsigned char *a, unsigned char *b){
    unsigned char temp = *a;
    *a = *b;
    *b = temp;
}

void getInput(unsigned char *pt, unsigned char *key){
    printf("Plaintext: ");
    fgets((char*)pt, 256, stdin);
    int len = strlen((char*)pt);
    if (len > 0 && pt[len-1] == '\n')
        pt[len-1] = '\0';

    printf("Key: ");
    fgets((char*)key, 256, stdin);
    len = strlen((char*)key);
    if (len > 0 && key[len-1] == '\n')
        key[len-1] = '\0';
}


void KSA(unsigned char *key, int key_len){
    for (int i=0; i<256; i++) s[i] = i;
    int j = 0;
    for (int i=0; i<256; i++){
        j = (j + s[i] + key[i % key_len]) % 256;
        swap(&s[i], &s[j]);
    }
}

void PRGA(unsigned char *pt, int pt_len, unsigned char *keystream){
    int i = 0, j = 0;
    for (int k=0; k<pt_len; k++){
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        swap(&s[i], &s[j]);
        int val = (s[i] + s[j]) % 256;
        keystream[k] = s[val];
    }
}

void xoring(unsigned char *pt, int pt_len, unsigned char *keystream, unsigned char *ct){
    for (int i=0; i<pt_len; i++){
        ct[i] = pt[i] ^ keystream[i];
    }
}

int main(){
    unsigned char keystream[256];
    unsigned char ct[256];
    getInput(pt, key);
    int pt_len = strlen(pt);
    int key_len = strlen(key);
    KSA(key, key_len);
    PRGA(pt, pt_len, keystream);
    xoring(pt, pt_len, keystream, ct);
    printf("Encrypted text: ");
    for (int i=0; i<pt_len; i++){
        printf("%02X", ct[i]);
    }
    printf("\n");

    return 0;

}
```
:::
- Test:
![image](https://hackmd.io/_uploads/B1iPrNE5yl.png)
- Mình muốn từ file C gen ra được code asm và có thể chạy được, nên đã thực thi các câu lệnh sau:
```
gcc -masm=intel -S .\RC4.c
as -o .\RC4.o .\RC4.s
gcc -o RC4.exe .\RC4.o
```
- Được:
![image](https://hackmd.io/_uploads/BJkNEsV5kx.png)
- Run thử:
![image](https://hackmd.io/_uploads/BJT0Ni4c1x.png)
- Đây là file `RC4.s` của mình
:::spoiler RC4.s
```asm
	.file	"RC4.c"
	.intel_syntax noprefix
	.text
	.globl	pt
	.bss
	.align 32
pt:
	.space 256
	.globl	key
	.align 32
key:
	.space 256
	.globl	s
	.align 32
s:
	.space 256
	.text
	.globl	swap
	.def	swap;	.scl	2;	.type	32;	.endef
	.seh_proc	swap
swap:
	push	rbp
	.seh_pushreg	rbp
	mov	rbp, rsp
	.seh_setframe	rbp, 0
	sub	rsp, 16
	.seh_stackalloc	16
	.seh_endprologue
	mov	QWORD PTR 16[rbp], rcx
	mov	QWORD PTR 24[rbp], rdx
	mov	rax, QWORD PTR 16[rbp]
	movzx	eax, BYTE PTR [rax]
	mov	BYTE PTR -1[rbp], al
	mov	rax, QWORD PTR 24[rbp]
	movzx	edx, BYTE PTR [rax]
	mov	rax, QWORD PTR 16[rbp]
	mov	BYTE PTR [rax], dl
	mov	rax, QWORD PTR 24[rbp]
	movzx	edx, BYTE PTR -1[rbp]
	mov	BYTE PTR [rax], dl
	nop
	add	rsp, 16
	pop	rbp
	ret
	.seh_endproc
	.section .rdata,"dr"
.LC0:
	.ascii "Plaintext: \0"
.LC1:
	.ascii "Key: \0"
	.text
	.globl	getInput
	.def	getInput;	.scl	2;	.type	32;	.endef
	.seh_proc	getInput
getInput:
	push	rbp
	.seh_pushreg	rbp
	mov	rbp, rsp
	.seh_setframe	rbp, 0
	sub	rsp, 48
	.seh_stackalloc	48
	.seh_endprologue
	mov	QWORD PTR 16[rbp], rcx
	mov	QWORD PTR 24[rbp], rdx
	lea	rax, .LC0[rip]
	mov	rcx, rax
	call	__mingw_printf
	mov	ecx, 0
	mov	rax, QWORD PTR __imp___acrt_iob_func[rip]
	call	rax
	mov	rdx, rax
	mov	rax, QWORD PTR 16[rbp]
	mov	r8, rdx
	mov	edx, 256
	mov	rcx, rax
	call	fgets
	mov	rax, QWORD PTR 16[rbp]
	mov	rcx, rax
	call	strlen
	mov	DWORD PTR -4[rbp], eax
	cmp	DWORD PTR -4[rbp], 0
	jle	.L3
	mov	eax, DWORD PTR -4[rbp]
	cdqe
	lea	rdx, -1[rax]
	mov	rax, QWORD PTR 16[rbp]
	add	rax, rdx
	movzx	eax, BYTE PTR [rax]
	cmp	al, 10
	jne	.L3
	mov	eax, DWORD PTR -4[rbp]
	cdqe
	lea	rdx, -1[rax]
	mov	rax, QWORD PTR 16[rbp]
	add	rax, rdx
	mov	BYTE PTR [rax], 0
.L3:
	lea	rax, .LC1[rip]
	mov	rcx, rax
	call	__mingw_printf
	mov	ecx, 0
	mov	rax, QWORD PTR __imp___acrt_iob_func[rip]
	call	rax
	mov	rdx, rax
	mov	rax, QWORD PTR 24[rbp]
	mov	r8, rdx
	mov	edx, 256
	mov	rcx, rax
	call	fgets
	mov	rax, QWORD PTR 24[rbp]
	mov	rcx, rax
	call	strlen
	mov	DWORD PTR -4[rbp], eax
	cmp	DWORD PTR -4[rbp], 0
	jle	.L5
	mov	eax, DWORD PTR -4[rbp]
	cdqe
	lea	rdx, -1[rax]
	mov	rax, QWORD PTR 24[rbp]
	add	rax, rdx
	movzx	eax, BYTE PTR [rax]
	cmp	al, 10
	jne	.L5
	mov	eax, DWORD PTR -4[rbp]
	cdqe
	lea	rdx, -1[rax]
	mov	rax, QWORD PTR 24[rbp]
	add	rax, rdx
	mov	BYTE PTR [rax], 0
.L5:
	nop
	add	rsp, 48
	pop	rbp
	ret
	.seh_endproc
	.globl	KSA
	.def	KSA;	.scl	2;	.type	32;	.endef
	.seh_proc	KSA
KSA:
	push	rbp
	.seh_pushreg	rbp
	mov	rbp, rsp
	.seh_setframe	rbp, 0
	sub	rsp, 48
	.seh_stackalloc	48
	.seh_endprologue
	mov	QWORD PTR 16[rbp], rcx
	mov	DWORD PTR 24[rbp], edx
	mov	DWORD PTR -4[rbp], 0
	jmp	.L7
.L8:
	mov	eax, DWORD PTR -4[rbp]
	mov	ecx, eax
	mov	eax, DWORD PTR -4[rbp]
	cdqe
	lea	rdx, s[rip]
	mov	BYTE PTR [rax+rdx], cl
	add	DWORD PTR -4[rbp], 1
.L7:
	cmp	DWORD PTR -4[rbp], 255
	jle	.L8
	mov	DWORD PTR -8[rbp], 0
	mov	DWORD PTR -12[rbp], 0
	jmp	.L9
.L10:
	mov	eax, DWORD PTR -12[rbp]
	cdqe
	lea	rdx, s[rip]
	movzx	eax, BYTE PTR [rax+rdx]
	movzx	edx, al
	mov	eax, DWORD PTR -8[rbp]
	lea	ecx, [rdx+rax]
	mov	eax, DWORD PTR -12[rbp]
	cdq
	idiv	DWORD PTR 24[rbp]
	mov	eax, edx
	movsx	rdx, eax
	mov	rax, QWORD PTR 16[rbp]
	add	rax, rdx
	movzx	eax, BYTE PTR [rax]
	movzx	eax, al
	lea	edx, [rcx+rax]
	mov	eax, edx
	sar	eax, 31
	shr	eax, 24
	add	edx, eax
	movzx	edx, dl
	sub	edx, eax
	mov	DWORD PTR -8[rbp], edx
	mov	eax, DWORD PTR -8[rbp]
	cdqe
	lea	rdx, s[rip]
	add	rdx, rax
	mov	eax, DWORD PTR -12[rbp]
	cdqe
	lea	rcx, s[rip]
	add	rax, rcx
	mov	rcx, rax
	call	swap
	add	DWORD PTR -12[rbp], 1
.L9:
	cmp	DWORD PTR -12[rbp], 255
	jle	.L10
	nop
	nop
	add	rsp, 48
	pop	rbp
	ret
	.seh_endproc
	.globl	PRGA
	.def	PRGA;	.scl	2;	.type	32;	.endef
	.seh_proc	PRGA
PRGA:
	push	rbp
	.seh_pushreg	rbp
	mov	rbp, rsp
	.seh_setframe	rbp, 0
	sub	rsp, 48
	.seh_stackalloc	48
	.seh_endprologue
	mov	QWORD PTR 16[rbp], rcx
	mov	DWORD PTR 24[rbp], edx
	mov	QWORD PTR 32[rbp], r8
	mov	DWORD PTR -4[rbp], 0
	mov	DWORD PTR -8[rbp], 0
	mov	DWORD PTR -12[rbp], 0
	jmp	.L12
.L13:
	mov	eax, DWORD PTR -4[rbp]
	lea	edx, 1[rax]
	mov	eax, edx
	sar	eax, 31
	shr	eax, 24
	add	edx, eax
	movzx	edx, dl
	sub	edx, eax
	mov	DWORD PTR -4[rbp], edx
	mov	eax, DWORD PTR -4[rbp]
	cdqe
	lea	rdx, s[rip]
	movzx	eax, BYTE PTR [rax+rdx]
	movzx	edx, al
	mov	eax, DWORD PTR -8[rbp]
	add	edx, eax
	mov	eax, edx
	sar	eax, 31
	shr	eax, 24
	add	edx, eax
	movzx	edx, dl
	sub	edx, eax
	mov	DWORD PTR -8[rbp], edx
	mov	eax, DWORD PTR -8[rbp]
	cdqe
	lea	rdx, s[rip]
	add	rdx, rax
	mov	eax, DWORD PTR -4[rbp]
	cdqe
	lea	rcx, s[rip]
	add	rax, rcx
	mov	rcx, rax
	call	swap
	mov	eax, DWORD PTR -4[rbp]
	cdqe
	lea	rdx, s[rip]
	movzx	ecx, BYTE PTR [rax+rdx]
	mov	eax, DWORD PTR -8[rbp]
	cdqe
	lea	rdx, s[rip]
	movzx	eax, BYTE PTR [rax+rdx]
	add	eax, ecx
	movzx	eax, al
	mov	DWORD PTR -16[rbp], eax
	mov	eax, DWORD PTR -12[rbp]
	movsx	rdx, eax
	mov	rax, QWORD PTR 32[rbp]
	add	rdx, rax
	mov	eax, DWORD PTR -16[rbp]
	cdqe
	lea	rcx, s[rip]
	movzx	eax, BYTE PTR [rax+rcx]
	mov	BYTE PTR [rdx], al
	add	DWORD PTR -12[rbp], 1
.L12:
	mov	eax, DWORD PTR -12[rbp]
	cmp	eax, DWORD PTR 24[rbp]
	jl	.L13
	nop
	nop
	add	rsp, 48
	pop	rbp
	ret
	.seh_endproc
	.globl	xoring
	.def	xoring;	.scl	2;	.type	32;	.endef
	.seh_proc	xoring
xoring:
	push	rbp
	.seh_pushreg	rbp
	mov	rbp, rsp
	.seh_setframe	rbp, 0
	sub	rsp, 16
	.seh_stackalloc	16
	.seh_endprologue
	mov	QWORD PTR 16[rbp], rcx
	mov	DWORD PTR 24[rbp], edx
	mov	QWORD PTR 32[rbp], r8
	mov	QWORD PTR 40[rbp], r9
	mov	DWORD PTR -4[rbp], 0
	jmp	.L15
.L16:
	mov	eax, DWORD PTR -4[rbp]
	movsx	rdx, eax
	mov	rax, QWORD PTR 16[rbp]
	add	rax, rdx
	movzx	r8d, BYTE PTR [rax]
	mov	eax, DWORD PTR -4[rbp]
	movsx	rdx, eax
	mov	rax, QWORD PTR 32[rbp]
	add	rax, rdx
	movzx	ecx, BYTE PTR [rax]
	mov	eax, DWORD PTR -4[rbp]
	movsx	rdx, eax
	mov	rax, QWORD PTR 40[rbp]
	add	rax, rdx
	mov	edx, r8d
	xor	edx, ecx
	mov	BYTE PTR [rax], dl
	add	DWORD PTR -4[rbp], 1
.L15:
	mov	eax, DWORD PTR -4[rbp]
	cmp	eax, DWORD PTR 24[rbp]
	jl	.L16
	nop
	nop
	add	rsp, 16
	pop	rbp
	ret
	.seh_endproc
	.section .rdata,"dr"
.LC2:
	.ascii "Encrypted text: \0"
.LC3:
	.ascii "%02X\0"
	.text
	.globl	main
	.def	main;	.scl	2;	.type	32;	.endef
	.seh_proc	main
main:
	push	rbp
	.seh_pushreg	rbp
	sub	rsp, 560
	.seh_stackalloc	560
	lea	rbp, 128[rsp]
	.seh_setframe	rbp, 128
	.seh_endprologue
	call	__main
	lea	rax, key[rip]
	mov	rdx, rax
	lea	rax, pt[rip]
	mov	rcx, rax
	call	getInput
	lea	rax, pt[rip]
	mov	rcx, rax
	call	strlen
	mov	DWORD PTR 424[rbp], eax
	lea	rax, key[rip]
	mov	rcx, rax
	call	strlen
	mov	DWORD PTR 420[rbp], eax
	mov	eax, DWORD PTR 420[rbp]
	mov	edx, eax
	lea	rax, key[rip]
	mov	rcx, rax
	call	KSA
	lea	rdx, 160[rbp]
	mov	eax, DWORD PTR 424[rbp]
	mov	r8, rdx
	mov	edx, eax
	lea	rax, pt[rip]
	mov	rcx, rax
	call	PRGA
	lea	rcx, -96[rbp]
	lea	rdx, 160[rbp]
	mov	eax, DWORD PTR 424[rbp]
	mov	r9, rcx
	mov	r8, rdx
	mov	edx, eax
	lea	rax, pt[rip]
	mov	rcx, rax
	call	xoring
	lea	rax, .LC2[rip]
	mov	rcx, rax
	call	__mingw_printf
	mov	DWORD PTR 428[rbp], 0
	jmp	.L18
.L19:
	mov	eax, DWORD PTR 428[rbp]
	cdqe
	movzx	eax, BYTE PTR -96[rbp+rax]
	movzx	eax, al
	mov	edx, eax
	lea	rax, .LC3[rip]
	mov	rcx, rax
	call	__mingw_printf
	add	DWORD PTR 428[rbp], 1
.L18:
	mov	eax, DWORD PTR 428[rbp]
	cmp	eax, DWORD PTR 424[rbp]
	jl	.L19
	mov	ecx, 10
	call	putchar
	mov	eax, 0
	add	rsp, 560
	pop	rbp
	ret
	.seh_endproc
	.def	__main;	.scl	2;	.type	32;	.endef
	.ident	"GCC: (Rev2, Built by MSYS2 project) 14.2.0"
	.def	fgets;	.scl	2;	.type	32;	.endef
	.def	strlen;	.scl	2;	.type	32;	.endef
	.def	putchar;	.scl	2;	.type	32;	.endef
```
:::
# Subtask 1: hidden & ezjunk
- Mentor có cho mình thêm hai bài nữa để reverse, một ELF, một PE
## hidden - AlpacaHackRound8
- Là một bài khá dễ trong giải AlpacaHackRound8, mã giả của bài khá đẹp:
::: spoiler Pseudocode
```c=
void __fastcall main(int argc, char **a2, char **a3)
{
  unsigned __int64 i; // [rsp+18h] [rbp-58h]
  char *input; // [rsp+20h] [rbp-50h]
  size_t input_len; // [rsp+28h] [rbp-48h]
  unsigned int *dest; // [rsp+38h] [rbp-38h]
  _DWORD fmt[6]; // [rsp+40h] [rbp-30h] BYREF
  unsigned __int64 v8; // [rsp+58h] [rbp-18h]

  v8 = __readfsqword(0x28u);
  strcpy(fmt, "AlpacaHackRound8");
  if ( argc > 1 )
  {
    input = a2[1];
    input_len = strlen(input);
    dest = calloc((input_len + 3) >> 2, 4uLL);
    memcpy(dest, input, input_len);
    for ( i = 0LL; i < (input_len + 3) >> 2; ++i )
      dest[i] = rolling(dest[i], fmt);
    if ( !memcmp(dest, &dword_557522600040, 4 * qword_557522600020) )
      puts("congratz");
    else
      puts("wrong");
  }
  else
  {
    printf("usage: %s <input>\n", *a2);
  }
}
```
:::
- Trong hàm có một hàm `encrypt` mình đã đổi tên thành `rolling` khá bất thường, phần dưới chỉ là flag checker nên mình không nói quá nhiều, để extract data mình chỉ cần chút script IDA:
```python=
start = 0x0000557522600040
for i in range(0, 0x1B):
    print(hex(get_wide_dword(start + 4*i)), end=", ")
```
- Với `0x1B` là số bytes so sánh giữa flag và `encrypted input`. Một điều lưu ý là các dữ liệu bài làm việc đều là DWORD (4 byte). Đây là hàm `rolling`:
![image](https://hackmd.io/_uploads/H1IKJljc1g.png)
- Mình cũng đã đổi tên một vài hàm khá sú trong đây, cụ thể `minusY(x)` là đưa giá trị `x` vào `[rbp-Y]`. Mình đoán đây là cách lưu biến của chương trình. Ở dưới là các hàm ROR4, ROL4 với `0` khá lạ, nhưng thực chất đó là giá trị IDA không phân tích được. Để làm rõ, mình sẽ đọc code assembly:
![image](https://hackmd.io/_uploads/Hkx5lxicke.png)
- Thực tế sau khi đưa chunk 4 kí tự của `input` vào trong stack thì chương trình thực hiện kiểm tra tính chẵn lẻ rồi rẽ nhánh sang hai hàm dưới, nơi thực hiện các phép bitwise trên. Mình sẽ không nói sâu vào phần này, đây là code mô phỏng mã hóa bằng python:
:::spoiler encrypt
```python=
def encrypt(chunk, fmt):
    s_12 = (rol4(fmt[0], 5) + ror4(fmt[1], 3)) & 0xFFFFFFFF
    s_8 = (ror4(fmt[2], 3) - rol4(fmt[3], 5)) & 0xFFFFFFFF
    s_4 = bytes_to_long(chunk[::-1].encode()) ^ s_12 ^ s_8
    new_chunk = s_4 & 0xFFFFFFFF
    if s_4 % 2 == 0:
        fmt[0] ^= ror4(s_8, 13)
        fmt[1] ^= ror4(s_8, 15)
        fmt[2] ^= rol4(s_12, 13)
        fmt[3] ^= rol4(s_12, 11)
    else:
        fmt[0] ^= rol4(s_8, 11)
        fmt[1] ^= rol4(s_8, 13)
        fmt[2] ^= ror4(s_12, 15)
        fmt[3] ^= ror4(s_12, 13)
    return new_chunk, fmt
```
:::
- Cần chú ý rằng chương trình cũng update lại mảng sau khi mã hóa từng chunk 4 byte của `input` nên mình cũng cần thực hiện tương tự. Test:
    - Với chall:
    ![image](https://hackmd.io/_uploads/SkrvWgjcyl.png)
    ![image](https://hackmd.io/_uploads/HJn2zeo51l.png)
    - Với python:
    ![image](https://hackmd.io/_uploads/rJyBMxocyg.png)
- Có thuật toán mã hóa, mình dễ dàng viết lại hàm giải mã:
::: spoiler decrypt
```python=
def decrypt(enc_chunk, fmt):
    s_12 = (rol4(fmt[0], 5) + ror4(fmt[1], 3)) & 0xFFFFFFFF
    s_8 = (ror4(fmt[2], 3) - rol4(fmt[3], 5)) & 0xFFFFFFFF
    chunk = (enc_chunk ^ s_12 ^ s_8) & 0xFFFFFFFF
    if enc_chunk % 2 == 0:
        fmt[0] ^= ror4(s_8, 13)
        fmt[1] ^= ror4(s_8, 15)
        fmt[2] ^= rol4(s_12, 13)
        fmt[3] ^= rol4(s_12, 11)
    else:
        fmt[0] ^= rol4(s_8, 11)
        fmt[1] ^= rol4(s_8, 13)
        fmt[2] ^= ror4(s_12, 15)
        fmt[3] ^= ror4(s_12, 13)
    return long_to_bytes(chunk)[::-1], fmt
```
:::
- Và đây là flag của mình:
![image](https://hackmd.io/_uploads/r10B7gjc1x.png)
>~~`Alpaca{th15_f145_1s_3xc3ssiv3ly_l3ngthy_but_th1s_1s_t0_3nsur3_th4t_1t_c4nn0t_b3_e4s1ly_s01v3d_us1ng_angr}`~~

## ezjunk - D^3CTF
- Mở file chall trong IDA, mình thấy khá bất thường:
![image](https://hackmd.io/_uploads/H1D6Nvicyg.png)
- Sau khi set bp và debug tại `loc_401A12` và `loc_401A1C`, mình cũng nắm được sơ qua hành vi của chương trình, nhưng một vài junk code khiến mã giả không gen ra được nên mình sẽ patch thẳng luôn:
![image](https://hackmd.io/_uploads/r19lovscke.png)
- Gen được mã giả:
![image](https://hackmd.io/_uploads/BJtMjvs9kx.png)
- Sau khi debug và phân tích, mình đổi tên được như sau (thực ra không phải làm phát ra luôn mà mình phải test gần 10 lần mới đổi được mã dễ đọc như này T.T):
![image](https://hackmd.io/_uploads/ry2ABdicJx.png)
- Tóm lại, thuật toán mã hóa trong bài là [XTEA](https://en.wikipedia.org/wiki/XTEA) có thay đổi một chút:
![image](https://hackmd.io/_uploads/rkir8uo91x.png)
- Các tham số truyền vào sẽ là `input`, `sum` và `delta`, `key`. Dựa vào debug (debug cần restore lại chương trình ban đầu vì `delta` và `sum` lấy giá trị tại nơi mình vừa patch T.T), mình tìm được:
![image](https://hackmd.io/_uploads/rJuWuuocke.png)
![image](https://hackmd.io/_uploads/SJcVu_s9kx.png)
```
sum = 0xE8017300
delta = 0xFF58F981
```
### off_404350 - modify key
- Riêng đối với `key` được lưu tại `off_404350`:
![image](https://hackmd.io/_uploads/SJ_Yimh9ke.png)
- Khi xref địa chỉ này thì mình tìm được một hàm (`sub_401550`) khá sú:
![image](https://hackmd.io/_uploads/S1jnjQh51e.png)
- Chạy debug thì hàm này được chạy trước `main`:
![image](https://hackmd.io/_uploads/r1jHnm25kl.png)
- Và resolved `IsDebuggerPresent` là một anti-debug. Để bypass, chỉ cần patch `jz` thành `jnz`. Tuy nhiên, khi xref thử `sub_401550` thì mình thấy nó không được gọi đến??:
![image](https://hackmd.io/_uploads/rksepQ2ckg.png)
- Điều này có liên quan tới hàm `sub_401CC0` được gọi ngay từ đầu:
![image](https://hackmd.io/_uploads/H1lwR735yl.png)
- Hàm không chỉ được gọi trong `main` mà còn được gọi trước `main`:
![image](https://hackmd.io/_uploads/SJxi0Qhc1x.png)
- Về cơ bản, `sub_401CC0` quan trọng để điều hướng luồng phân tích của mình. Nó được gọi trước `main` để thực thi hàm `sub_401C50` như sau:
![image](https://hackmd.io/_uploads/rk3ybVhckl.png)
- Tại đây, `qword_403350` sẽ chứa
![image](https://hackmd.io/_uploads/rkNFxE3c1l.png)
- Một giá trị -1 đóng vai trò là setpoint để bắt đầu và kết thúc vòng lặp, và hai địa chỉ hàm được khai báo ở đây, trong đó có hàm anti-debug mình đã nói ở trên, và hàm `sub_403340` gọi tới `sub_401530`
- Tóm lại, anti-debug được gọi trước `main` và được gọi theo sơ đồ sau:
```
[sub_401CC0] -> [sub_401C50] -> [qword_403350]
                                       |
                                       V
                                  [sub_401550]
                                       |
                                       V
                    Modify key <-- [AntiDebug]
```
- Sau khi debug nhiều lần, mình rút được `key`:
```
key = [0x5454, 0x4602, 0x4477, 0x5E5E]
```
- Tuy nhiên, nếu thử đi decrypt thử thì kết quả sẽ ra một fake flag:
![image](https://hackmd.io/_uploads/By97gShcJe.png)
### onexit - real check flag
- Khi phân tích tiếp `sub_401530`, mình thấy nó có gọi tới
![image](https://hackmd.io/_uploads/HkJFZE3ckx.png)
- Với `sub_401510` là một `onexit`:
![image](https://hackmd.io/_uploads/rJ05-4nckx.png)
- `onexit` đóng vai trò là hàm giúp đăng kí các hàm khác để thực thi khi thoát chương trình:
![image](https://hackmd.io/_uploads/H1ekMEn91e.png)
- Trong chương trình, `onexit` được gọi để đăng kí 2 hàm:
![image](https://hackmd.io/_uploads/BkyPMV35Je.png)
- `nullsub` và `sub_401C10` nhưng `nullsub` không quan trọng nên mình tạm bỏ qua. Đây là `sub_401C10`:
![image](https://hackmd.io/_uploads/SJrcIEh91l.png)
- Tại `off_404380` sẽ trỏ tới `off_403378` là `sub_4016BC` như sau:
![image](https://hackmd.io/_uploads/SkL8PE2qke.png)
- `sub_4016BC` cũng chứa toàn junk code nên mình không gen mã giả được, phải tạm thời patch đi các lỗi nhìn tạm:
![image](https://hackmd.io/_uploads/rkX-FV3q1e.png)
- Mình sẽ decrypt thử chuỗi kia:
![image](https://hackmd.io/_uploads/H10LzHnqyl.png)
- Chuỗi giúp ta xác định format của flag. Về cơ bản, luồng sẽ như sau:
![image](https://hackmd.io/_uploads/r11Y-SncJe.png)
- Sau khi chạy `checkFlag`, nếu đúng, chương trình sẽ in ra:
![image](https://hackmd.io/_uploads/rkd0WS3qyl.png)
và kết thúc nhưng do chương trình đã đăng kí hàm `real_sub` từ trước nên luồng tiếp tục chạy vào `real_sub`. Tại đây, chương trình sẽ so sánh với chuỗi flag mã hóa thực sự. Trong hàm còn có một phần check khá hay, theo như các wu mình đọc được thì họ giải thích đó là CRC, để recover lại `enc_flag` ban đầu, mình làm như sau:
```python=
enc = [0xB6DDB3A9, 0x36162C23, 0x1889FABF, 0x6CE4E73B, 0xA5AF8FC, 0x21FF8415, 0x44859557, 0x2DC227B7]
enc = [c_uint(v) for v in enc]
for i in range(len(enc)):
    for _ in range(32):
        if enc[i].value & 1:
            enc[i] = c_uint(enc[i].value ^ 0x84A6972F)
            enc[i] = c_uint(enc[i].value // 2) 
            enc[i] = c_uint(enc[i].value | 1 << 31)
        else:
            enc[i] = c_uint(enc[i].value // 2)
enc = [v.value for v in enc]
```
- Giải thích một chút cho phép `| 1 << 31`, do thuật toán trong hàm có kiểm tra tính âm của giá trị, nên để recover lại số ban đầu, cần set bit cao nhất có giá trị 1, tức là mang dấu âm ([nguồn](https://www.geeksforgeeks.org/representation-of-negative-binary-numbers/#:~:text=The%20sign%20bit%20indicates%20the%20sign%20of%20the,sign%20bit%20of%201%20represents%20a%20negative%20number.)). Cuối cùng, mình có source hoàn chỉnh:
```python=
from Crypto.Util.number import long_to_bytes
from ctypes import *

def customXTEA(block, s=0xE8017300, delta=0xFF58F981, key=[0x5454, 0x4602, 0x4477, 0x5E5E]):
    chunk0 = c_uint32(block[0])
    chunk1 = c_uint32(block[1])
    ss = c_uint32(s - delta * 32)
    for _ in range(32):
        ss.value += delta
        chunk1.value -= (((chunk0.value << 5) ^ (chunk0.value >> 6)) + chunk0.value) ^ (ss.value + key[(ss.value >> 11) & 3]) ^ 0x33
        chunk0.value -= (((chunk1.value << 4) ^ (chunk1.value >> 5)) + chunk1.value) ^ (ss.value + key[ss.value & 3]) ^ 0x44
    return chunk0.value, chunk1.value

enc = [0xB6DDB3A9, 0x36162C23, 0x1889FABF, 0x6CE4E73B, 0xA5AF8FC, 0x21FF8415, 0x44859557, 0x2DC227B7]
enc = [c_uint(v) for v in enc]
for i in range(len(enc)):
    for _ in range(32):
        if enc[i].value & 1:
            enc[i] = c_uint(enc[i].value ^ 0x84A6972F)
            enc[i] = c_uint(enc[i].value // 2) 
            enc[i] = c_uint(enc[i].value | 1 << 31)
        else:
            enc[i] = c_uint(enc[i].value // 2)
enc = [v.value for v in enc]
flag = b""
for i in range(0, len(enc), 2):
    block = (enc[i], enc[i+1])
    dec0, dec1 = customXTEA(block)
    dec0, dec1 = long_to_bytes(dec0), long_to_bytes(dec1)
    flag += dec0[::-1] + dec1[::-1]
print(flag)
```
- Tìm được flag:
![image](https://hackmd.io/_uploads/SyEt2B39ye.png)
> ~~`d3ctf{ea3yjunk_c0d3_4nd_ea5y_re}`~~
- Có thể thấy, mặc dù XTEA của chuỗi flag khác với chuỗi cố định trong chall của hàm `checkFlag`, mình vẫn nhận kết quả đúng vì hàm kiểm tra thực sự được thực thi ngay trước khi chương trình exit.
### Tham khảo
- [Nguồn 1](https://oacia.dev/d3ctf-2024/)
- [Nguồn 2](https://blog.xmcve.com/2024/04/29/D3CTF-2024-Writeup/#title-9)
- [Nguồn 3](https://www.52pojie.cn/thread-1918788-1-1.html)
- [Nguồn 4](https://blog.s1um4i.com/2024-D3CTF/)