---
title: 'Task 3: Dynamic API Resolution'
tags: [Reverse, Training_RE]

---


# Task 3: Dynamic API Resolution
- Chính xác kĩ thuật mà mình cần phải thực hiện trong task này là `Resolve API`, hay một số trang gọi là `Dynamic API Resolution`. Nói một cách ngắn gọn, API có thể hiểu là các hàm được viết sẵn, đặt trong các DLL của Windows, khi cần dùng thì user phải khai báo các hàm đó ra để load vào memory khi startup. Kĩ thuật này giúp chúng ta resolve và invoke WinAPI cùng lúc với run-time. Đây là một trong những kĩ thuật cơ bản trước khi nghiên cứu các kĩ thuật cao cấp hơn như shellcode injection hay (reflective) dll injection,... và nó cũng khá hữu dụng để anti static analysis.

## Code C
### Idea
- Trong task này, mình cần resolve tất cả các API cần dùng để gọi ra `MessageBoxA`. Thông thường, chúng ta sẽ làm như sau:
```c=
#include <windows.h>

int main() {
	MessageBoxA(NULL, "Hello World!", "Hello", MB_OK);
	return 0;
}
```
để hiện ra:
![image](https://hackmd.io/_uploads/HJELAcVh1x.png)
- Trông nhỏ bé vậy nhưng thực ra chương trình đã trải qua các bước như sau:
:::info
Build Phase:
    - Compiler nhận thấy chương trình call `MsgBox` và nhận định nó là external function
    - Linker thêm entry vào IAT trong PE Header
    - Entry chỉ ra `MsgBox` imported từ `user32.dll`
    
Load Phase:
    - Windows loader duyệt IAT
    - Loader kiểm tra `user32.dll` trong memory
    - Loader tìm kiếm `MsgBox` trong `user32.dll`
    - Loader viết địa chỉ `MsgBox` vào IAT

Run Phase:
    - Call `MsgBox` thực chất là call qua IAT
    - Processor sẽ nhảy đến địa chỉ được viết bởi loader và `user32.dll` thực thi show `MsgBox`
:::
- Đó là các bước của một chương trình bình thường. Tuy nhiên, nếu malware sử dụng các hàm API rõ ràng như này thì rõ ràng đã mất đi tính `stealth`, khi đó cần thực hiện `resolve API`.
- Về cơ bản, quy trình cũng sẽ giống như chương trình bình thường, chỉ khác là chúng ta cần thực hiện bằng tay các bước nói trên. Quy trình sẽ như sau:
::: success
- Duyệt `TEB`, trỏ tới `PEB`
- Duyệt `PEB`, trỏ tới `Ldr` (xem thêm ở [đây](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntpsapi_x/peb_ldr_data.htm)) thực chất chính là danh sách liên kết đôi chứa thông tin về các modules đã load dưới dạng cấu trúc `LDR_DATA_TABLE_ENTRY`(xem thêm ở [đây](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm))
- Duyệt `LDR_DATA_TABLE_ENTRY` và tìm kiếm `targetModule` mà ở đây chính là `kernel32.dll`
- Duyệt tất cả các functions của `kernel32.dll` và lấy ra `GetProcAddress`, `LoadLibraryA`
- Load `user32.dll` và sử dụng `GetProcAddress` để lấy địa chỉ của `MessageBoxA` để thực thi.
:::
- Tương đối thì mình có sơ đồ dưới đây để so sánh (gen bởi Claude dựa trên code của mình nên nó hơi đần):
![image](https://hackmd.io/_uploads/BktoVi42ke.png)
- Ở đây, có hai bước khó chính là bước 1 và 2, dưới đây là cách mình deal với nó:

### myGetModuleHandle
- Trước tiên, nhận thấy `PEB` có lưu trữ nhiều thông tin quan trọng về Dll được load vào chương trình nên chúng ta sẽ tìm kiếm `kernel32.dll` trong đó. Do `Ldr` là danh sách liên kết nên mình có thể thực hiện `PEB Traversal` để duyệt và đọc các Dll bằng `CONTAINING_RECORD`, chi tiết như sau:
```c=
HMODULE myGetModuleHandle(LPCWSTR lModuleName) {
    PPEB peb = __readfsdword(0x30); //0x60 for x64
    PLIST_ENTRY pListEntry = peb->Ldr->InMemoryOrderModuleList.Flink;
    PLIST_ENTRY pListEntryEnd = &peb->Ldr->InMemoryOrderModuleList;
    int moduleNameLength = wcslen(lModuleName);

    while (pListEntry != pListEntryEnd) {
        PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		WCHAR* fullName = module->FullDllName.Buffer; // retrieve the full path of the module
		int fullNameLength = module->FullDllName.Length / sizeof(WCHAR); // length of the full path
		WCHAR* fileNameStart = fullName + (fullNameLength - moduleNameLength); // start of the file name
		if (_wcsnicmp(fileNameStart, lModuleName, moduleNameLength) == 0) { // compare the file name
			return (HMODULE)module->DllBase; // return the base address of the module if the file name matches target
        }
        pListEntry = pListEntry->Flink;
    };
    return NULL;
}
```
- Mình đã có comment bên cạnh để tiện theo dõi và hiểu luồng hơn. Sau hàm này, mình đã lấy được địa chỉ của con `kernel32.dll` trong process:
![image](https://hackmd.io/_uploads/r1Nlus4nye.png)

### myGetProcAddress
- Trong `kernel32.dll` có hàm `GetProcAddress` rất quan trọng vì nó lấy được địa chỉ của hàm trong một con Dll:
![image](https://hackmd.io/_uploads/H1xjOsN3Jl.png)
- Bên cạnh đó còn có `LoadLibraryA` giúp load `user32.dll` vào process đang chạy để lấy được `MessageBox`:
![image](https://hackmd.io/_uploads/HyJfFsN2yx.png)
- Vốn dĩ chỉ có `kernel32.dll` và một vài Dll cơ bản khác được nạp sẵn vào chương trình, các Dll khác thì phải khai báo mới sử dụng được. `MessageBoxA` nằm trong `user32.dll` là target của mình nên mình cần load Dll này. 
- Idea của hàm này mình viết rất đơn giản là duyệt toàn bộ các hàm có trong EAT của `module`, nếu trùng khớp với `GetProcAddress` thì sẽ trả về địa chỉ của hàm. Tuy nhiên, phần khó ở đây là làm sao để duyệt đúng thì [bài này](https://www.ired.team/offensive-security/code-injection-process-injection/finding-kernel32-base-and-function-addresses-in-shellcode) đã giúp mình đi chuẩn hướng.
- Với mình, phần này đọc code asm dễ thở hơn hẳn. Đây là code C của mình:
```c=
FARPROC myGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    
    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDirRVA);

    // Get tables
    DWORD* functionAddresses = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);
    WORD* nameOrdinals = (WORD*)((BYTE*)hModule + exportDirectory->AddressOfNameOrdinals);
    DWORD* functionNames = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
        LPCSTR functionName = (LPCSTR)((BYTE*)hModule + functionNames[i]);

        if (strcmp(lpProcName, functionName) == 0) {
            DWORD functionIndex = nameOrdinals[i];
            DWORD functionRVA = functionAddresses[functionIndex];
            return (FARPROC)((BYTE*)hModule + functionRVA);
        }
    }
    return NULL;
}
```
- Ở đây chúng ta cần khai báo kiểu dữ liệu trả về đúng như trong syntax của MSDN.

### API Resolution
- Sau khi có được địa chỉ của `GetProcAddress`, mình sẽ call hàm để lấy địa chỉ của `LoadLibraryA` và `user32.dll -> MessageBoxA`:
```c=
typedef FARPROC(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef int(WINAPI* MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);

GETPROCADDRESS getProcAddress = myGetProcAddress(kernel32BaseAddr, getprocaddress);
LOADLIBRARYA loadLibraryA = getProcAddress(kernel32BaseAddr, loadlibrarya);
HMODULE user32BaseAddr = loadLibraryA(user32);
MESSAGEBOXA messageBoxA = getProcAddress(user32BaseAddr, messageboxa);
```
- Tại đây thì mình có thể call được `MessageBoxA` rồi, dưới đây là so sánh giữa hai địa chỉ của hai phương pháp:
```c=
HMODULE user32BaseAddr = loadLibraryA("user32.dll");
MESSAGEBOXA messageBoxA = getProcAddress(user32BaseAddr, "MessageBoxA");
printf("MessageBoxA from Resolution: %p\n", messageBoxA);

HMODULE hModule = LoadLibraryA("user32.dll");
FARPROC pFunc = GetProcAddress(hModule, "MessageBoxA");
printf("MessageBoxA not from Resolution: %p\n", pFunc);
```
![image](https://hackmd.io/_uploads/HJ5chjE31e.png)
- Vậy là phương pháp resolve API này đã thành công. Dưới đây là toàn bộ code C của mình (mình có nghịch nghịch thêm chút obfuscate):
```c=
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <winternl.h>

typedef FARPROC(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef int(WINAPI* MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);

char *decrypt(BYTE* data) {
	size_t length = strlen((char*)data);
    for (size_t i = 0; i < length; i++) {
        data[i] ^= (BYTE)length;
    }
	return (char*)data;
}

HMODULE myGetModuleHandle(LPCWSTR lModuleName) {
	PPEB peb = __readfsdword(0x30); //0x60 for x64
    PLIST_ENTRY pListEntry = peb->Ldr->InMemoryOrderModuleList.Flink;
	PLIST_ENTRY pListEntryEnd = &peb->Ldr->InMemoryOrderModuleList;
    int moduleNameLength = wcslen(lModuleName);

    while (pListEntry != pListEntryEnd) {
        PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		WCHAR* fullName = module->FullDllName.Buffer; // retrieve the full path of the module
		int fullNameLength = module->FullDllName.Length / sizeof(WCHAR); // length of the full path
		WCHAR* fileNameStart = fullName + (fullNameLength - moduleNameLength); // start of the file name
		if (_wcsnicmp(fileNameStart, lModuleName, moduleNameLength) == 0) { // compare the file name
			return (HMODULE)module->DllBase; // return the base address of the module if the file name matches target
        }
        pListEntry = pListEntry->Flink;
    };
    return NULL;
}

FARPROC myGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    
    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDirRVA);

    // Get tables
    DWORD* functionAddresses = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);
    WORD* nameOrdinals = (WORD*)((BYTE*)hModule + exportDirectory->AddressOfNameOrdinals);
    DWORD* functionNames = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
        LPCSTR functionName = (LPCSTR)((BYTE*)hModule + functionNames[i]);

        if (strcmp(lpProcName, functionName) == 0) {
            DWORD functionIndex = nameOrdinals[i];
            DWORD functionRVA = functionAddresses[functionIndex];
            return (FARPROC)((BYTE*)hModule + functionRVA);
        }
    }
    return NULL;
}
int main() {
    BYTE user32[] = { 0x7f, 0x79, 0x6f, 0x78, 0x39, 0x38, 0x24, 0x6e, 0x66, 0x66, 0x00 };
    BYTE getprocaddress[] = { 0x49, 0x6b, 0x7a, 0x5e, 0x7c, 0x61, 0x6d, 0x4f, 0x6a, 0x6a, 0x7c, 0x6b, 0x7d, 0x7d, 0x00 };
    BYTE loadlibrarya[] = { 0x40, 0x63, 0x6d, 0x68, 0x40, 0x65, 0x6e, 0x7e, 0x6d, 0x7e, 0x75, 0x4d, 0x00 };
    BYTE messageboxa[] = { 0x46, 0x6e, 0x78, 0x78, 0x6a, 0x6c, 0x6e, 0x49, 0x64, 0x73, 0x4a, 0x00 };
    BYTE hello[] = { 0x5f, 0x72, 0x7b, 0x7b, 0x78, 0x37, 0x71, 0x65, 0x78, 0x7a, 0x37, 0x56, 0x47, 0x5e, 0x48, 0x45, 0x72, 0x64, 0x78, 0x7b, 0x61, 0x72, 0x36, 0x00 };
    BYTE msg[] = { 0x4a, 0x5b, 0x42, 0x54, 0x59, 0x6e, 0x78, 0x64, 0x67, 0x7d, 0x6e, 0x00 };

	HMODULE kernel32BaseAddr = myGetModuleHandle(L"kernel32.dll");
    if (kernel32BaseAddr != NULL) {
        GETPROCADDRESS getProcAddress = myGetProcAddress(kernel32BaseAddr, decrypt(getprocaddress));
        LOADLIBRARYA loadLibraryA = getProcAddress(kernel32BaseAddr, decrypt(loadlibrarya));
        HMODULE user32BaseAddr = loadLibraryA((LPCSTR)decrypt(user32));
        MESSAGEBOXA messageBoxA = getProcAddress(user32BaseAddr, decrypt(messageboxa));
        messageBoxA(NULL, decrypt(msg), decrypt(hello), MB_OK);
    }
    return 0;
}
```
## Code ASM
- Code ASM thì có phần đơn giản hơn chút, mình code bằng MASM, sẽ thử bằng NASM sau. Các dòng code mình đều đã thêm comment để tiện theo dõi và debug:
```masm=
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
```
- Kiểm tra code:
![image](https://hackmd.io/_uploads/By0rCsN3kg.png)
- Trong trường hợp code chạy không thành công, mình đã để trống hàm `error_exit` để nó return giá trị lỗi:
![image](https://hackmd.io/_uploads/BkL6Rs42kg.png)
