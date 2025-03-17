---
title: 'Task 2: Anti-debug'
tags: [Reverse, Training_RE]

---


# Task 2: Anti-debug
- Debugging (dynamic analysis) là một kĩ thuật quan trọng trong dịch ngược, giúp phân tích hành vi chương trình bên cạnh static analysis. Để bảo vệ chương trình hoặc che giấu hành vi của mã độc, người viết code có thể sử dụng các phương pháp chống debug (anti-debug).
- Task 2 mình được giao nghiên cứu và tìm hiểu một số loại anti-debug được ghi chép lại trong [Antidebug checkpoint](https://anti-debug.checkpoint.com/). Hiện đang có 8 kiểu anti-debug tất cả, trong đó, hầu như dạng nào mình cũng đã từng gặp qua, thường gặp [debug flags](https://anti-debug.checkpoint.com/techniques/debug-flags.html), [timing](https://anti-debug.checkpoint.com/techniques/timing.html), [exceptions](https://anti-debug.checkpoint.com/techniques/exceptions.html). Hôm nay mình sẽ báo cáo lại các dạng anti-debug và code lại chúng, cũng như đề xuất hướng bypass (nếu có thể).

## [1. Debug flags](https://anti-debug.checkpoint.com/techniques/debug-flags.html)
- Theo mình hiểu, kĩ thuật này sẽ kiểm tra các cờ debug từ WinAPI (ví dụ IsDebuggerPresent, Remote...), hoặc từ process memory (tuy nhiên phần này hơi chuyên sâu nên mình chỉ tập trung vào WinAPI).
### 1.1. IsDebuggerPresent and Manual check
- Hàm API này thực chất sẽ kiểm tra cờ `BeingDebugged` trong `Process Environment Block` (PEB). Về cơ bản, code sẽ như sau:
```c=
#include <stdio.h>
#include <Windows.h>

int main() {
	if (IsDebuggerPresent()) {
		printf("Hello from BeingDebugged\n");
	}
	else {
		printf("Hello from main\n");
	}
	return 0;
}
```
- Bên cạnh đó, chương trình cũng có thể thực hiện kiểm tra thủ công như sau:
```c=
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

int main() {
	PPEB pPeb = (PPEB)__readfsdword(0x30);
	if (pPeb->BeingDebugged) {
		printf("Hello from BeingDebugged\n");
	}
	else {
		printf("Hello from main\n");
	}
	return 0;
}
```
- Trong cả hai cách, nếu thực hiện run bằng debugger (mình sử dụng Visual Studio để debug cho nhanh) thì đều trả ra:

<div style="width: 50%; float:right">
   <img style="float: right;", src="https://hackmd.io/_uploads/ry4Zx2foJl.png">
</div>
<div style="width: 50%; float:left">
    <img style="float: left;", src="https://hackmd.io/_uploads/SJOnxnzoJe.png">
</div>

- Và tất nhiên, nếu mình run .exe không dùng debugger thì không có gì xảy ra:
![image](https://hackmd.io/_uploads/rkkfmhfj1e.png)
- Bên cạnh `IsDebuggerPresent` còn có `CheckRemoteDebuggerPresent` tuy nhiên mình chưa biết cách để mô phỏng nên sẽ tạm thời bỏ qua. Về cơ bản là sẽ kiểm tra xem [remote debugger](https://learn.microsoft.com/en-us/visualstudio/debugger/remote-debugging?view=vs-2022) có debug chương trình hay không. Mình cũng thường sử dụng file `linux_server64` để tạo một `Remote Linux Debugger` debug file ELF trên Windows nhưng cũng chưa gặp con anti-debug trên bao giờ.
### 1.2. NtQueryInformationProcess
- Một hàm nữa mình cũng thường thấy trong các bài CTF là `NtQueryInformationProcess`. Theo mình đọc được từ [tài liệu](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess), hàm này sẽ lấy ra các thông tin về tiến trình được handled:
```c
__kernel_entry NTSTATUS NtQueryInformationProcess(
  [in]            HANDLE           ProcessHandle,
  [in]            PROCESSINFOCLASS ProcessInformationClass,
  [out]           PVOID            ProcessInformation,
  [in]            ULONG            ProcessInformationLength,
  [out, optional] PULONG           ReturnLength
);
```
- Tại đây, class thông tin sẽ được khai báo tại tham số thứ 2, và trong kĩ thuật anti-debug, các cổng được kiểm tra thường sẽ là 
    - `ProcessDebugPort(0x7)`,
    - `ProcessDebugObjectHandle(0x1E)`, 
    - `ProcessDebugFlags(0x1F)` 
(mình tham khảo từ [đây](https://ntdoc.m417z.com/processinfoclass))
- Sau khi khai báo class, thông tin lấy được sẽ được return trong `ProcessInformation`, và tùy theo từng class, giá trị trả về sẽ giúp ta xác định chương trình có bị debug hay không. Code mình viết dưới đây (có tham khảo) đã gộp cả ba trường hợp này vào thành 1, vì đều gọi chung hàm `NtQueryInformationProcess`, chỉ khác class nên mình rút ngắn gọn nó lại:
```c=
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

int main() {
    typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );

    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (hNtdll) {
        auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
            hNtdll, "NtQueryInformationProcess");

        if (pfnNtQueryInformationProcess) {
            DWORD dwReturned;
            DWORD dwProcessDebugPort, dwProcessDebugFlags;
            HANDLE hProcessDebugObject = 0;

            const DWORD ProcessDebugPort = 7;
            const DWORD ProcessDebugFlags = 0x1f;
            const DWORD ProcessDebugObjectHandle = 0x1e;

            NTSTATUS status1 = pfnNtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugPort,
                &dwProcessDebugPort,
                sizeof(DWORD),
                &dwReturned);

            printf("ProcessDebugPort: %s\n", (NT_SUCCESS(status1) && (-1 == dwProcessDebugPort)) ? 
                "Hello from NtQueryInformationProcess" : "Hello from main");

            NTSTATUS status2 = pfnNtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugFlags,
                &dwProcessDebugFlags,
                sizeof(DWORD),
                &dwReturned);

            printf("ProcessDebugFlags: %s\n", (NT_SUCCESS(status2) && (0 == dwProcessDebugFlags)) ? 
                "Hello from NtQueryInformationProcess" : "Hello from main");

            NTSTATUS status3 = pfnNtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugObjectHandle,
                &hProcessDebugObject,
                sizeof(HANDLE),
                &dwReturned);

            printf("ProcessDebugObjectHandle: %s\n", (NT_SUCCESS(status3) && (0 != hProcessDebugObject)) ? 
                "Hello from NtQueryInformationProcess" : "Hello from main");
        }
    }
    return 0;
}
```
- Nếu run với debugger:
![image](https://hackmd.io/_uploads/r1h9bI7jJe.png)
- Nếu không:
![image](https://hackmd.io/_uploads/rkAjW8Qi1g.png)
### 1.3. NtGlobalFlag
- Đây là một trường có trong PEB, tùy theo phiên bản 64 bit hay 32 bit thì trường này sẽ nằm ở offset (0x68 hoặc 0xBC), giá trị của trường mặc định là 0. Việc attach một debugger không làm thay đổi trường này, nhưng nếu chạy một tiến trình, các cờ sau sẽ được bật:
    - `FLG_HEAP_ENABLE_TAIL_CHECK (0x10)`
    - `FLG_HEAP_ENABLE_FREE_CHECK (0x20)`
    - `FLG_HEAP_VALIDATE_PARAMETERS (0x40)`
- Thực hiện `OR` các giá trị cờ này, chương trình có thể phát hiện ra debugger, code như sau (nếu không muốn phải include các header dài dòng khác):
```c=
#include <stdio.h>

int main() {
	__asm {
		mov eax, fs: [0x30]
		mov al, [eax + 0x68]
		and al, 0x70
		cmp al, 0x70
		jz have_debugger
	}
	printf("Hello from main\n");
	return 0;
have_debugger:
	printf("Hello from NtGlobalFlag\n");
	return 0;
}
```
- Và nếu muốn include header:
```c=
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

int main() {
	PPEB pPeb = (PPEB)__readfsdword(0x30);
	DWORD dwNtGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0x68);
	if (dwNtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED) {
		printf("Hello from NtGlobalFlag\n");
	}
	else {
		printf("Hello from main\n");
	}
	return 0;
}
```
- Tùy từng trường hợp mà debugger có thể bị detected, ví dụ trong phần `NtGlobalFlag` này, mình run debugger bằng VS tím mà không bị detected :face_with_monocle:. Tuy nhiên với IDA thì:
![image](https://hackmd.io/_uploads/HJCG40mjJl.png)
![image](https://hackmd.io/_uploads/ryIvK0mskx.png)

### 1.4. Heap Protection
- Một vài hệ quả của việc set flag trong NtGlobalFlag có thể sử dụng để phát hiện debugger, ví dụ:
    - Nếu cờ `TAIL_CHECKING` được bật, DWORD `0xABABABAB` sẽ được thêm vào cuối của khối heap được cấp phát (2 lần nếu là win 32-bit và 4 lần nếu 64-bit)
    - Nếu cờ `FREE_CHECKING` được bật, DWORD `0xFEEEFEEE` cũng sẽ được thêm để fill vào dải bytes còn trống cho tới ô nhớ sau đó.
- Code để detect như sau:
```c=
#include <stdio.h>
#include <Windows.h>

bool isDebugging() {
	PROCESS_HEAP_ENTRY HeapEntry = { 0 };
	do {
		if (!HeapWalk(GetProcessHeap(), &HeapEntry))
			return false;
	} while (HeapEntry.wFlags != PROCESS_HEAP_ENTRY_BUSY);

	PVOID pOverlapped = (PBYTE)HeapEntry.lpData + HeapEntry.cbData;
	return ((DWORD)(*(PDWORD)pOverlapped) == 0xABABABAB);
}

int main() {
	if (isDebugging())
		printf("Hello from HeapProtection\n");
	else
		printf("Hello from main\n");
	return 0;
}
```
- Khi debug bằng IDA:
![image](https://hackmd.io/_uploads/ByVjPk4iJe.png)
và kết quả:
![image](https://hackmd.io/_uploads/HJPpw14jke.png)
### 1.5. Bypass
- Để bypass các anti-debug này, chúng ta chỉ đơn giản là sửa lại logic chương trình. Ví dụ, code asm `IsDebuggerPresent` như sau:
```asm=
call IsDebuggerPresent    
test al, al
jne  being_debugged
```
- Thì đơn giản, mình chỉ cần sửa opcode `jne` ở dòng 3 thành `je` là có thể bypass được nó. Tương tự với các con anti-debug ở trên, mình đều làm theo hướng này để bypass và tiếp tục reverse.
## [2. Object Handles](https://anti-debug.checkpoint.com/techniques/object-handles.html)
- Phần này mình chưa được gặp quá nhiều trong thực tế, tuy nhiên có tài liệu nên mình sẽ tham khảo và cố gắng mô phỏng nó.
### 2.1. OpenProcess()
- Code của phần này mình đã có test nhưng với máy mình thì con debugger lại không bị phát hiện. Về cơ bản, chương trình sẽ call tới `csrss.exe`, và điều đặc biệt là chỉ thành viên trong admin group với quyền debug mới có thể open process này. Nếu gặp lỗi thì chương trình có khả năng đang bị debug. Hàm check như sau:
```c=
typedef DWORD (WINAPI *TCsrGetProcessId)(VOID);

bool Check()
{   
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll)
        return false;
    
    TCsrGetProcessId pfnCsrGetProcessId = (TCsrGetProcessId)GetProcAddress(hNtdll, "CsrGetProcessId");
    if (!pfnCsrGetProcessId)
        return false;

    HANDLE hCsr = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pfnCsrGetProcessId());
    if (hCsr != NULL)
    {
        CloseHandle(hCsr);
        return true;
    }        
    else
        return false;
}
```
### 2.2. CreateFile()
- Kĩ thuật này lợi dụng cơ chế đọc file của debugger. Khi event `CREATE_PROCESS_DEBUG_EVENT` xảy ra, handle của file bị debug sẽ được lưu trong `CREATE_PROCESS_DEBUG_INFO`, các thông tin này giúp debugger có thể đọc thông tin debug từ file. Nếu debugger không đóng handle, file sẽ không được mở với quyền truy cập đặc biệt. Bằng cách sử dụng `kernel32!CreateFileW/A()` để truy cập đặc biệt một file nào đó và kiểm tra call, chúng ta có thể phát hiện debugger. Kĩ thuật khá đặc biệt, nhưng áp dụng trên máy mình thì không thành công, có thể do kĩ thuật đã lạc hậu chăng?. Hàm check như sau:
```c=
bool Check()
{
    CHAR szFileName[MAX_PATH];
    if (0 == GetModuleFileNameA(NULL, szFileName, sizeof(szFileName)))
        return false;
    
    return INVALID_HANDLE_VALUE == CreateFileA(szFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);
}
```
### 2.3. CloseHandle()
- Trong tất cả các kĩ thuật của phần này, đây là kĩ thuật duy nhất mình có thể mô phỏng thành công. Dựa trên việc raise exception, chương trình có thể nhận biết được debugger. Khi bị debug, nếu một handle không hợp lệ được truyền vào `ntdll!NtClose()` hay `kernel32!CloseHandle()` thì `EXCEPTION_INVALID_HANDLE (0xC0000008)` sẽ được raise, ngoại lệ này có thể nhận biết bởi exception handler. Khi đó, việc control được chuyển sang handler cũng đồng nghĩa rằng đang có debugger. Hàm check như sau:
```c=
#include <stdio.h>
#include <Windows.h>

bool isDebugging() {
	_try{
		CloseHandle((HANDLE)0xDEADBEEF);
		return false;
	}
	__except (EXCEPTION_INVALID_HANDLE == GetExceptionCode()
			? EXCEPTION_EXECUTE_HANDLER
			: EXCEPTION_CONTINUE_SEARCH)
	{
		return true;
	}

}

int main() {
	if (isDebugging())
		printf("Hello from CloseHandle\n");
	else
		printf("Hello from main\n");
	return 0;
}
```
- Khi run bằng debugger, một ngoại lệ sẽ được catch:
![image](https://hackmd.io/_uploads/H11WQ7Vsyl.png)
- Nếu run tiếp thì:
![image](https://hackmd.io/_uploads/S1VGQ7Niyx.png)
- Trong trường hợp run bình thường:
![image](https://hackmd.io/_uploads/HyCUX7Eskx.png)

### 2.4. Bypass
- Do mình mới chỉ mô phỏng được anti-debug bằng `CloseHandle()` nên cách bypass của mình cũng chỉ áp dụng với nó. Giống như các exception khác, mình đều set breakpoint trước khi exception được raised, sau đó set IP vào luồng chuẩn, hoặc patch NOP phần đó luôn.

## [3. Exceptions](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- Các kĩ thuật dưới đây đều raise lên exception để nhận biết debugger bằng cách kiểm tra hành vi của chương trình có phù hợp như là một tiến trình run bình thường hay không. Phần này mình gặp lần đầu tiên trong giải TTV2025.
### 3.1. UnhandledExceptionFilter()
- Kĩ thuật này khá đơn giản, lí thuyết rằng nếu có ngoại lệ xảy ra và chương trình chưa đăng kí bất kì exception handler nào để xử lí, thì hàm `kernel32!UnhandledExceptionFilter()` sẽ được gọi tới. Chúng ta cũng có thể đăng kí một handler xử lí ngoại lệ bằng hàm `kernel32!SetUnhandledExceptionFilter()`. Tuy nhiên, nếu chương trình đang chạy bị debug, exception sẽ được chuyển control sang cho debugger chứ không phải hai hàm trên, đây chính là anti-debug.
![image](https://hackmd.io/_uploads/S1Sh74Eoyg.png)
- Code check như sau:
```c=
#include <stdio.h>
#include <Windows.h>

LONG WINAPI MyUnhandledExceptionFilter(PEXCEPTION_POINTERS pExceptionInfo) {
    PCONTEXT ctx = pExceptionInfo->ContextRecord;
    ctx->Eip += 3; // Skip int 3 (CC) and jmp instruction for 32-bit
    return EXCEPTION_CONTINUE_EXECUTION;
}

bool isDebugging() {
    bool bDebugged = true;
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)MyUnhandledExceptionFilter);

    __asm {
        int 3               // CC - Breakpoint exception
        jmp being_debugged  // Jump to label if exception is handled
    }
    bDebugged = false;

being_debugged:
    return bDebugged;
}

int main() {
    if (isDebugging())
        printf("Hello from MyUnhandledExceptionFilter\n");
    else
        printf("No Exception, hello from main\n");
    return 0;
}
```
- Nếu run bằng debug VS tím:
![image](https://hackmd.io/_uploads/BJ3CtE4iyl.png)
- Output nếu continue:
![image](https://hackmd.io/_uploads/HJRASENiye.png)
- Nếu run bình thường:
![image](https://hackmd.io/_uploads/SJPntVNj1g.png)
### 3.2. RaiseException()
- Một số ngoại lệ như `DBC_CONTROL_C` hay `DBG_RIPEVENT` không được truyền vào handlers để xử lí mà phải thông qua debugger. Từ đây, chúng ta có thể đăng kí một handler (giả sử handler1) kiểm tra xem control có được chuyển hướng sang handler1 hay không. Nếu không, vậy thì khả năng chương trình đang được run với debugger.
- Code như sau:
```c=
#include <stdio.h>
#include <Windows.h>

bool isDebugging() {
    __try {
        RaiseException(DBG_CONTROL_C, 0, 0, NULL);
        return true;
    }
    __except (DBG_CONTROL_C == GetExceptionCode()
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_SEARCH)
    {
        return false;
    }
}

int main() {
    if (isDebugging())
        printf("Hello from RaiseException\n");
    else
        printf("No RaiseException, hello from main\n");
    return 0;
}
```
- Control được chuyển qua debugger:
![image](https://hackmd.io/_uploads/SJCdoEEjkl.png)
- Nếu run bình thường:
![image](https://hackmd.io/_uploads/SyO5sNNjkx.png)
### 3.3. Control Flow Hiding
- Đây không phải kĩ thuật giúp nhận biết debugger mà là kĩ thuật giúp ẩn giấu hành vi chương trình dưới những exception handlers. Được biết, chúng ta có thể đăng kí các ngoại lệ bằng [SEH](https://learn.microsoft.com/en-us/cpp/cpp/structured-exception-handling-c-cpp?view=msvc-170) hoặc [VEH](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling). Sau khi ngoại lệ xảy ra, chương trình nếu không bị debug, sẽ điều hướng luồng tới hàm xử lí ngoại lệ. Ngược lại, nếu debug thì control sẽ được chuyển cho debugger. Điều này giúp quá trình debug trở nên khó khăn và phần nào đó giúp che giấu hành vi của chương trình. Mình gặp kĩ thuật này lần đầu tiên khi làm chall `Mixture` của `noobmannn`. Rất cảm ơn anh đã cho em trải nghiệm kiến thức mới mẻ này :fire:.
### 3.4. Bypass
- Với các thể loại exceptions này, mình đều làm theo hướng NOP hết mọi code cản trở. Ngoài ra, với kĩ thuật che giấu hành vi ở trên, mình thường trace và set IP để thực hiện phân tích.

## [4. Timing](https://anti-debug.checkpoint.com/techniques/timing.html)
- Một trong những kĩ thuật anti-debug mình gặp nhiều nhất trong khoảng thời gian đầu tự học RE, đặc biệt là khi làm bài của `kcbowhunter`. Được biết, thời gian chương trình xử lí các câu lệnh là cực kì nhanh, khi đó, ta có thể lợi dụng sự chênh lệch thời gian giữa hai câu lệnh để kiểm tra có debugger hay không. Kĩ thuật này cơ bản, đơn giản và khá tốt với những newbie single-step reverser, nhưng cũng rất dễ để bypass.
### 4.1. RDTSC
```c=
#include <Windows.h>
#include <stdio.h>

BOOL debugger_check(DWORD64 qwNativeElapsed) {
    ULARGE_INTEGER Start, End;
    __asm {
        xor ecx, ecx
        rdtsc
        mov  Start.LowPart, eax
        mov  Start.HighPart, edx
    }

    __asm {
        xor ecx, ecx
        rdtsc
        mov  End.LowPart, eax
        mov  End.HighPart, edx
    }
    return (End.QuadPart - Start.QuadPart) > qwNativeElapsed;
}
int main() {
	const DWORD qwNativeElapsed = 0xFF;
    if (debugger_check(qwNativeElapsed)) {
        printf("Hello from RDTSC\n");
    }
    else printf("No debugger detected from RDTSC, hello from main");
	return 0;
}
```
- Nếu có debugger:
![image](https://hackmd.io/_uploads/ByeOGHVj1l.png)
- Nếu không:
![image](https://hackmd.io/_uploads/B1ItGr4iyl.png)
### 4.2. GetLocalTime()
- Phần này mình lại không detect được debugger, code như sau:
```c=
bool IsDebugged(DWORD64 qwNativeElapsed)
{
    SYSTEMTIME stStart, stEnd;
    FILETIME ftStart, ftEnd;
    ULARGE_INTEGER uiStart, uiEnd;

    GetLocalTime(&stStart);
    // ... some work
    GetLocalTime(&stEnd);

    if (!SystemTimeToFileTime(&stStart, &ftStart))
        return false;
    if (!SystemTimeToFileTime(&stEnd, &ftEnd))
        return false;

    uiStart.LowPart  = ftStart.dwLowDateTime;
    uiStart.HighPart = ftStart.dwHighDateTime;
    uiEnd.LowPart  = ftEnd.dwLowDateTime;
    uiEnd.HighPart = ftEnd.dwHighDateTime;
    return (uiEnd.QuadPart - uiStart.QuadPart) > qwNativeElapsed;
}
```
### 4.3. So on and bypass
- Các kĩ thuật timing sau cũng đơn giản cấu trúc như trên nên mình sẽ không đề cập nữa vì nó khá đơn giản. Thay vào đó, mình sẽ đề xuất cách bypass. Với timing, mình thường sẽ NOP các hàm lấy thời gian như trên, hoặc một cách hay hơn đó là hạn chế single-step qua các bước kiểm tra chênh lệch mốc thời gian và chỉ đặt breakpoint sau các hàm này.

## [5. Process Memory](https://anti-debug.checkpoint.com/techniques/process-memory.html)
- Kĩ thuật anti-debug trong mục này dựa trên việc một process có thể tự kiểm tra memory của chính nó để nhận biết debugger, có thể thông qua thread contexts, breakpoints hoặc function patching.
### 5.1 Software Breakpoints (INT 3)
- Kĩ thuật này sẽ kiểm tra sự xuất hiện của byte 0xCC tương đương với instruction `INT 3` trong chương trình. Trên thực tế, khi debug chương trình, tại nơi breakpoints, debugger sẽ thêm opcode 0xCC vào để dừng chương trình tại đó. Cụ thể có thể xem tại [đây](https://www.youtube.com/watch?v=PVnjYgoX_ck&t=2s), mình sẽ tóm gọn lại: set breakpoint tương ứng với việc thay thế opcode tại đó bằng 0xCC, debugger sẽ nhớ lại byte bị thay thế đó, cho khi debugger reach 0xCC, nó sẽ điền lại byte ban đầu vào vị trí cũ, set IP - 1 và tiếp tục debug.
- Đó là cách mà software bp được sử dụng trong phân tích, và lợi dụng điều này, anti-debug sẽ examine toàn bộ mem của nó để nhận biết có anti-debug hay không. Tuy nhiên cách này hơi có phần thiếu căn cứ và cần được sử dụng đúng cách. Code như sau:
```c=
bool CheckForSpecificByte(BYTE cByte, PVOID pMemory, SIZE_T nMemorySize = 0)
{
    PBYTE pBytes = (PBYTE)pMemory; 
    for (SIZE_T i = 0; ; i++)
    {
        // Break on RET (0xC3) if we don't know the function's size
        if (((nMemorySize > 0) && (i >= nMemorySize)) ||
            ((nMemorySize == 0) && (pBytes[i] == 0xC3)))
            break;

        if (pBytes[i] == cByte)
            return true;
    }
    return false;
}

bool IsDebugged()
{
    PVOID functionsToCheck[] = {
        &Function1,
        &Function2,
        &Function3,
    };
    for (auto funcAddr : functionsToCheck)
    {
        if (CheckForSpecificByte(0xCC, funcAddr))
            return true;
    }
    return false;
}
```
### 5.2. Toolhelp32ReadProcessMemory()
- Một phương pháp nữa mình cũng gặp khá nhiều đó là sử dụng `Toolhelp32` để đọc mem từ các process. Kĩ thuật này có thể được sử dụng để anti-step-over, cũng dựa trên opcode 0xCC:
```c=
#include <TlHelp32.h>

bool foo()
{
    // ..
    
    PVOID pRetAddress = _ReturnAddress();
    BYTE uByte;
    if (FALSE != Toolhelp32ReadProcessMemory(GetCurrentProcessId(), _ReturnAddress(), &uByte, sizeof(BYTE), NULL))
    {
        if (uByte == 0xCC)
            ExitProcess(0);
    }
    
    // ..
}
```
### 5.3. Bypass
- Một cách hữu hiệu để bypass tất cả các anti-debug trong phần này là NOP. Mình sẽ tìm tất cả các code check mem và NOP chúng, hoặc chỉnh sửa logic/giá trị return để phân tích.

## [6. Assembly instructions](https://anti-debug.checkpoint.com/techniques/assembly.html)
- Các kĩ thuật trong phần này sẽ nhận biết debugger thông qua hành vi của debugger khi CPU thực thi các instruction nhất định.
### 6.1. INT 3/2D
- Theo lí thuyết, `int 3` hay `0xCC` là opcode giúp debugger dừng lại tại breakpoints. Tuy nhiên, coder có thể sử dụng opcode này để nhận anti-debug, bởi khi CPU gặp `int 3` có sẵn trong code, `EXCEPTION_BREAKPOINT (0x80000003)` sẽ được raise. Control sẽ được chuyển cho debugger nếu chương trình đang bị debug, đây chính là kĩ thuật anti, tương tự với `int 2D`. Đây là code:
```c=
bool IsDebugged()
{
    __try
    {
        __asm xor eax, eax;
        __asm int 3; //__asm int 2d
        // nop because int 2d increase EIP by one
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}
```
### 6.2. DebugBreak
- Bên cạnh cách trên, chúng ta cũng có thể dùng `DebugBreak` để anti-debug. Đây là kĩ thuật mình đã gặp trong bài `steal` của giải [KCSC REcruitment 2025](/C7anopbtTRaMGumUlQuPzg). Code khá đơn giản như sau:
```c=
bool IsDebugged()
{
    __try
    {
        DebugBreak();
    }
    __except(EXCEPTION_BREAKPOINT)
    {
        return false;
    }
    
    return true;
}
```
### 6.3. Stack Segment Register
- Đây là một cách khá hay giúp set [Trap Flag](https://en.wikipedia.org/wiki/Trap_flag) để kiểm tra xem chương trình có đang bị traced hay không. Vì `Trap Flag` được clear bởi debuggers, ta có thể phát hiện debugger bằng kĩ thuật này, có thể đọc thêm ở [đây](https://github.com/mindsleader/reverse-engineering-reference-manual/blob/master/contents/anti-analysis/Anti-Debugging.md). Code như sau:
```c=
bool IsDebugged()
{
    bool bTraced = false;

    __asm
    {
        push ss
        pop ss
        pushf
        test byte ptr [esp+1], 1
        jz movss_not_being_debugged
    }

    bTraced = true;

movss_not_being_debugged:
    // restore stack
    __asm popf;

    return bTraced;
}
```
### 6.4. POPF 
- Giống với `ss` ở trên, đây cũng là kĩ thuật giúp nhận biết chương trình có đang bị traced hay không dựa vào `Trap Flag`. Code như sau:
```c=
bool IsDebugged()
{
    __try
    {
        __asm
        {
            pushfd
            mov dword ptr [esp], 0x100
            popfd
            nop
        }
        return true;
    }
    __except(GetExceptionCode() == EXCEPTION_SINGLE_STEP
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_EXECUTION)
    {
        return false;
    }
}
```
### 6.5. Bypass
- Cách tốt nhất để bypass các kĩ thuật trên đều là NOP bởi chúng đều là assembly instructions không dài, mình có thể patch các instruction đó mà không làm thay đổi logic chương trình. Bên cạnh đó, mình có thể set bp ngay trước các lệnh, và set IP pass qua lệnh đó.

## [7. Interactive Checks](https://anti-debug.checkpoint.com/techniques/interactive.html)
- Các kĩ thuật trong này mình chưa gặp bao giờ, chỉ biết qua tài liệu. Tuy nhiên, mình sẽ note down hai kĩ thuật mình thấy gần gũi nhất.
### 7.1. NtSetInformationThread()
- Hàm này giúp chúng ta ẩn thread khỏi debugger. Sau khi thread được ẩn, debugger sẽ không thể nhận biết events liên quan đến thread này, sau đó, thread có thể thực hiện các cách anti-debug nói trên để counter. 
- Nếu có bp trong hidden thread hoặc main thread bị ẩn, process sẽ bị crash và không thể debug. Code thực hiện kĩ thuật như sau:
```c=
#define NtCurrentThread ((HANDLE)-2)

bool AntiDebug()
{
    NTSTATUS status = ntdll::NtSetInformationThread(
        NtCurrentThread, 
        ntdll::THREAD_INFORMATION_CLASS::ThreadHideFromDebugger, 
        NULL, 
        0);
    return status >= 0;
}
```
### 7.2. OutputDebugString()
- Đây là kĩ thuật cũ rất nổi tiếng mà chỉ thực hiện được với các phiên bản Vista trở xuống. Idea của kĩ thuật khá đơn giản, nếu chương trình không bị debug, khi gọi tới `kernel32!OutputDebugString` thì lỗi sẽ xảy ra. Vậy không có lỗi đồng nghĩa với việc có debugger. Code như sau:
```c=
bool IsDebugged()
{
    if (IsWindowsVistaOrGreater())
        return false;

    DWORD dwLastError = GetLastError();
    OutputDebugString(L"AntiDebug_OutputDebugString_v1");
    return GetLastError() != dwLastError;
}
```
- Do là kĩ thuật cũ nên mình không thể mô phỏng được
### 7.3. Bypass
- Tiếp tục là NOP các hàm khả nghi hoặc bypass bằng cách đặt breakpoint trước khi hàm được gọi và set IP nhảy qua nó.

## [8. MISC](https://anti-debug.checkpoint.com/techniques/misc.html)
- No comment, các kĩ thuật trong này mình cũng chỉ gặp 1, 2 lần vì nó quá đa dạng
### 8.1. Parent Process Check
- Thông thường, nếu người dùng mở ứng dụng lên bằng cách kích đúp chuột, parent process của ứng dụng sẽ là `explorer.exe`, khi đó, chương trình chỉ cần lấy PID của parent process và so sánh với `explorer.exe` là có thể phát hiện được debugger.
#### 8.1.1. NtQueryInformationProcess()
- Đầu tiên, chương trình sẽ lấy shell process handle với `user32!GetShellWindow()` và lấy ID của process bằng cách gọi tới `user32!GetWindowThreadProcessId()`.
- PID có thể được lấy từ struct `PROCESS_BASIC_INFORMATION` khi gọi tới `ntdll!NtQueryInformationProcess()`. Code như sau:
```c=
bool IsDebugged()
{
    HWND hExplorerWnd = GetShellWindow();
    if (!hExplorerWnd)
        return false;

    DWORD dwExplorerProcessId;
    GetWindowThreadProcessId(hExplorerWnd, &dwExplorerProcessId);

    ntdll::PROCESS_BASIC_INFORMATION ProcessInfo;
    NTSTATUS status = ntdll::NtQueryInformationProcess(
        GetCurrentProcess(),
        ntdll::PROCESS_INFORMATION_CLASS::ProcessBasicInformation,
        &ProcessInfo,
        sizeof(ProcessInfo),
        NULL);
    if (!NT_SUCCESS(status))
        return false;

    return (DWORD)ProcessInfo.InheritedFromUniqueProcessId != dwExplorerProcessId;
}
```
#### 8.1.2. CreateToolhelp32Snapshot()
- Một kĩ thuật mình cũng gặp khá nhiều trong các bài CTF. ID và tên của tiến trình cha có thể được lấy bằng cách gọi hàm `kernel32!CreateToolhelp32Snapshot()` và `kernel32!Process32Next()`. Code như sau:
```c=
DWORD GetParentProcessId(DWORD dwCurrentProcessId)
{
    DWORD dwParentProcessId = -1;
    PROCESSENTRY32W ProcessEntry = { 0 };
    ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(Process32FirstW(hSnapshot, &ProcessEntry))
    {
        do
        {
            if (ProcessEntry.th32ProcessID == dwCurrentProcessId)
            {
                dwParentProcessId = ProcessEntry.th32ParentProcessID;
                break;
            }
        } while(Process32NextW(hSnapshot, &ProcessEntry));
    }

    CloseHandle(hSnapshot);
    return dwParentProcessId;
}

bool IsDebugged()
{
    bool bDebugged = false;
    DWORD dwParentProcessId = GetParentProcessId(GetCurrentProcessId());

    PROCESSENTRY32 ProcessEntry = { 0 };
    ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(Process32First(hSnapshot, &ProcessEntry))
    {
        do
        {
            if ((ProcessEntry.th32ProcessID == dwParentProcessId) &&
                (strcmp(ProcessEntry.szExeFile, "explorer.exe")))
            {
                bDebugged = true;
                break;
            }
        } while(Process32Next(hSnapshot, &ProcessEntry));
    }

    CloseHandle(hSnapshot);
    return bDebugged;
}
```
### 8.2. FindWindow()
- Kĩ thuật này sẽ duyệt qua danh sách các window classes trong system và so sánh với các classes debuggers đã khai báo. Các hàm có thể được sử dụng là `user32!FindWindowW/A/ExW/ExA()`. Code như sau:
```c=
const std::vector<std::string> vWindowClasses = {
    "antidbg",
    "ID",               // Immunity Debugger
    "ntdll.dll",        // peculiar name for a window class
    "ObsidianGUI",
    "OLLYDBG",
    "Rock Debugger",
    "SunAwtFrame",
    "Qt5QWindowIcon"
    "WinDbgFrameClass", // WinDbg
    "Zeta Debugger",
};

bool IsDebugged()
{
    for (auto &sWndClass : vWindowClasses)
    {
        if (NULL != FindWindowA(sWndClass.c_str(), NULL))
            return true;
    }
    return false;
}
```
### 8.3. DbgPrint()
- Kĩ thuật cũng gần giống như `OutputDebugString()` ở trên. Do `ntdll!DbgPrint()` sẽ gây ra ngoại lệ `DBG_PRINTEXCEPTION_C (0x40010006)`, ta có thể sử dụng ngoại lệ này để kiểm tra xem exception handler hay debugger xử lí nó. Code như sau:
```c=
bool IsDebugged()
{
    __try
    {
        RaiseException(DBG_PRINTEXCEPTION_C, 0, 0, 0);
    }
    __except(GetExceptionCode() == DBG_PRINTEXCEPTION_C)
    {
        return false;
    }

    return true;
}
```
### 8.4. Bypass
- Cách hợp lí và hiệu quả nhất vẫn là NOP các hàm check. Đối với kĩ thuật lấy PID ở trên, mình thường làm thay đổi giá trị trả về của `isDebugging` và từ đó phân tích chương trình bình thường.

# Subtask 2: Anti1 & Anti3
- Hai bài khá lạ đối với mình, một bài là của anh Tuna, một bài là của VCS training, mình sẽ đi sâu vào phân tích các kĩ thuật là chủ yếu vì mục đích học hỏi, còn `flag` thì tạm thời không chú trọng.
## Anti3
- Một bài lạ, `flag` có len 100 và sử dụng đến 6 kĩ thuật anti-debug. Ngay đầu vào, mình đã bắt gặp hàm xử lí ngoại lệ `SetUnhandledExceptionFilter`:
![image](https://hackmd.io/_uploads/rJR6wApoyl.png)
- Sau khi run thử thì:
![image](https://hackmd.io/_uploads/rJUg_R6iJg.png)
- Dính lỗi ngoại lệ chia cho 0 ngay tại đây:
![image](https://hackmd.io/_uploads/rJemdATskl.png)
- Vậy sau khi chương trình dính exception, do mình sử dụng debugger nên phần xử lí ngoại lệ sẽ được giao cho debugger và mình sẽ bị mất luồng thực thi chính.
- Với `SetUnhandledExceptionFilter`, hàm truyền vào sẽ là hàm được thực thi sau khi xảy ra ngoại lệ. Lợi dụng điều này, mình patch code để chương trình thực thi thẳng vào luồng chính bằng cách sửa `call SetUnhandledExceptionFilter` thành:
![image](https://hackmd.io/_uploads/HkSjuAaike.png)
- Và nop hết toàn bộ những gì không liên quan (do trong hàm thực thi khi ngoại lệ có calling convention rồi nên mình cũng nop luôn ở ngoài)
![image](https://hackmd.io/_uploads/HJaxY0TjJe.png)
- Patch & rename:
![image](https://hackmd.io/_uploads/ryKtFApjkg.png)
và một đống NOPs ở dưới. Như vậy, sau khi bật debug thì mình có thể nhảy vào luồng chính. Tuy nhiên, khi vào được `main_exception` thì mình lại gặp phải chút code rác:
![image](https://hackmd.io/_uploads/rk1kqyCj1x.png)
![image](https://hackmd.io/_uploads/rkvgq10ikg.png)
- Nguyên do là tác giả đã chèn vào vài byte rác khiến việc phân tích khó hơn. Kĩ thuật để làm đẹp lại code cũng đơn giản chỉ là NOP nên mình sẽ không nói chi tiết.
- Sau khi sửa, mình có được code như sau:
![image](https://hackmd.io/_uploads/S18j_l0iJl.png)
![image](https://hackmd.io/_uploads/r1WKAJCjJl.png)
- Các hàm trong `main_exception` mình sẽ phân tích khi đi vào từng parts.
### Part 1
- Trong phần này có kĩ thuật cần chú ý là examine `BeingDebugged Flag` trong PEB, nếu có debugger, các `debugByte` sẽ bị thay đổi (đây là các byte sử dụng cho mã hóa các part tiếp theo). Bên cạnh đó, hàm `isBreakpointThere` (mình đã đổi tên) sử dụng để kiểm tra opcode `0xCC` trong khoảng memory nhất định (lát nữa sẽ phân tích sau) và thay đổi `debugDword`.
- Mã hóa ở đây khá đơn giản, mình chỉ cần nhặt `flag_enc` nằm trong hàm `lastCheck` là có thể giải, trong hai bài `anti` này thì mình tiện học hỏi cách sử dụng code ida python luôn:
```python!
off = 0x00904118 # flag_enc offset
flag = ""
part1 = get_bytes(off, 17)
part1 = "".join([chr(i ^ 0x1) for i in part1])
print(part1)
```
![image](https://hackmd.io/_uploads/Skn1PeAiye.png)
### Part 2, 3, 4
![image](https://hackmd.io/_uploads/rJk6OlRiyl.png)
- Phần này có sử dụng đến `debugDword` mà mình nói ở phần trước. `debugDword` bị thay đổi do hàm `isBreakpointThere()`:
![image](https://hackmd.io/_uploads/HyKLYlAiye.png)
- Hàm này sẽ kiểm tra opcode `0x99 ^ 0x55 = 0xCC` trong vùng .text của `phase3`, nếu có thì khả năng cao là có debugger can thiệp vào. Đây chính là kĩ thuật detect debugger trong phần `Process Memory - Software Breakpoints` ở trên. Để bypass thì chúng ta chỉ cần không đặt bp trong hàm `phase3` là được. Bên cạnh đó, `debugDword` nếu chạy bình thường thì sẽ luôn có giá trị `48879` hay `0xBEEF`.
- Tại `phase3` này thì `part2` và `part3` của flag được enc như sau:
![image](https://hackmd.io/_uploads/S10Y5gAsJe.png)
- Đây là code để giải mã (sau khi test thì mình nhận ra giá trị đúng của `debugByte2 = 0xAB` và `debugByte3 = 0xCD`):
```python=
off += 18 # retrieve data from offset + 18
part2 = get_bytes(off, 8)
part2 = "".join([chr(i ^ 0xAB) for i in part2])
print(part2)

off += 9 # retrieve data from offset + 18 + 9
E = lambda c, idx: ((2*c | 1) ^ (idx + 0xCD)) & 0xFF
part3 = ""
for idx in range(12):
    check = get_wide_byte(off)
    for c in range(0x20, 0x7E):
        if E(c, idx) == check: part3 += chr(c)
    off += 1
print(part3)
```
![image](https://hackmd.io/_uploads/HkXBix0oyx.png)

- Tiếp theo, chương trình cũng thực hiện mã hóa `part4` bằng cách:
```c
for ( i = 0; i < 9; ++i )
    *(part2 + 2 * i) ^= debugDword;            
```
- Để giải, mình chỉ cần lấy được giá trị của `debugDword = 0xBEEF` và `xor` ngược lại là xong:
```python=
off += 1
D = lambda c: (c ^ 0xBEEF).to_bytes(2, "little")
part4 = ""
for i in range(9):
    c = get_wide_word(off)
    part4 += D(c).decode()
    off += 2
print(part4)
```
![image](https://hackmd.io/_uploads/r1RUhgRs1e.png)
### Part 5, 6, 7
![image](https://hackmd.io/_uploads/ryxqngCsyg.png)
![image](https://hackmd.io/_uploads/SyLbRxAoJg.png)
- Kĩ thuật phần này khá rõ ràng, bao gồm:
    - int 2D
    - int 3 - debugbreak()
- nên mình sẽ không đi sâu vào nữa, để bypass thì chỉ cần chạy đến instruction int 2D hoặc int 3 và setIP là được. Mình không khuyến khích NOP đi hai lệnh đó lắm vì mình làm thế thì các offset bị thay đổi dẫn đến sai data. Các `part5`, `part6`, `part7` cũng khá dễ dàng để giải mã:
```python=
off += 1
EE = lambda c, idx: ((c << (9 - idx)) | (c >> (idx-1))) & 0xFF
part5 = ""
for idx in range(1, 6):
    check = get_wide_byte(off)
    for c in range(0x20, 0x7E):
        if EE(c, idx) == check: part5 += chr(c)
    off += 1
print(part5)

off += 1
part6 = int.from_bytes(get_bytes(off, 4), "little")
part6 = (part6 ^ 0xC0FE1337).to_bytes(4, "little").decode()
print(part6)

off += 5
part7 = [0] + list(get_bytes(off, 30))
part7 = [part7[i] ^ part7[i-1] for i in range(1, 31)]
part7 = "".join([chr(c) for c in part7])
print(part7)
```
![image](https://hackmd.io/_uploads/S1ftCeRiJl.png)
- Sau khi ghép tất cả các phần lại, mình được `flag`.
> ~~`kcsc{unh4Ndl33xC3pTi0n_pebDebU9_nt9lob4Lfl49_s0F7w4r38r34Kp01n7_int2d_int3_YXV0aG9ydHVuYTk5ZnJvbWtjc2M===}`~~
~~Dài vcl~~

![image](https://hackmd.io/_uploads/SkCX1b0sye.png)
## Anti1
- Chall này cũng dị, mình phải run bằng quyền admin, các kĩ thuật được sử dụng khá mới với mình. Đây là `main - WinMain`:
```c=
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  HACCEL v4; // esi
  HANDLE CurrentProcess; // eax
  HWND Window; // eax
  HWND v7; // esi
  struct tagMSG Msg; // [esp+8h] [ebp-2Ch] BYREF
  HANDLE TokenHandle; // [esp+24h] [ebp-10h] BYREF
  DWORD ReturnLength; // [esp+28h] [ebp-Ch] BYREF
  HACCEL TokenInformation; // [esp+2Ch] [ebp-8h] BYREF

  v4 = 0;
  TokenHandle = 0;
  CurrentProcess = GetCurrentProcess();
  if ( OpenProcessToken(CurrentProcess, 8u, &TokenHandle) )
  {
    ReturnLength = 4;
    if ( GetTokenInformation(TokenHandle, TokenElevation, &TokenInformation, 4u, &ReturnLength) )
      v4 = TokenInformation;
  }
  if ( TokenHandle )
    CloseHandle(TokenHandle);
  if ( !v4 )
  {
    MessageBoxA(0, "Please run the program with administrator right", "Warning", 0);
    exit(1);
  }
  LoadStringW(hInstance, 0x67u, &WindowName, 100);
  LoadStringW(hInstance, 0x6Du, &ClassName, 100);
  sub_401260(hInstance);
  ::hInstance = hInstance;
  Window = CreateWindowExW(0, &ClassName, &WindowName, 0xCF0000u, 0x80000000, 0, 0x80000000, 0, 0, 0, hInstance, 0);
  v7 = Window;
  if ( !Window )
    return 0;
  ShowWindow(Window, nShowCmd);
  UpdateWindow(v7);
  TokenInformation = LoadAcceleratorsW(hInstance, (LPCWSTR)0x6D);
  while ( GetMessageW(&Msg, 0, 0, 0) )
  {
    if ( !TranslateAcceleratorW(Msg.hwnd, TokenInformation, &Msg) )
    {
      TranslateMessage(&Msg);
      DispatchMessageW(&Msg);
    }
  }
  return Msg.wParam;
}
```
- Trong đây có thể thấy chương trình sử dụng khá nhiều API để build app, và lòi ra được một hàm khá sú `sub_401260` ở dòng 30. Bước vào hàm thì thấy được:
![image](https://hackmd.io/_uploads/ryDQiZRsJl.png)
- Đây là hàm khởi tạo cho GUI của chương trình, mình sẽ phân tích tập trung vào `sub_401350`:
```c=
LRESULT __stdcall sub_401350(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
  const CHAR *v5; // [esp-Ch] [ebp-258h]
  DWORD pdwDataLen; // [esp+0h] [ebp-24Ch] BYREF
  struct tagPAINTSTRUCT Paint; // [esp+4h] [ebp-248h] BYREF
  __int128 v8[2]; // [esp+44h] [ebp-208h] BYREF
  __int128 v9; // [esp+64h] [ebp-1E8h]
  char v10[208]; // [esp+74h] [ebp-1D8h] BYREF
  CHAR input[260]; // [esp+144h] [ebp-108h] BYREF

  v8[0] = xmmword_4038D0;
  v8[1] = xmmword_4038E0;
  v9 = xmmword_4038F0;
  memset(v10, 0, sizeof(v10));
  pdwDataLen = 48;
  if ( Msg <= 0xF )
  {
    switch ( Msg )
    {
      case 0xFu:
        BeginPaint(hWnd, &Paint);
        EndPaint(hWnd, &Paint);
        return 0;
      case 1u:
        buttons(hWnd);
        return 0;
      case 2u:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, Msg, wParam, lParam);
  }
  if ( Msg != 273 )
    return DefWindowProcW(hWnd, Msg, wParam, lParam);
  switch ( (unsigned __int16)wParam )
  {
    case 4u:
      GetWindowTextA(::hWnd, input, 256);
      if ( checking(input) )
      {
        sha256_and_aes128((BYTE *)input, (BYTE *)v8, &pdwDataLen);
        if ( pdwDataLen >= 0x2E )
        {
          BYTE14(v9) = 0;
          MessageBoxA(0, (LPCSTR)v8, "OK", 0);
          return 0;
        }
        v5 = "Wrong";
      }
      else
      {
        v5 = "Wrong check fail";
      }
      MessageBoxA(0, "oh, no", v5, 0);
      return 0;
    case 0x68u:
      DialogBoxParamW(hInstance, (LPCWSTR)0x67, hWnd, DialogFunc, 0);
      return 0;
    case 0x69u:
      DestroyWindow(hWnd);
      return 0;
    default:
      return DefWindowProcW(hWnd, 0x111u, wParam, lParam);
  }
}
```
- Có thể thấy, đây là code chính trong core chương trình của mình. Mình sẽ chỉ tập trung vào hàm `checking` mà thôi:
::: spoiler cheking()
```c=
char __thiscall checking(const char *input)
{
  char v2; // cl
  int v3; // esi
  int v4; // ecx
  char v5; // bl
  char v6; // cl
  int v7; // eax
  char v8; // al
  int v9; // eax
  void (__stdcall *v10)(_DWORD); // eax
  char result; // al
  char v12; // bl
  int v13; // eax
  unsigned __int8 v14; // cl
  int v15; // eax
  int v16; // eax
  void (__stdcall *v17)(_DWORD); // eax
  void (__stdcall *v18)(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD); // [esp-4h] [ebp-25Ch] BYREF
  void (__stdcall *v19)(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD); // [esp+10h] [ebp-248h]
  int v20; // [esp+14h] [ebp-244h]
  void (__stdcall *v21)(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD); // [esp+18h] [ebp-240h]
  char v22; // [esp+1Fh] [ebp-239h]
  char v23[556]; // [esp+20h] [ebp-238h] BYREF
  int v24; // [esp+24Ch] [ebp-Ch]

  if ( strlen(input) < 0x26 )
    return 0;
  SSE((__m128i *)v23, byte_40501C[(unsigned __int8)byte_40501C[0] / 0xCu]);
  v2 = v22;
  v3 = 0;
  while ( 2 )
  {
    switch ( choices[v3] )
    {
      case 1:
        v4 = dword_403360[v3];
        v5 = input[dword_4033F8[v3]];
        v22 = NtCurrentPeb()->NtGlobalFlag & 0x70;
        v6 = sub_402050(v4);
        v7 = v24;
        if ( v24 >= 256 )
          v7 = 0;
        v24 = v7 + 1;
        v2 = byte_40329F[v7 + 1] == (char)(v5 ^ v6);
        goto LABEL_9;
      case 2:
        v8 = sub_401600(dword_403360[v3]);
        goto LABEL_8;
      case 3:
        v8 = sub_4016C0(dword_403360[v3]);
        goto LABEL_8;
      case 4:
        v8 = sub_401760(dword_403360[v3]);
        goto LABEL_8;
      case 5:
        v8 = sub_401950(dword_403360[v3]);
        goto LABEL_8;
      case 6:
        v8 = sub_401AA0(dword_403360[v3]);
LABEL_8:
        v2 = v8;
        goto LABEL_9;
      case 7:
        v20 = dword_403360[v3];
        v12 = input[dword_4033F8[v3]];
        v13 = sub_401DF0(2067767744);
        v19 = (void (__stdcall *)(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD))sub_401F10(v13, 1513862064);
        v21 = 0;
        v18 = v19;
        v19(-1, 31, &v18, 4, 0);
        v21 = v18;
        v14 = sub_402050(v20);
        v15 = v24;
        if ( v24 >= 256 )
          v15 = 0;
        v24 = v15 + 1;
        if ( byte_40329F[v15 + 1] != (v14 ^ (unsigned __int8)v12) )
          goto LABEL_20;
        v2 = 1;
        goto LABEL_10;
      default:
LABEL_9:
        if ( !v2 )
        {
LABEL_20:
          v16 = sub_401DF0(38312619);
          v17 = (void (__stdcall *)(_DWORD))sub_401F10(v16, 838910877);
          v17(0);
          byte_4055B8 = 0;
          return 0;
        }
LABEL_10:
        if ( ++v3 < 38 )
          continue;
        v9 = sub_401DF0(38312619);
        v10 = (void (__stdcall *)(_DWORD))sub_401F10(v9, 838910877);
        v10(0);
        byte_4055B8 = 0;
        result = 1;
        break;
    }
    return result;
  }
}
```
:::
- Hàm rất dài, và được chia thành rất nhiều case, và sau khi phân tích thì mình hiểu luồng như sau: chương trình nhận `input` rồi truyền vào hàm, mỗi `input[index]`sẽ được lựa chọn một trong 7 case tương ứng với 7 loại anti-debug, sau đó detect debugger và `xor` `input[index]` với giá trị nào đó.
### Resolving API
- Tuy nhiên, dấu hiệu của anti-debug không được rõ ràng, vì chương trình đã sử dụng kĩ thuật `API Hashing` (xem thêm tại [đây](https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware)) để resolve các hàm.
- Trong đó, hai hàm được sử dụng để resolve là:
`sub_401DF0` và `sub_401F10` (tùy theo từng phiên phân tích mà tên có thể khác nhau nhưng 4 hex cuối sẽ luôn không đổi). Mình sẽ debug và xref setIP để comment vào các case antidebug. Mình cũng có viết code idc để phục vụ phân tích nhanh hơn:
```python=
def to_hex(arr):
    return [hex(a) for a in arr]

def find_value(call_addr, reg):
    instr_addr = call_addr
    for _ in range(5):  # Scan max 5 instructions back
        instr_addr = prev_head(instr_addr)
        
        if print_insn_mnem(instr_addr) == "mov":
            dest = print_operand(instr_addr, 0)
            src = print_operand(instr_addr, 1)

            if dest == reg:  # Found ECX assignment
                return f"Non-immediate value: {src}", instr_addr
    return "Unknown (not found within 5 instructions)"

def resolve_API(func_addr, reg):
    call_sites = list(CodeRefsTo(func_addr, 0))
    mov_sites = []
    for addr in call_sites:
        reg_value, site = find_value(addr, reg)
        mov_sites.append(site)
        # print(f"Call at {hex(addr)} | {reg} = {reg_value} | site = {hex(site)}")
    return list(zip(mov_sites, call_sites))

lib_addr = 0x401DF0
resolved_lib = resolve_API(lib_addr, "ecx")
func_addr = 0x401F10
resolved_func = resolve_API(func_addr, "edx")

eips = list(zip(resolved_lib, resolved_func))
eip = eips[ 0 ] # replace index here
start, end = eip[0][0], eip[1][1]
set_reg_value(start, "eip")
print("Set IP succesfully")
run_to(next_head(end))
```
- Một số hình ảnh hàm được resolve
![image](https://hackmd.io/_uploads/rJttyzCjJe.png)
![image](https://hackmd.io/_uploads/BJBUxGRiyx.png)
![image](https://hackmd.io/_uploads/BJG1ZGAjJg.png)
![image](https://hackmd.io/_uploads/S1hfWfCoye.png)
![image](https://hackmd.io/_uploads/SyHNZfRsJl.png)
- Có thể thấy, tác giả sử dụng hàm `BlockInput` khá nhiều, hàm này chặn chúng ta sử dụng chuột hay bàn phím để tương tác với ứng dụng, nếu tham số truyền vào là `0` thì user được unblock và ngược lại. Mình sẽ cố gắng phân tích đủ các phase check antidebug (các phase được phân tích theo code trong hàm `checking`).
### Phase 0: TlsCallback - Debug Flag
![image](https://hackmd.io/_uploads/S1IzK_Rsyx.png)
- Một kĩ thuật quen thuộc, với class truyền vào là `0x7` thì chương trình đang examine cờ `ProcessDebugPort`, kết quả trả về là `-1` đồng nghĩa với việc chương trình bị debug. Mã giả ở đây hơi trôn chút nên mình phải đọc bằng mã asm, luồng đúng sẽ không thay đổi `unk_E05018`. Mình sẽ cần patch để debug cho đúng luồng.
### Phase 1: NtGlobalFlag - Heap Flag
![image](https://hackmd.io/_uploads/rJ9W5OAs1g.png)
- Đây là kĩ thuật examine 3 cờ trong `NtGlobalFlag`, cụ thể như sau:
![image](https://hackmd.io/_uploads/B1yuquCjke.png)
- Giá trị tổng 3 cờ đó đúng bằng `0x70` chứng tỏ có debugger đang attached. Tuy nhiên bài khá ảo khi sử dụng opcode `jnz` thay vì `jz` để đổi luồng, cụ thể như sau:
```!
- Nếu 0x70 -> cmp 0x70 --Đúng--> không nhảy tới loc_E01BEB 
=> Không debug thì vào luồng loc_E01BEB
```
- Sau đó, giá trị check debugger trả về sẽ được đưa vào hàm `sub_E02050` để tính toán giá trị `xor`.
### Phase 2: ProcessHeap - Heap Flag1
![image](https://hackmd.io/_uploads/BJK9Dt0okx.png)
- Kĩ thuật tiếp tục là examine Debug Flag, và trong phần này là Heap Flag, cụ thể như sau
![image](https://hackmd.io/_uploads/ryIDvtRjJg.png)
- Vì phiên bản của máy mình là 0x64 nên:
![image](https://hackmd.io/_uploads/HkpmdFCikx.png)
- Khi debug, các cờ sẽ được set hết và có tổng là `0x40000062`.
### Phase 3: ProcessHeap - Heap Flag2
![image](https://hackmd.io/_uploads/HyOs_YCokg.png)
- Again, examine Heap Flag. Nếu debug, giá trị tại `eax` sẽ là:
![image](https://hackmd.io/_uploads/SkpWtKCokl.png)
- Tuy nhiên, tại sao lại có sự chênh lệch của giá trị tổng cờ khi đều sử dụng kĩ thuật này?
![image](https://hackmd.io/_uploads/H1pjYtCsJx.png)
- Lí do là vì trong `Phase 2`, cờ `HEAP_GROWABLE (0x2)` cũng được check (+12) nên tổng sẽ là 0x40000062, còn trong `Phase 3` này, chương trình chỉ kiểm tra từ (+16) nên bỏ qua `HEAP_GROWABLE`.
### Phase 4: Heap Protection
![image](https://hackmd.io/_uploads/rkhLiF0okx.png)
- Đây là kĩ thuật được sử dụng:
![image](https://hackmd.io/_uploads/BJt_stRj1g.png)
- Nôm na là chương trình sẽ kiểm tra chuỗi `0xAB` có được appended vào cuối của heap block hay không:
![image](https://hackmd.io/_uploads/ryc6otAj1l.png)
![image](https://hackmd.io/_uploads/S1XM3F0o1g.png)
![image](https://hackmd.io/_uploads/HJWH2FRjkl.png)
- Do file thực thi là 32 bit nên chuỗi `0xAB` được append 8 lần. Đây chính là cách phát hiện debugger bằng cách check số lần `0xAB` xuất hiện, cách bypass là thay đổi giá trị trả về mà thôi.

### Phase 5: CreateToolhelp32Snapshot
![image](https://hackmd.io/_uploads/r1ZmzjAsyg.png)
- Kĩ thuật được sử dụng ở đây là examine các parent process của chương trình đang chạy. Mình thường thấy các author so sánh tên process với một chuỗi nào đó kiểu `ida.exe` hoặc `cmd.exe`, nhưng mình lại không tìm được chuỗi nào như thế. Ban đầu mình nghĩ author sẽ encrypt các chuỗi của process rồi so sánh ở trong phần này:
![image](https://hackmd.io/_uploads/rkHkssCoye.png)
nhưng lại chưa chứng minh được chương trình sẽ phát hiện anti-debug ở đâu.
### Phase 6: BlockInput
![image](https://hackmd.io/_uploads/S1WQni0ike.png)
- Đây cũng là một kĩ thuật được documented lại trong phần [này](https://anti-debug.checkpoint.com/techniques/interactive.html#blockinput)
- Điều cần lưu ý là:
![image](https://hackmd.io/_uploads/HJSm0s0jye.png)
- Cụ thể, chương trình đã thực hiện `BlockInput` hai lần. Lần đầu tiên nếu thành công thì trong lần thứ hai, giá trị trả về sẽ là `0`. Trong trường hợp giá trị trả về tiếp tục là `True` thì khả năng cao là chương trình đang bị hooked (khái niệm mình chưa tìm hiểu kĩ nên chưa giải thích ở đây)
![image](https://hackmd.io/_uploads/HkmX3oCsyg.png)
- Ảnh này là mình đang bị blocked nên phải sử dụng trackpad. Luồng đúng sẽ là luồng sao cho hai lần `BlockInput` trả về hai giá trị khác nhau.
### Phase 7: NtQueryInformationProcess - DebugFlag
![image](https://hackmd.io/_uploads/BkXu1h0syl.png)
- Tiếp tục là examine `Debug Flag`, nhưng lần này thay vì sử dụng `ProcessDebugPort(0x7)` thì chương trình dùng `ProcessDebugFlags(0x1f)`. Nếu giá trị trả về là `0` thì chương trình đang bị debugged.

### Script to solve:
- Bài thì có tận 8 phase để anti-debug nên mình cũng rén để bypass cả 8 cái, mình sẽ đi vào từng phase và nhặt giá trị ra để tìm lại `flag`. Trong đó, cần lưu ý mảng để check sẽ là:
```python=
validationTable = [
  0x0E, 0xEB, 0xF3, 0xF6, 0xD1, 0x6B, 0xA7, 0x8F, 0x3D, 
  0x91, 0x85, 0x2B, 0x86, 0xA7, 0x6B, 0xDB, 0x7B, 0x6E, 
  0x89, 0x89, 0x18, 0x95, 0x67, 0xCA, 0x5F, 0xE2, 0x54,
  0x0E, 0xD3, 0x3E, 0x20, 0x5A, 0x7E, 0xD4, 0xB8, 0x10, 
  0xC2, 0xB7]

idxTable = [
  0x9, 0x12, 0xf, 0x3, 0x4, 0x17, 0x6, 
  0x7, 0x8, 0x16, 0xa, 0xb, 0x21, 0xd, 
  0xe, 0x1b, 0x10, 0x25, 0x11, 0x13, 0x14, 
  0x15, 0x5, 0x22, 0x18, 0x19, 0x1a, 0x2, 
  0xc, 0x1d, 0x1e, 0x1f, 0x20, 0x1c, 0x0, 
  0x23, 0x24, 0x1]
```
- Để tìm lại các giá trị `xor` đúng, mình sẽ cần nhập chuỗi đầu vào có 38 kí tự, mình chọn `"?" * 38`, và cứ thế đi theo luồng, tới đâu thì bypass, ví dụ trong trường hợp đầu tiên rơi vào case 6:
![image](https://hackmd.io/_uploads/rJs-R2AsJx.png)
- Mình tìm lại được giá trị `xor` đầu tiên là 0x5B và tìm được kí tự thứ 9 của `flag`. Lặp lại 38 lần thì tìm được `flag`. Note thêm là mình viết script ida python để giải từng kí tự trong khi debug, mình đặt bp tại hàm tính toán kí tự `xor`: `sub_xx2050` và tại dòng `cmp` với `validationTable` để thay đổi cờ `ZF` thành 1, sau đó ghi vào trong mảng `xorTable` để in ra flag:
![image](https://hackmd.io/_uploads/rkoBp6AsJg.png)
- Script:
```python=
xorTable = [0x5B, 0xDB, 0x9D, 0xC6, 0xA7, 0x5A, 0x8A, 0xF6, 0x0D, 0xA5, 0xDA, 0x74, 0xE9, 0xCF, 0x58, 0x96, 0x5B, 0x5A, 0xD0, 0xFC, 0x25, 0xF6, 0x54, 0xB8, 0x6E, 0xCC, 0x7A, 0x3F, 0xA4, 0x1E, 0x73, 0x3F, 0x10, 0xE7, 0xF1, 0x21, 0xB6, 0xE8]

validationTable = [
  0x0E, 0xEB, 0xF3, 0xF6, 0xD1, 0x6B, 0xA7, 0x8F, 0x3D, 
  0x91, 0x85, 0x2B, 0x86, 0xA7, 0x6B, 0xDB, 0x7B, 0x6E, 
  0x89, 0x89, 0x18, 0x95, 0x67, 0xCA, 0x5F, 0xE2, 0x54,
  0x0E, 0xD3, 0x3E, 0x20, 0x5A, 0x7E, 0xD4, 0xB8, 0x10, 
  0xC2, 0xB7]

idxTable = [
  0x9, 0x12, 0xf, 0x3, 0x4, 0x17, 0x6, 
  0x7, 0x8, 0x16, 0xa, 0xb, 0x21, 0xd, 
  0xe, 0x1b, 0x10, 0x25, 0x11, 0x13, 0x14, 
  0x15, 0x5, 0x22, 0x18, 0x19, 0x1a, 0x2, 
  0xc, 0x1d, 0x1e, 0x1f, 0x20, 0x1c, 0x0, 
  0x23, 0x24, 0x1]

caseTable = [
  0x6, 0x1, 0x7, 0x1, 0x3, 0x2, 
  0x4, 0x3, 0x6, 0x3, 0x7, 0x6, 
  0x1, 0x4, 0x7, 0x4, 0x1, 0x5, 
  0x7, 0x6, 0x7, 0x5, 0x6, 0x4, 
  0x5, 0x1, 0x7, 0x5, 0x2, 0x3, 
  0x1, 0x2, 0x3, 0x2, 0x1, 0x6, 
  0x2, 0x4]

assert len(validationTable) == len(idxTable) and len(validationTable) == len(caseTable)
flag = ["?"] * 38
for idx in range(len(xorTable)):
    index = idxTable[idx]
    flag[index] = chr(validationTable[idx] ^ xorTable[idx])
print("".join(flag))
print(len(xorTable) == len(validationTable))
```
> ~~`I_10v3-y0U__wh3n Y0u=c411..M3 Senor1t4`~~
![image](https://hackmd.io/_uploads/HJmE0pRs1e.png)
Bài viết có tham khảo [wu của anh Thắng :fire:](https://github.com/neziRzz/KCSC_Training/blob/main/Tasks/Task_03/antisss.md#detailed-analysis-3)