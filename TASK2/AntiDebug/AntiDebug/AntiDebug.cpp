#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <cwchar>

void antis0() {
	// This is function to print flag
	const BYTE flag_encode[38] = {75, 66, 81, 64, 127, 64, 111, 96, 96, 125, 85, 74, 98, 121, 63, 80, 116, 34, 112, 102, 115, 102, 55, 54, 57, 70, 72, 40, 125, 44, 47, 102, 127, 99, 80, 19, 27, 88};
	printf("Congratulations! You have passed all the eight Anti-Debugging techniques :))\n");
	printf("Here is your flag: ");
	for (int i = 0; i < 38; i++) {
		printf("%c", flag_encode[i] ^ i);
	}
}

void antis1() {
	// RDTSC
	const DWORD qwNativeElapsed = 0x20;
	ULARGE_INTEGER Start, End;
	__asm {
		xor ecx, ecx
		rdtsc
		mov Start.LowPart, eax
		mov Start.HighPart, edx
	}
	__asm {
		xor ecx, ecx
		rdtsc
		mov End.LowPart, eax
		mov End.HighPart, edx
	}
	if (End.QuadPart - Start.QuadPart > qwNativeElapsed) {
		printf("Stop there!!!\n");
		printf("Caught by RDTSC\n");
		exit(0);
	}
	printf("Successfully passed RDTSC\n");
}

void antis2() {
	// BeingDebugged
	PPEB pPeb = (PPEB)__readfsdword(0x30);
	if (pPeb->BeingDebugged) {
		printf("Stop there!!!\n");
		printf("Caught by BeingDebugged\n");
		exit(0);
	}
	printf("Successfully passed BeingDebugged\n");
}

void antis3() {
	// CloseHandle
	_try{
		CloseHandle((HANDLE)0xDEADBEEF);
		printf("Successfully passed CloseHandle\n");
	}
	__except (EXCEPTION_INVALID_HANDLE == GetExceptionCode()
		? EXCEPTION_EXECUTE_HANDLER
		: EXCEPTION_CONTINUE_SEARCH) {
		printf("Stop there!!!\n");
		printf("Caught by CloseHandle\n");
		exit(0);
	}
}

void antis4() {
	// RaiseException
	__try {
		RaiseException(DBG_CONTROL_C, 0, 0, NULL);
		printf("Stop there!!!\n");
		printf("Caught by RaiseException\n");
		exit(0);
	}
	__except (DBG_CONTROL_C == GetExceptionCode()
		? EXCEPTION_EXECUTE_HANDLER
		: EXCEPTION_CONTINUE_SEARCH) {
		printf("Successfully passed RaiseException\n");
	}
}

void antis5() {
	// INT 3
	__try {
		__asm xor eax, eax;
		__asm int 3;
		printf("Stop there!!!\n");
		printf("Caught by INT 3\n");
		exit(0);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		printf("Successfully passed INT 3\n");
	}
}

DWORD GetParentProcessId(DWORD dwCurrentProcessId) {
	DWORD dwParentProcessId = -1;
	PROCESSENTRY32W ProcessEntry = { 0 };
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Process32FirstW(hSnapshot, &ProcessEntry)) {
		do {
			if (ProcessEntry.th32ProcessID == dwCurrentProcessId) {
				dwParentProcessId = ProcessEntry.th32ParentProcessID;
				break;
			}
		} while (Process32NextW(hSnapshot, &ProcessEntry));
	}
	CloseHandle(hSnapshot);
	return dwParentProcessId;
}

void antis6() {
	// CreateToolhelp32Snapshot() with cmd.exe - powershell.exe - explorer.exe
	bool bDebugged = false;
	DWORD dwParentProcessId = GetParentProcessId(GetCurrentProcessId());

	PROCESSENTRY32 ProcessEntry = { 0 };
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Process32First(hSnapshot, &ProcessEntry)) {
		do {
			if (ProcessEntry.th32ProcessID == dwParentProcessId) {
				if (wcscmp(ProcessEntry.szExeFile, L"cmd.exe") != 0 &&
					wcscmp(ProcessEntry.szExeFile, L"powershell.exe") != 0 &&
					wcscmp(ProcessEntry.szExeFile, L"explorer.exe") != 0)
				{
					bDebugged = true;
					break;
				}
			}
		} while (Process32Next(hSnapshot, &ProcessEntry));
	}

	CloseHandle(hSnapshot);
	if (bDebugged) {
		printf("Stop there!!!\n");
		printf("Caught by CreateToolhelp32Snapshot\n");
		exit(0);
	}
	printf("Successfully passed CreateToolhelp32Snapshot\n");
}

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

void antis7() {
	// Software Breakpoints (INT3)
	PVOID functionsToCheck[] = {
		& antis1,
		& antis2,
		& antis3,
		& antis4,
		//&antis5, // INT 3 so we can't check this function
		& antis6,
	};
	for (int i = 0; i < sizeof(functionsToCheck) / sizeof(PVOID); i++) {
		if (CheckForSpecificByte(0xCC, functionsToCheck[i])) {
			printf("Stop there!!!\n");
			printf("Caught by Software Breakpoints\n");
			exit(0);
		}
	}
	printf("Successfully passed Software Breakpoints\n");
}

void antis8() {
	// NtSetInformationThread
	typedef NTSTATUS(NTAPI* fp_NtSetInformationThread)(HANDLE ThreadHandle,
		THREAD_INFORMATION_CLASS ThreadInformationClass,
		PVOID ThreadInformation, ULONG ThreadInformationLength);

	HMODULE hNtdll = ::GetModuleHandle(L"ntdll.dll");
	if (hNtdll == NULL) {
		printf("Failed to get ntdll.dll\n");
		exit(0);
	}
	auto addr = ::GetProcAddress(hNtdll, "NtSetInformationThread");
	if (addr == NULL) {
		printf("Failed to get NtSetInformationThread\n");
		exit(0);
	}
	fp_NtSetInformationThread NtSetInformationThread = (fp_NtSetInformationThread)addr;
	NTSTATUS status = NtSetInformationThread(GetCurrentThread(), (THREAD_INFORMATION_CLASS)0x11, NULL, 0);
	if (status == 0) {
		printf("Successfully hide thread from Debugger\n");
		exit(0);
	}
	else {
		printf("Failed to hide thread from Debugger\n");
	}
}

int main() {
	antis1(); // Timing
	antis2(); // Debug Flags
	antis3(); // Object Handles
	antis4(); // Exceptions
	antis5(); // Assembly Instruction
	antis6(); // MISC
	antis7(); // Process Memory
	//antis8(); // Interactive Checks -> A bit of struggle because there is no thread except the main one
	antis0(); // Flag
	return 0;
}
//#include <stdio.h>
//#include <Windows.h>
//
//bool isDebugging() {
//	PROCESS_HEAP_ENTRY HeapEntry = { 0 };
//	do {
//		if (!HeapWalk(GetProcessHeap(), &HeapEntry))
//			return false;
//	} while (HeapEntry.wFlags != PROCESS_HEAP_ENTRY_BUSY);
//
//	PVOID pOverlapped = (PBYTE)HeapEntry.lpData + HeapEntry.cbData;
//	return ((DWORD)(*(PDWORD)pOverlapped) == 0xABABABAB);
//}
//
//int main() {
//	if (isDebugging())
//		printf("Hello from HeapProtection\n");
//	else
//		printf("Hello from main\n");
//	return 0;
//}
