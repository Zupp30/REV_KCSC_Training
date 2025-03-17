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