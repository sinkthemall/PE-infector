#pragma once
#include <Windows.h>
// #include <winternl.h>

#ifndef __NTDLL_H__

#ifndef TO_LOWERCASE
#define TO_LOWERCASE(c) ('a' <= c && c <= 'z' ? c : c - 'A' + 'a')
#endif

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;

} UNICODE_STRING, *PUNICODE_STRING;



typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;

} PEB_LDR_DATA, *PPEB_LDR_DATA;

// here we don't want to use any functions imported form extenal modules

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    void *BaseAddress;
    void *EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    HANDLE SectionHandle;
    ULONG CheckSum;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;

    // [...] this is a fragment, more elements follow here

} PEB, *PPEB;

#endif  //__NTDLL_H__

static inline LPVOID getModuleByName(WCHAR *name) {
    PPEB peb = NULL;
#if defined(_WIN64)
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif
    PPEB_LDR_DATA ldr = peb->Ldr;
    PLDR_DATA_TABLE_ENTRY currentModule = (PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;

    while (currentModule && currentModule->BaseAddress) {
        if (!currentModule->BaseDllName.Buffer) continue;
        WCHAR *currentName = currentModule->BaseDllName.Buffer;

        size_t i = 0;
        for (i = 0; name[i] != 0 && currentName[i] != 0; i++) {
            if (TO_LOWERCASE(name[i]) != TO_LOWERCASE(currentName[i])) break;
        }

        if (name[i] == 0 && currentName[i] == 0) {
            return currentModule->BaseAddress;
        }

        currentModule = (PLDR_DATA_TABLE_ENTRY)currentModule->InLoadOrderModuleList.Flink;
    }

    return NULL;
}

static inline LPVOID getFuncByName(HANDLE module, LPCSTR name) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)module + dosHeader->e_lfanew);
    PIMAGE_DATA_DIRECTORY dataDirectoryExports =
        &(ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (!dataDirectoryExports->VirtualAddress) {
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY exportsDirectory =
        (PIMAGE_EXPORT_DIRECTORY)(dataDirectoryExports->VirtualAddress + (ULONG_PTR)module);

    DWORD funcsListRVA = exportsDirectory->AddressOfFunctions;
    DWORD funcNamesListRVA = exportsDirectory->AddressOfNames;
    DWORD namesOrdsListRVA = exportsDirectory->AddressOfNameOrdinals;

    for (SIZE_T i = 0; i < exportsDirectory->NumberOfNames; i++) {
        PDWORD nameRVA = (PDWORD)(funcNamesListRVA + (BYTE *)module + i * sizeof(DWORD));
        PWORD nameIndex = (PWORD)(namesOrdsListRVA + (BYTE *)module + i * sizeof(WORD));
        PDWORD funcRVA = (PDWORD)(funcsListRVA + (BYTE *)module + (*nameIndex) * sizeof(DWORD));

        LPSTR currentName = (LPSTR)(*nameRVA + (BYTE *)module);

        size_t k = 0;
        for (k = 0; name[k] != 0 && currentName[k] != 0; k++) {
            if (name[k] != currentName[k]) break;
        }

        if (!name[k] && !currentName[k]) {
            return (BYTE *)module + (*funcRVA);
        }
    }

    return NULL;
}