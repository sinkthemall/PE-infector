#include <Windows.h>
#include <stdio.h>
#include "func-prototype.h"

int D_strncmp(char *buffer1, char *buffer2, size_t size) /// #define it, so it will not use lib
{
    for(size_t i = 0; i < size; ++i)
    {
        if  (buffer1[i] == buffer2[i])
            continue;
        if (buffer1[i] > buffer2[i])
            return 1;
        if (buffer1[i] < buffer2[i]) 
            return -1;
    }
    return 0;
}

BOOL detectCPUID_HypervisorBit()
{
    unsigned int ecx;
    __asm__(
        ".intel_syntax noprefix\n"
        "mov eax, 0x1\n"
        "cpuid\n"
        "mov %0, ecx\n"
        ".att_syntax\n"
        : "=r" (ecx)
        :
        : "eax", "ebx", "edx" 
    );
    if ((ecx >> 31) & 1)
        return TRUE;
    else return FALSE;
}

char aKVM[] __attribute__((section(".text"))) = "KVMKVMKVM\0\0\0";
char aHyperV[] __attribute__((section(".text"))) = "Microsoft Hv";
char aVMWare[] __attribute__((section(".text"))) = "VMwareVMware";
char aXen[] __attribute__((section(".text"))) = "XenVMMXenVMM";
char aParallels[] __attribute__((section(".text"))) = " lrpepyh  vr";
char aVirtualBox[] __attribute__((section(".text"))) = "VBoxVBoxVBox";



BOOL detectCPUID_ManufactureID(HANDLE kernel32, pGetProcAddress _GetProcAddress, pLoadLibraryA _LoadLibraryA) /// I dont know why I do this =)), just for fun, the checkHypervisorBit is already enough
{
    unsigned int ebx, ecx, edx ;
    unsigned char nameID[0x10] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    HMODULE hUser32 = _LoadLibraryA(aUser32);
    pMessageBoxA _MessageBoxA = (pMessageBoxA)_GetProcAddress(hUser32, aMessageBoxA);

    __asm__(
        ".intel_syntax noprefix\n"
        "mov eax, 0x40000000\n"
        "cpuid\n"
        "mov %0, ebx\n"
        "mov %1, ecx\n"
        "mov %2, edx\n"
        ".att_syntax\n"
        : "=r" (ebx),
            "=r" (ecx),
            "=r" (edx) 
        :
        : "eax", "ebx", "ecx", "edx"
    );
    
    *(unsigned int *)(&nameID[0]) = ebx;
    *(unsigned int *)(&nameID[4]) = ecx;
    *(unsigned int *)(&nameID[8]) = edx;

    _MessageBoxA(NULL, nameID, NULL, 0);
    if (!D_strncmp((char *)nameID, aKVM, 12))
    {
        // _MessageBoxA(NULL, aKVM, NULL, 0);
        return TRUE;
    }
    if (!D_strncmp((char *)nameID, aHyperV, 12))
    {
        // _MessageBoxA(NULL, aHyperV, NULL, 0);
        return TRUE;
    }
    if (!D_strncmp((char *)nameID, aVMWare, 12))
    {
        // _MessageBoxA(NULL, aVMWare, NULL, 0);
        return TRUE;
    }
    if (!D_strncmp((char *)nameID, aXen, 12))
    {
        // _MessageBoxA(NULL, aXen, NULL, 0);
        return TRUE;
    }
    if (!D_strncmp((char *)nameID, aParallels, 12))
    {
        // _MessageBoxA(NULL, aParallels, NULL, 0);
        return TRUE;
    }
    if (!D_strncmp((char *)nameID, aVirtualBox, 12))
    {
        // _MessageBoxA(NULL, aVirtualBox, NULL, 0);
        return TRUE;
    }   
    return FALSE;
}

