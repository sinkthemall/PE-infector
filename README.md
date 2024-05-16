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
-   About Anti VM: I use cpuid for detection, if you using windows with hyperV enable, you probably gonna get VM detect message even you run it on physical OS. That's because, when hypervisor is enable, the host OS is still gonna run under virtualization (this will explain everything, in the limitation part: ![link](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/about/))
-   Currently I dont have time to implement some method such as: checking registry (for detect VM), capture process list and check for debugger, ... That will be story of another time.
-   There is no harm in the original code, but I still warn you to compile it instead of using my PE.
-   If you want to make the reverse task more challenging, you should add -s and -O3 flag to the last line( the ``gcc start.o decryptor.o shellcode.o -o final.o -m64 ...``) to strip all symbol and optimize code
