# PE-infector
A small project that infect itself (malicious payload) to other file and trigger when run
Use it widely, I won't be responsible for any damage cause by this project.
### Build
``make`` to build the project
``make clean`` to clean stuff(object file, .exe file), only keep the source
Final file: ``final.exe``


### What it does
- [x] TLS callback inject
- [x] Inject itself to anther file (in same directory)
- [x] Checking debugger (anti debug)
- [ ] Checking Virtualization (anti vm, curently only vmware and vbox, add more later)
- [ ] IAT patching
- [x] All shellcode, only .text section required

