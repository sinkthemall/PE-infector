ENTRY(WinMain)
. = 0x140000000;
SECTIONS
{
    .text : AT(. + 0x1000)
    {
        . = ALIGN(0x100);
        start.o(.text*)
        . = ALIGN(0x100);
        decryptor.o(.text*)
        . = ALIGN(0x100);
        shellcode.o(.text*)
    }
}
