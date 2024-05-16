# main:
# 	gcc -o encryptor.exe encryptor.c
# 	nasm -f win64 -o start.o start.asm
# 	gcc start.o decryptor.c shellcode.c -o shellcode.exe -O2 -flto -Wall -Wextra -fdata-sections -ffunction-sections -fno-asynchronous-unwind-tables -fno-ident -nostdlib 
# 	# ./encryptor.exe

# main:
# 	
# 	nasm -f win64 -o start.o start.asm
# 	gcc start.o shellcode.c -o shellcode.exe -O2 -flto -Wall -Wextra -fdata-sections -ffunction-sections -fno-asynchronous-unwind-tables -fno-ident -nostdlib -T linkscript.ld
# 	# ./encryptor.exe
# main:
# 	gcc -o encryptor.exe encryptor.c
# 	nasm -f win64 -o start.o start.asm
# 	gcc start.o shellcode.c -o shellcode.exe -flto -g -Wall -Wextra -fdata-sections -ffunction-sections -fno-asynchronous-unwind-tables -fno-ident -nostdlib
# 	./encryptor.exe 
# main:
# 	gcc -o encryptor.exe encryptor.c
# 	nasm -f win64 -o start.o start.asm
# 	gcc shellcode.c -o shellcode.o -c -ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables -fno-ident -Wall -Wextra -nostdlib
# 	gcc decryptor.c -o decryptor.o -c -ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables -fno-ident -Wall -Wextra -nostdlib
# 	gcc start.o decryptor.o shellcode.o -o shellcode.exe -fno-pie -Wall -Wextra -fno-asynchronous-unwind-tables -fno-ident -nostdlib -Tlinkerscript.ld
# 	# ./encryptor.exe 
main:
	gcc -o encryptor.exe encryptor.c
	nasm -f win64 -o start.o start.asm
	gcc shellcode.c -o shellcode.o  -c -ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables -fno-ident -Wall -Wextra -nostdlib
	gcc decryptor.c -o decryptor.o -c -ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables -fno-ident -Wall -Wextra -nostdlib
	# gcc anti_debug.c -o anti_debug.o -c -ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables -fno-ident -Wall -Wextra -nostdlib
	
	gcc start.o decryptor.o shellcode.o -o final.o -m64 -fdata-sections -fno-asynchronous-unwind-tables -fno-ident -Wall -Wextra -nostdlib -Wl,-Tlinkerscript.ld,--no-seh
	ld final.o -o final.exe
	./encryptor.exe
run: shellcode.exe
	./shellcode.exe
clean:
	rm ./encryptor.exe ./decryptor.o ./shellcode.o ./start.o ./final.exe ./final.o