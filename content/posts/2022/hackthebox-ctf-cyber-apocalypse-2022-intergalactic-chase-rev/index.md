---
title: "HackTheBox CTF Cyber Apocalypse 2022: Intergalactic Chase (Reverse)"
date: 2022-05-21T21:15:40+02:00
draft: false
toc: true
images:
tags: 
  - ctf
---

[Hack The Box](https://www.hackthebox.com) was hosting a CTF event and we played together with some friends.

Here are some writeups for some of the reversing challenges i solved.

There's often shortcuts taken and (un)educated guesses involved...


# 0. TOC


1. [Without A Trace](#1-without-a-trace)

2. [Teleport](#2-teleport)

3. [Rebuilding](#3-rebuilding)

4. [Nuts and Bolts](#4-nuts-and-bolts)

5. [Shuffle Me](#5-shuffle-me)

6. [Snake Code](#6-snake-code)

7. [Freaky Forum Interception](#7-freaky-forum-interception)

8. [Indefinite](#8-indefinite)



# 1. Without A Trace

Original file [here](rev_without_a_trace.zip).

The ```check_password``` function calls ``` ptrace(PTRACE_ME) and use the return value as part of the flag decryption loop.

It's a classic antidebug trick, as if the process is being debugged already, the ptrace call will fail (a process can only be traced once) and the decrypted result will be garbage.

```C
ulong check_password(char *param_1)

{
    int iVar1;
    long ptrace_result;
    undefined4 extraout_var;
    long in_FS_OFFSET;
    uint n;
    undefined8 stack_string;
    undefined8 local_30;
    undefined8 local_28;
    undefined2 local_20;
    undefined local_1e;
    long local_10;
    
    ptrace_result = ptrace(PTRACE_TRACEME,0,0,0);
    stack_string = 0x1c4b0d0b043d2b37;
    local_30 = 0x200f0a204c12204c;
    local_28 = 0x184f18200a204b1d;
    local_20 = 0x24f;
    local_1e = 0;
    for (n = 0; n < 0x1a; n = n + 1) {
        *(byte *)((long)&stack_string + (long)(int)n) =
             *(byte *)((long)&stack_string + (long)(int)n) ^ (char)ptrace_result + 0x7fU;
    }
    /* strcmp */
    iVar1 = strcmp(param_1,(char *)&stack_string);
    
    return CONCAT44(extraout_var,iVar1) & 0xffffffffffffff00 | (ulong)(iVar1 == 0);
}
```

One way of going around that is to manipulate the ```ptrace``` return value to simulate a sucessful call.

We can just break at ```strcmp```afterwards and dump the string...

```
% gdb ./without_a_trace
pwndbg: loaded 198 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from ./without_a_trace...
(No debugging symbols found in ./without_a_trace)
pwndbg> break ptrace
Breakpoint 1 at 0x730
pwndbg> run
Starting program: ./without_a_trace
[+] Primary Mothership Tracking Panel
[X] Unusual activity detected
 |-------] Unrecognised login location: Earth
[X] Please verify your identity by entering your password > dsdsdsdsdsds

Breakpoint 1, ptrace (request=PTRACE_TRACEME) at ../sysdeps/unix/sysv/linux/ptrace.c:30

pwndbg> finish
pwndbg> set $rax=0
pwndbg> break strcmp
Breakpoint 2 at 0x7ffff7f282a0: file ../sysdeps/x86_64/multiarch/strcmp-avx2.S, line 106.
pwndbg> c
Continuing.
pwndbg> x/s $rsi
0x7fffffffe340:	"HTB{tr4c3_m3_up_b4_u_g0g0}"
```






# 2. Teleport

Original files [here](rev_teleport.zip).

```C
undefined8 main(int argc,char **argv)

{
    int iVar1;
    undefined8 uVar2;
    uint i;

    if (argc == 2) {
        strncpy(INPUT,argv[1],100);
        for (i = 0; i < 0x2b; i = i + 1) {
            (*(code *)(&PTR_FUN_00303020)[(int)i])();
        }
        iVar1 = _setjmp((__jmp_buf_tag *)&DAT_003031a0);
        if (iVar1 == 100) {
            puts("Looks good to me!");
        }
        else {
            if (iVar1 != 0x65) {
                    /* WARNING: Subroutine does not return */
                longjmp((__jmp_buf_tag *)(&DAT_00303300 + (long)iVar1 * 200),1);
            }
            puts("Something\'s wrong...");
        }
        uVar2 = 0;
    }
    else {
        puts("Missing password");
        uVar2 = 0xffffffff;
    }
    return uVar2;
}
```

we want to reach the ```Looks good to me```, just throw it angr and reuse some old script...

```python
#!/usr/bin/env python3

import angr
import claripy
import logging


BASE_ADDR = 0x400000


def rebase(addr):
    return BASE_ADDR + addr


def main():
    p = angr.Project('teleport')

    # 64 bytes argv[1]
    argv1 = claripy.BVS("argv1", 8*64)
    initial_state = p.factory.entry_state(args=["./teleport", argv1])

    sm = p.factory.simulation_manager(initial_state)

    # 0x1732 = good boy
    #  00101732 48 8d 3d ec 00 00 00     LEA                  argc,[s_Looks_good_to_me!_00101825]
    #  00101739 e8 a2 f2 ff ff           CALL                 <EXTERNAL>::puts

    # 0x1740 = nop
    #  00101740 48 8d 3d f0 00 00 00     LEA                  argc,[s_Something's_wrong..._00101837]
    #  00101747 e8 94 f2 ff ff           CALL                 <EXTERNAL>::puts

    sm.explore(find=rebase(0x1732), avoid=rebase(0x1740))

    if not len(sm.found):
        print("no solution")
        return 1


    found = sm.found[0]
    solution = found.solver.eval(argv1, cast_to=bytes)
    solution = solution[:solution.find(b'\x00')]
    return solution


if __name__ == "__main__":
    print([main()])

```

```
% python solve02.py
WARNING | 2022-05-21 10:11:38,350 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
WARNING | 2022-05-21 10:11:39,063 | angr.storage.memory_mixins.default_filler_mixin | The program is accessing memory with an unspecified value. This could indicate unwanted behavior.
WARNING | 2022-05-21 10:11:39,064 | angr.storage.memory_mixins.default_filler_mixin | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2022-05-21 10:11:39,064 | angr.storage.memory_mixins.default_filler_mixin | 1) setting a value to the initial state
WARNING | 2022-05-21 10:11:39,064 | angr.storage.memory_mixins.default_filler_mixin | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2022-05-21 10:11:39,064 | angr.storage.memory_mixins.default_filler_mixin | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to suppress these messages.
WARNING | 2022-05-21 10:11:39,064 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0x7fffffffffeff4c with 4 unconstrained bytes referenced from 0x400a25 (PLT.__cxa_finalize+0x15 in teleport (0xa25))
WARNING | 2022-05-21 10:11:39,147 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0x7ffffffffff0000 with 28 unconstrained bytes referenced from 0x78a620 (strncpy+0x0 in libc.so.6 (0x8a620))
[b'HTB{h0pp1ng_thru_th3_sp4c3_t1m3_c0nt1nuum!}\x80\x80']
```

not much reversing needed...



# 3. Rebuilding

Original files [here](rev_rebuilding.zip).

same as ```Teleport```, just fix the *find* and *avoid* offsets...

```python
#!/usr/bin/python

import angr
import claripy
import logging


BASE_ADDR = 0x400000


def rebase(addr):
    return BASE_ADDR + addr


def main():
    p = angr.Project('rebuilding')

    argv1 = claripy.BVS("argv1", 8*0x21)
    initial_state = p.factory.entry_state(args=["./rebuilding", argv1])

    sm = p.factory.simulation_manager(initial_state)
    sm.explore(find=rebase(0x000009f2), avoid=rebase(0x00000a05))

    if not len(sm.found):
        print("no solution")
        return 1


    found = sm.found[0]
    solution = found.solver.eval(argv1, cast_to=bytes)
    solution = solution[:solution.find(b'\x00')]
    return solution


if __name__ == "__main__":
    print([main()])

```


```
% python solve02.py
WARNING | 2022-05-21 10:20:18,366 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
WARNING | 2022-05-21 10:20:19,039 | angr.storage.memory_mixins.default_filler_mixin | The program is accessing memory with an unspecified value. This could indicate unwanted behavior.
WARNING | 2022-05-21 10:20:19,040 | angr.storage.memory_mixins.default_filler_mixin | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2022-05-21 10:20:19,040 | angr.storage.memory_mixins.default_filler_mixin | 1) setting a value to the initial state
WARNING | 2022-05-21 10:20:19,040 | angr.storage.memory_mixins.default_filler_mixin | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2022-05-21 10:20:19,040 | angr.storage.memory_mixins.default_filler_mixin | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to suppress these messages.
WARNING | 2022-05-21 10:20:19,040 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0x7fffffffffeff6c with 4 unconstrained bytes referenced from 0x400745 (_start+0x5 in rebuilding (0x745))
WARNING | 2022-05-21 10:20:19,180 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0x7ffffffffff0000 with 62 unconstrained bytes referenced from 0x78a410 (strlen+0x0 in libc.so.6 (0x8a410))
[b'HTB{h1d1ng_1n_c0nstruct0r5_1n1t}']
```



# 4. Nuts and Bolts

Original files [here](rev_nuts_and_bolts.zip).

It's Rust program, they are nice enough to give us the source code.

```rust
use std::io::{self, Read};
use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use nuts_and_bolts::StorageMethod;
use rand::Rng;


fn main() {
    let mut flag = [0u8; 64];
    io::stdin().read(&mut flag).expect("Flag not provided");

    let orig_key = rand::thread_rng().gen::<[u8; 32]>();
    let key = GenericArray::from(orig_key);
    let cipher = Aes256::new(&key);

    flag.chunks_mut(16).for_each(|block| {
        cipher.encrypt_block(GenericArray::from_mut_slice(block));
    });
    let mut key = StorageMethod::plain(orig_key);
    let mut flag = StorageMethod::plain(flag);
    let mut rng = rand::thread_rng();
    for _ in 0..10 {
        key = if rng.gen::<u8>() % 2 == 0 {
            key.reverse()
        } else {
            key.xor()
        };
        flag = if rng.gen::<u8>() % 2 == 0 {
            flag.reverse()
        } else {
            flag.xor()
        };
    }
    println!("Here's your key: {:?}!", bincode::serialize(&key).unwrap());
    println!("And here's your flag: {:?}!", bincode::serialize(&flag).unwrap());
}
```

and some output we need to reverse.

```
Here's your key: [2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 101, 19, 249, 222, 49, 245, 116, 246, 138, 161, 222, 65, 116, 18, 61, 227, 218, 154, 107, 172, 132, 119, 92, 126, 137, 33, 97, 243, 195, 200, 118, 12]!
And here's your flag: [2, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 196, 182, 72, 102, 37, 214, 250, 240, 211, 193, 251, 206, 179, 194, 23, 99, 88, 217, 216, 191, 130, 131, 52, 44, 174, 146, 211, 48, 39, 39, 20, 57, 144, 169, 11, 154, 215, 56, 164, 22, 46, 39, 71, 75, 208, 173, 225, 77, 2, 20, 34, 143, 222, 168, 158, 127, 15, 126, 143, 42, 125, 18, 239, 27]!
```


Basically it it generates a 32 bytes random key, AES encrypt the input flag with it, then performs a transformations on the key and output before printing it.

the applied transformation is either ```reverse``` or ```xor``` base on a random number % 2.

```reverse``` and ```xor``` are both methods of ``nuts_and_bolts::StorageMethod``` for which we do not have the source.

For ```reverse``` we assume it will just reverse the string (sorry :))

For ```xor``` we need to follow the breadcrumbs to ```nuts_and_bolts::StorageMethod<_>::xor``` -> ```nuts_and_bolts::StorageMethod<_>::xor_inner``` ->  ```for_each```

```C
void __thiscall
<core::slice::iter::IterMut<T>_as_core::iter::traits::iterator::Iterator>::for_each
          (<core::slice::iter::IterMut<T>_as_core::iter::traits::iterator::Iterator> *this,IterMut<u8> self,
          Option<&mut_u8> param_3)

{
    <core::slice::iter::IterMut<T>_as_core::iter::traits::iterator::Iterator> *local_40;
    Option<&mut_u8> local_38;
    {closure_env#0}<64> local_30 [8];
    Option<&mut_u8> local_28;
    Option<&mut_u8> local_20;
    Option<&mut_u8> local_8;

    local_40 = this;
    local_38 = param_3;
    while (param_3 = next((<core::slice::iter::IterMut<T>_as_core::iter::traits::iterator::Iterator> *)&local_40,
                          (IterMut<u8> *)param_3), param_3 != (Option<&mut_u8>)0x0) {
        local_28 = param_3;
        local_20 = param_3;
        local_8 = param_3;
        nuts_and_bolts::StorageMethod<_>::xor_inner::{{closure}}(local_30,(u8 *)param_3);
    }
    return;
}
```

and then ```nuts_and_bolts::StorageMethod<_>::xor_inner::{{closure}}```

```C

void nuts_and_bolts::StorageMethod<_>::xor_inner::{{closure}}({closure_env#0}<64> *param_1,u8 *v)

{
    *v = *v ^ 0xd;
    return;
}
```

from there i took another shortcut:
- the first half of the output (0, 1, 2) is potentially a hint on the transformations to apply

but:
- rev(rev(str)) == str
- xor(xor(str, 0xd), 0xd) == str

so maybe i can just try to bruteforce it, there's only 16 possibilites:

```python
from Crypto.Cipher import AES
from pwn import xor


# from output.txt
key = bytearray([101, 19, 249, 222, 49, 245, 116, 246, 138, 161, 222, 65, 116, 18, 61, 227, \
    218, 154, 107, 172, 132, 119, 92, 126, 137, 33, 97, 243, 195, 200, 118, 12])

msg = bytearray([196, 182, 72, 102, 37, 214, 250, 240, 211, 193, 251, 206, 179, 194, 23, 99, 88, \
    217, 216, 191, 130, 131, 52, 44, 174, 146, 211, 48, 39, 39, 20, 57, 144, 169, 11, 154, 215, \
    56, 164, 22, 46, 39, 71, 75, 208, 173, 225, 77, 2, 20, 34, 143, 222, 168, 158, 127, 15, \
    126, 143, 42, 125, 18, 239, 27])


# all keys 
keys = [key, key[::-1], xor(key, 0xd), xor(key[::-1], 0xd)]
# all msgs
msgs =  [msg, msg[::-1], xor(msg, 0xd), xor(msg[::-1], 0xd)]

for k in keys:
    for m in msgs:
        c = AES.new(k, AES.MODE_ECB)
        print(c.decrypt(m))

```

```
% python nab.py | grep HTB
b'HTB{ru5t_h45_t4gg3d_3num5_4nd_th3yr3_pr3tty_c00l}\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```



# 5. Shuffle Me

Original files [here](rev_shuffleme.zip).

This is one i need to get back to, because i honestly didnt take time to understand what it was doing...

I either missed the obvious or there's some solid voodoo going on, but nevertheless got it with some solid shortcuts and a lot of luck maybe

The binary is not stripped and we can see the following in the ``go``function:

```C
    extract_blob(key_blob,0x20,extracted_key_blob);
    extract_blob(data_blob,0x50,extracted_data_blob);
```

there's also ```EVP_aes_256_cbc``` in the imports.

```
% readelf -r shuffleme | grep EVP
000000202020  000600000007 R_X86_64_JUMP_SLO 0000000000000000 EVP_CIPHER_key_length@OPENSSL_1_1_0 + 0
000000202060  001200000007 R_X86_64_JUMP_SLO 0000000000000000 EVP_CIPHER_CTX_new@OPENSSL_1_1_0 + 0
0000002020d8  001600000007 R_X86_64_JUMP_SLO 0000000000000000 EVP_aes_256_cbc@OPENSSL_1_1_0 + 0
0000002020d0  001800000007 R_X86_64_JUMP_SLO 0000000000000000 EVP_CIPHER_iv_length@OPENSSL_1_1_0 + 0
000000202078  001b00000007 R_X86_64_JUMP_SLO 0000000000000000 EVP_CIPHER_CTX_free@OPENSSL_1_1_0 + 0
0000002020c8  001d00000007 R_X86_64_JUMP_SLO 0000000000000000 EVP_EncryptFinal_ex@OPENSSL_1_1_0 + 0
0000002020b8  001f00000007 R_X86_64_JUMP_SLO 0000000000000000 EVP_EncryptInit_ex@OPENSSL_1_1_0 + 0
000000202028  002000000007 R_X86_64_JUMP_SLO 0000000000000000 EVP_EncryptUpdate@OPENSSL_1_1_0 + 0
```

anyhow, i dumped the extracted key and data blob with gdb:

```
   0x0000555555400f7f <+45>:	lea    rdi,[rip+0x2012da]        # 0x555555602260 <key_blob>
   0x0000555555400f86 <+52>:	call   0x555555401005 <extract_blob>
...
   0x0000555555400f9e <+76>:	call   0x555555401005 <extract_blob>
   0x0000555555400fa3 <+81>:	mov    rax,QWORD PTR [rbp-0x88]

pwndbg> break *go+52
Breakpoint 2 at 0x555555400f86
pwndbg> break *go+57
Breakpoint 3 at 0x555555400f8b
pwndbg> break *go+76
Breakpoint 4 at 0x555555400f9e
pwndbg> break *go+81
Breakpoint 5 at 0x555555400fa3
pwndbg> c
...
 ► 0x555555400f86 <go+52>    call   extract_blob                <extract_blob>
        rdi: 0x555555602260 (key_blob) ◂— 0x9f21016cc238d330
        rsi: 0x20
        rdx: 0x7fffffffe340 ◂— 0x0
        rcx: 0xfffffa00
pwndbg> c
pwndbg> x/32bx 0x7fffffffe340
0x7fffffffe340:	0x30	0x6c	0x03	0x7c	0x45	0xb0	0x41	0x32
0x7fffffffe348:	0xc0	0xc3	0xa7	0xb0	0x7f	0x72	0xcd	0x94
0x7fffffffe350:	0x75	0x8f	0x49	0x8b	0xb1	0xd8	0x3a	0x03
0x7fffffffe358:	0xd4	0x2f	0xa4	0x49	0x91	0x59	0x27	0xe7
pwndbg> c
...
► 0x555555400f9e <go+76>    call   extract_blob                <extract_blob>
        rdi: 0x555555602120 (data_blob) ◂— 0xf8f1725539de5807
        rsi: 0x50
        rdx: 0x7fffffffe360 ◂— 0x0
        rcx: 0x7ffff7ffe050 (_rtld_global+4112) ◂— 0x7ffff7ffe050
pwndbg> c
pwndbg> x/80bx 0x7fffffffe360
0x7fffffffe360:	0x07	0x55	0xc5	0x7a	0x53	0xd9	0x3e	0xef
0x7fffffffe368:	0xcc	0xe9	0x39	0x7c	0xa8	0xa2	0x66	0x8f
0x7fffffffe370:	0x66	0x56	0x3a	0x17	0x84	0xbd	0xf5	0x2a
0x7fffffffe378:	0x4b	0xca	0x25	0x5a	0x2d	0x87	0xa0	0x8a
0x7fffffffe380:	0x04	0x94	0xd2	0x72	0x0e	0xb7	0xc6	0xf9
0x7fffffffe388:	0xf9	0xcd	0x91	0x0e	0x22	0x90	0xfc	0x15
0x7fffffffe390:	0xe6	0xd2	0x49	0x6a	0x74	0x38	0x86	0xdb
0x7fffffffe398:	0xca	0x0e	0xbd	0x7c	0x9c	0xe1	0x57	0xf0
0x7fffffffe3a0:	0x44	0x59	0x5a	0x10	0x1b	0xd4	0x6f	0x33
0x7fffffffe3a8:	0xe8	0x95	0xc3	0x82	0x67	0x96	0xb6	0x61
```

The extracted values are not dependant on the argv[1] input.

Then i decided to try AES on them, beause the length of the blob fits nicely into AES blocks, and... why not after all, doesnt take much time.

```python
>>> key = [
...     0x30, 0x6c, 0x03, 0x7c, 0x45, 0xb0, 0x41, 0x32,
...     0xc0, 0xc3, 0xa7, 0xb0, 0x7f, 0x72, 0xcd, 0x94,
...     0x75, 0x8f, 0x49, 0x8b, 0xb1, 0xd8, 0x3a, 0x03,
...     0xd4, 0x2f, 0xa4, 0x49, 0x91, 0x59, 0x27, 0xe7
... ]
>>>
>>> data = [
...     0x07, 0x55, 0xc5, 0x7a, 0x53, 0xd9, 0x3e, 0xef,
...     0xcc, 0xe9, 0x39, 0x7c, 0xa8, 0xa2, 0x66, 0x8f,
...     0x66, 0x56, 0x3a, 0x17, 0x84, 0xbd, 0xf5, 0x2a,
...     0x4b, 0xca, 0x25, 0x5a, 0x2d, 0x87, 0xa0, 0x8a,
...     0x04, 0x94, 0xd2, 0x72, 0x0e, 0xb7, 0xc6, 0xf9,
...     0xf9, 0xcd, 0x91, 0x0e, 0x22, 0x90, 0xfc, 0x15,
...     0xe6, 0xd2, 0x49, 0x6a, 0x74, 0x38, 0x86, 0xdb,
...     0xca, 0x0e, 0xbd, 0x7c, 0x9c, 0xe1, 0x57, 0xf0,
...     0x44, 0x59, 0x5a, 0x10, 0x1b, 0xd4, 0x6f, 0x33,
...     0xe8, 0x95, 0xc3, 0x82, 0x67, 0x96, 0xb6, 0x61
... ]
>>>
>>> key = bytearray(key)
>>> data = bytearray(data)
>>>
>>> from Crypto.Cipher import AES
>>>
>>> c = AES.new(key, AES.MODE_CBC)
>>> c.decrypt(data)
b'\x86#\x81s\xb3\x04\xcd\x01\x80\xa8\xeb4\x0eL\x90z3_4nd_sw1tch1ng_th3r3-1t5_m0r3_th4n_1_c4n_b34r!}\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
```

I tried CBC first because of the import, the 1st block is garbage but then there's something looking like a flag.

At this point, why not try ECB too, i mean it's been a train of stupid but working ideas so far... :)

```python
>>> c = AES.new(key, AES.MODE_ECB)
>>> c.decrypt(data)
b'HTB{sw4pp1ng_h3r4\n\xf1\x147\x86M\x98\xfd\x9dZ\x14\x99\xcc\x01\xd0\x12>\te\xb7\x90\xc4^~\x95Hj_\xb4\xff\xfel\xa0\xbc-?\xe8\xa5\xcd\x97\x92\xf3=\x16\xe2\xddh\xf6\xc2Yzd(\x96\xcb\xda\x1e\xadl\x8c\xf1G\xe0'
```

the the first part of the flag is revealed.

not really proud of myself on this one but a flag is a flag!




# 6. Snake Code

Original files [here](rev_snakecode.zip).

This is a pure python challenge, we starts by using uncompyle6 on the pyc file.

It yields some proper code:

```python
# uncompyle6 version 3.5.0
# Python bytecode 2.7 (62211)
# Decompiled from: Python 2.7.5 (default, Nov 16 2020, 22:23:17)
# [GCC 4.8.5 20150623 (Red Hat 4.8.5-44)]
# Embedded file name: ./snake_obf.py
# Compiled at: 2022-01-18 06:16:46
import marshal, types, time
ll = types.FunctionType(marshal.loads(('YwEAAAABAAAABQAAAEMAAABzNAAAAHQAAGoBAHQCAGoDAHQEAGQBAIMBAGoFAHwAAGoGAGQCAIMB\nAIMBAIMBAHQHAIMAAIMCAFMoAwAAAE50BAAAAHpsaWJ0BgAAAGJhc2U2NCgIAAAAdAUAAAB0eXBl\nc3QMAAAARnVuY3Rpb25UeXBldAcAAABtYXJzaGFsdAUAAABsb2Fkc3QKAAAAX19pbXBvcnRfX3QK\nAAAAZGVjb21wcmVzc3QGAAAAZGVjb2RldAcAAABnbG9iYWxzKAEAAAB0AQAAAHMoAAAAACgAAAAA\ncwcAAAA8c3RkaW4+dAoAAABsb2FkTGFtYmRhAQAAAHQAAAAA\n').decode('base64')), globals())
i0 = ll('eJxLZoACJiB2BuJiLiBRwsCQwsjQzMgQrAES9ythA5JFiXkp+bkajCB5kKL4+Mzcgvyikvh4DZAB\nCKKYHUjYFJekZObZlXCA2DmJuUkpiXaMEKMZGAC+nBJh\n')
i1 = ll('eJxLZoACJiB2BuJiLiBRwsCQwsjQzMgQrAES9ythA5LJpUXFqcUajCB5kKL4+Mzcgvyikvh4DZAB\nCKKYHUjYFJekZObZlXCA2DmJuUkpiXaMEKMZGADEORJ1\n')
f0 = ll('eJxLZmRgYABhJiB2BuJiXiBRw8CQxcCQwsjQzMgQrAGS8ssEEgwaIJUl7CAiMzc1v7QEIsAMJMoz\n8zTASkBEMUiJTXFJSmaeXQkHiJ2TmJuUkmgHVg5SAQBjWRD5\n')
#...
#...
#...
def snake(w):
    r = i0()
    c = i1()
    f0(w)
    d = (0, 1)
    p = [(5, 5)]
    pl = 1
    s = 0
    l = None
    while 1:
        p, d, pl, l, s, w, c, r = m2(p, d, pl, l, s, w, c, r)
        time.sleep(0.4)

    return


i1().wrapper(snake)
```

clearly the ``ll`` function loads more code.

We can reverse marshall'd code using [marshal-to-pyc.py](https://gist.github.com/stecman/3751ac494795164efa82a683130cabe5#file-marshal-to-pyc-py)

```python
$ echo -n $'YwEAAAABAAAABQAAAEMAAABzNAAAAHQAAGoBAHQCAGoDAHQEAGQBAIMBAGoFAHwAAGoGAGQCAIMB\nAIMBAIMBAHQHAIMAAIMCAFMoAwAAAE50BAAAAHpsaWJ0BgAAAGJhc2U2NCgIAAAAdAUAAAB0eXBl\nc3QMAAAARnVuY3Rpb25UeXBldAcAAABtYXJzaGFsdAUAAABsb2Fkc3QKAAAAX19pbXBvcnRfX3QK\nAAAAZGVjb21wcmVzc3QGAAAAZGVjb2RldAcAAABnbG9iYWxzKAEAAAB0AQAAAHMoAAAAACgAAAAA\ncwcAAAA8c3RkaW4+dAoAAABsb2FkTGFtYmRhAQAAAHQAAAAA\n' | base64 -d  > ll.bin

$ python marshal-to-pyc.py ll.bin

$  cat ll.bin.py
# uncompyle6 version 3.8.0
# Python bytecode 2.7 (62211)
# Decompiled from: Python 2.7.16 (default, Oct 10 2019, 22:02:15) 
# [GCC 8.3.0]
# Warning: this version of Python has problems handling the Python 3 byte type in constants properly.

# Embedded file name: <stdin>
# Compiled at: 2022-05-21 08:34:32
return types.FunctionType(marshal.loads(__import__('zlib').decompress(s.decode('base64'))), globals())
```

All we have to do now is to decompile the rest of the functions, we just need to ```zlib.decompress``` them.

I quickly modified the intial file so that ``ll`` dumps me the data to files:

```python
def ll(name, data):
    with open("out/"+name, "wb") as fp:
        fp.write(zlib.decompress(data.decode("base64")))

i0 = ll("i0", 'eJxLZoACJiB2BuJiLiBRwsCQwsjQzMgQrAES9ythA5JFiXkp+bkajCB5kKL4+Mzcgvyikvh4DZAB\nCKKYHUjYFJekZObZlXCA2DmJuUkpiXaMEKMZGAC+nBJh\n')
i1 = ll("i1", 'eJxLZoACJiB2BuJiLiBRwsCQwsjQzMgQrAES9ythA5LJpUXFqcUajCB5kKL4+Mzcgvyikvh4DZAB\nCKKYHUjYFJekZObZlXCA2DmJuUkpiXaMEKMZGADEORJ1\n')
f0 = ll("f0", 'eJxLZmRgYABhJiB2BuJiXiBRw8CQxcCQwsjQzMgQrAGS8ssEEgwaIJUl7CAiMzc1v7QEIsAMJMoz\n8zTASkBEMUiJTXFJSmaeXQkHiJ2TmJuUkmgHVg5SAQBjWRD5\n')
# etc...
```

```
out$ ls
a1  a2  a4  a5  a6  a7  a8  a9  f0  f1  f2  f3  f4  f5  f6  f7  f8  i0  i1  m0  m1  m2

out$ for x in *; do python ../marshal-to-pyc.py $x; done

out$ cat a2.py
# uncompyle6 version 3.8.0
# Python bytecode 2.7 (62211)
# Decompiled from: Python 2.7.16 (default, Oct 10 2019, 22:02:15) 
# [GCC 8.3.0]
# Warning: this version of Python has problems handling the Python 3 byte type in constants properly.

# Embedded file name: <stdin>
# Compiled at: 2022-05-21 08:39:47
f = ['H', 'T', 'B', '{', 'S', 'u', 'P', '3', 'r', '_', 'S', '3', 'C', 'R', 't', '_', 'S', 'n', '4', 'k', '3', 'c', '0', 'd', '3', '}']
return f[(pl / 5 % len(f))](venv2) 

out$ python
>>> f = ['H', 'T', 'B', '{', 'S', 'u', 'P', '3', 'r', '_', 'S', '3', 'C', 'R', 't', '_', 'S', 'n', '4', 'k', '3', 'c', '0', 'd', '3', '}']
>>> 
>>> ''.join(f)
'HTB{SuP3r_S3CRt_Sn4k3c0d3}'
```


# 7. Freaky Forum Interception

Original files [here](rev_ffi.zip).


This one makes heavy use of [FFI](https://en.wikipedia.org/wiki/Foreign_function_interface), which makes it one big mess :-)

If we start with the ```main``` function, we understand that the flag will need to be of the following format:

```HTB{part1_part2_part3_part4}```

- part1 will be validated by the ```GoCheck```function
- part2 will be validated by the ```rust_check``` function
- part3 will be validated by the ```python_check``` function
- part4 will be validated by the ```java_check```function.

## 7.1 GoCheck

If you deal with Go with Ghidra, you might want to check the ```Decompiler Parameter ID```in the analysis option (by pressing 'A') - otherwise most function calls will look like they have no parameters.

Basically there's a channel between ```main.Waiter``` and ```main.Oracle```.

The ```main.Oracle``` is feeding expected characters and positions read from the data pointed by ```main.g```

```
                         main.g                                                       XREF[1]:   main.Oracle:001b6c92(R)  
      003491f0 40 bd 34 00 00 00 00     addr                 main..stmp_0
               00
```

we can quickly dump the table with GDB

```
 ► 0x55555560accb <main.Oracle+107>    mov    rdx, qword ptr [rcx]          <main..stmp_0>

pwndbg> x/16gx $rcx
0x55555579fd40 <main..stmp_0>:  	0x0000000000000002	0x0000000000000074
0x55555579fd50 <main..stmp_0+16>:	0x0000000000000006	0x0000000000000067
0x55555579fd60 <main..stmp_0+32>:	0x0000000000000003	0x0000000000000074
0x55555579fd70 <main..stmp_0+48>:	0x0000000000000004	0x0000000000000031
0x55555579fd80 <main..stmp_0+64>:	0x0000000000000001	0x0000000000000033
0x55555579fd90 <main..stmp_0+80>:	0x0000000000000000	0x0000000000000067
0x55555579fda0 <main..stmp_0+96>:	0x0000000000000005	0x000000000000006e
0x55555579fdb0:	0x0000000000000000	0x0000000000000000
```

first "column" is the position, 2nd one is the character

```
>>> chr(0x0000000000000067) + chr(0x0000000000000033) + chr(0x0000000000000074) + chr(0x0000000000000074) + chr(0x0000000000000031) + chr(0x000000000000006e) + chr(0x0000000000000067)
'g3tt1ng'
```


## 7.2 rust_check

It starts by checking the length of the flag part which must be 6 characters

then checks that the sum of all input chars is 0x223

```C
    if (param_2 == 6) {
        bVar2 = *input_flag;
        if ((byte)(~bVar2 & ((byte)(bVar2 + 0xbf) < 0x1a) << 5) == 0) {
            bVar3 = input_flag[1];
            if ((byte)(~bVar3 & ((byte)(bVar3 + 0xbf) < 0x1a) << 5) == 0) {
                bVar4 = input_flag[2];
                if ((byte)(~bVar4 & ((byte)(bVar4 + 0xbf) < 0x1a) << 5) == 0) {
                    bVar5 = input_flag[3];
                    if ((byte)(~bVar5 & ((byte)(bVar5 + 0xbf) < 0x1a) << 5) == 0) {
                        bVar6 = input_flag[4];
                        if ((byte)(~bVar6 & ((byte)(bVar6 + 0xbf) < 0x1a) << 5) == 0) {
                            bVar7 = input_flag[5];
                            if (((byte)(~bVar7 & ((byte)(bVar7 + 0xbf) < 0x1a) << 5) == 0) &&
                               ((uint)bVar7 + (uint)bVar6 + (uint)bVar5 + (uint)bVar4 + (uint)bVar2 + (uint)bVar3 == 0x223)) {
```


later on it checks that:
```C
 ((((((ulong)*input_flag * 3 + (ulong)input_flag[1]) * 3 + (ulong)input_flag[2]) * 3 +
  (ulong)input_flag[3]) * 3 + (ulong)input_flag[4]) * 3 + (ulong)input_flag[5] == 0x8dd3))
```

then it calls this from_iter() and build and compare the resulting array to some hardcoded table.

```C
  <alloc::vec::Vec<T>as_alloc::vec::spec_from_iter::SpecFromIter<T,I>>::from_iter
            (&local_68,(long *)&ptr_input_flag);
  if (local_58 == 6) {
      iVar8 = bcmp(local_68,QWORD_ARRAY_00279ca0,0x30);
      bVar10 = iVar8 == 0;
  }
```


This ```from_iter``` function sums the first and last chr, the 2nd and before-last, etc...
```C
    flag_chr0 = *param_2;
    flag_char1 = param_2[1];
    flag_char2 = param_2[2];
    flag_char3 = param_2[3];

            lVar1 = flag_chr0;
        for (; (lVar1 != flag_char1 && (flag_char3 != flag_char2)); flag_char3 = flag_char3 + -1) {
            *(ulong *)(buffer + i * 8) = (ulong)*(byte *)(flag_char3 + -1) + (ulong)*(byte *)(flag_chr0 + i);
            lVar1 = flag_chr0 + i + 1;
            i = i + 1;
        }
        param_1[2] = i;
```

if we dump the table we are looking for we have enough informations to guess this part of the flag:
```
pwndbg> x/48bx $rsi
0x5555556cdca0:	0xdf	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x5555556cdca8:	0xdd	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x5555556cdcb0:	0x67	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x5555556cdcb8:	0x67	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x5555556cdcc0:	0xdd	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x5555556cdcc8:	0xdf	0x00	0x00	0x00	0x00	0x00	0x00	0x00
```

which means we need:
```
flag[0] + flag[5] == 0xdf
flag[1] + flag[4] == 0xdd
flag[2] + flag[3] == 0x67
```

we can use the following script to bruteforce a bit and make us stop reversing rust, or we can keep reversing.

I chose the lazy way, sorry

```
from z3 import *
from pwn import *
import sys

FLAG = "HTB{g3tt1ng_%s_part3_part4}"

s = Solver()
flag = []
for x in range(6):
    c = BitVec('f%d'%x, 8)
    flag.append(c)
    s.add(
            Or(
                And(c >= 48, c < 65),
                And(c > 90, c <= 122)
            )
            )

s.add(flag[0] + flag[1] + flag[2] + flag[3] + flag[4] + flag[5] == 0x223)
s.add(((((flag[0] * 3 + flag[1]) * 3 + flag[2]) * 3 + flag[3]) * 3 + flag[4]) * 3 + flag[5] == 0x8dd3)

s.add(flag[0] + flag[5] == 0xdf)
s.add(flag[1] + flag[4] == 0xdd)
s.add(flag[2] + flag[3] == 0x67)



context.log_level = 'error'

def check(password):
    io = process("./ffi")
    io.sendline(bytes(FLAG%password, 'ascii'))
    if b'Rust says no!' not in io.recv(1024):
        print(FLAG%password)
        sys.exit(0)

    io.close()



while s.check() == sat:
    m = s.model()
    condition = []

    out = ""
    for x in range(len(flag)):
        c = m[flag[x]].as_long()
        out += chr(c)

        condition.append(flag[x] != int(m[flag[x]].as_long()))
    s.add(Or(condition))

    check(out)
```


```
% python rust_gen2.py
HTB{g3tt1ng_fr34ky_part3_part4}
```


## 7.3 python_check

the python check expects a 5 chrs flag

```C
    if (len == 5) {
        Py_Initialize();
        seed(0x7a69);
        py_method = (long *)PyCMethod_New(GenDef,0,0);
        for (i = 0; i < 5; i = i + 1) {
            uVar1 = PyObject_CallNoArgs(py_method);
            key_char = PyLong_AsLong(uVar1);
            Py_DecRef(uVar1);
            if ((local_1e == '\0') || ((uint)*(byte *)((long)&secret + (long)i) != ((int)flag[i] ^ (uint)key_char))) {
                local_1e = '\0';
            }
            else {
                local_1e = '\x01';
            }
        }
```


the ```seed``` function  sets the seed:

```C
void seed(int param_1)

{
    long *plVar1;
    undefined8 uVar2;
    long *plVar3;
    
    randomMod = PyImport_ImportModule("random");
    plVar1 = (long *)PyObject_GetAttrString(randomMod,"seed");
    uVar2 = PyLong_FromLong((long)param_1);
    plVar3 = (long *)PyTuple_New(1);
    PyTuple_SetItem(plVar3,0,uVar2);
    PyObject_CallObject(plVar1,plVar3);
    _Py_DECREF(plVar3);
    _Py_DECREF(plVar1);
    return;
}
```

- it initializes the seed with 0x7a69
- then for every chrs
  - calls a python method
  - cast the result to long
  - check that flag[i] ^ result == secret[i]

The value of ```secret``` is no secret:
```
                         secret                                                       XREF[2]:   python_check:00267dd3(*), python_check:00267dda(R)
      0034b8b0 22 af 2d 26 3b           undefined5           002DAF223Bh
```


The ```PyCMethod_New```first argument must be a [PyMethodDef](https://docs.python.org/3/c-api/structures.html#c.PyMethodDef). (*see methodobject.h*)

```C
struct PyMethodDef {
    const char  *ml_name;   /* The name of the built-in function/method */
    PyCFunction ml_meth;    /* The C function that implements it */
    int         ml_flags;   /* Combination of METH_xxx flags, which mostly
                               describe the args expected by the C func */
    const char  *ml_doc;    /* The __doc__ attribute, or NULL */
};
typedef struct PyMethodDef PyMethodDef;
```

so if we quickly cast 4 pointers in place of "GenDef" we get:

```
                         GenDef                                                       XREF[1]:   python_check:00267d84(*)
      0034b8c0 24 f6 29 00 00 00 00     addr                 s_rand_stream_0029f624                                                                   = "rand_stream"
               00
      0034b8c8 c0 7c 26 00 00 00 00     addr                 GetNum
               00
      0034b8d0 80 00 00 00 00 00 00     addr                 DAT_00000080
               00
      0034b8d8 00 00 00 00 00 00 00     addr                 00000000
               00
```

and the ```GetNum``` function

```C
long * GetNum(void)

{
    long *plVar1;
    long *plVar2;
    long *plVar3;
    
    plVar1 = (long *)PyObject_GetAttrString(randomMod,"randrange");
    plVar2 = (long *)PyLong_FromLong(0x100);
    plVar3 = (long *)PyObject_CallOneArg((long)plVar1,(long)plVar2);
    _Py_DECREF(plVar1);
    _Py_DECREF(plVar2);
    _Py_INCREF(plVar3);
    return plVar3;
}
```


we can easily reimplement it in python:

```python
import random

random.seed(0x7a69)

secret = [0x22, 0xaf, 0x2d, 0x26, 0x3b]

flag = ''
for s in secret:
    v = random.randrange(0x100)
    flag += chr(s ^ v)

print(flag)
```

```
% python pyt_check.py
u51Ng
```


## 7.4 java_check

Whenever you have to deal with JNI, start by loading the proper jni.h header (you can get one which works for ghidra: [https://github.com/extremecoders-re/ghidra-jni](https://github.com/extremecoders-re/ghidra-jni)).

then you can cast the JNIEnv and JavaVM, and everything becomes clear :)


```C
    JNIEnv *env;
    JavaVM jvm;

    iVar2 = JNI_CreateJavaVM(&jvm,&env,&local_28);
    if (iVar2 == 0) {
        local_40 = (*(*env)->DefineClass)(env,"Checker",NULL,(jbyte *)Class,0x752);
        (*(*env)->ExceptionDescribe)(env);
        if (local_40 == NULL) {
            puts("Failed to find Checker class");
            bVar3 = true;
        }
        else {
            local_38 = (*(*env)->GetStaticMethodID)(env,local_40,"hello_java","(Ljava/lang/String;)Z");
            if (local_38 == NULL) {
                puts("Failed to find main function");
                bVar3 = true;
            }
            else {
                local_30 = (*(*env)->NewStringUTF)(env,utf);
                jVar1 = (*(*env)->CallStaticBooleanMethod)(env,local_40,local_38,local_30);
                bVar3 = jVar1 != '\0';
                free(utf);
            }
        }
    }
```


so it starts by loading a ```Checker```class from 0x752 bytes binary blob ```Class```
```C
local_40 = (*(*env)->DefineClass)(env,"Checker",NULL,(jbyte *)Class,0x752);
```

notice the java magic string cafebabe, it's a class file.
```
                         Class                                                        XREF[2]:   Entry Point(*), java_check:00267f6f(*)
      0029f722 ca fe ba be 00 00 00     db[1874]
               37 00 61 0a 00 0b 00
               1d 0a 00 1e 00 1f 0
         0029f722 [0]           CAh, FEh, BAh, BEh
         0029f726 [4]            0h,  0h,  0h, 37h
         0029f72a [8]            0h, 61h,  Ah,  0h
         0029f72e [12]           Bh,  0h, 1Dh,  Ah
```

export the class file, use [jadx](https://github.com/skylot/jadx) or so to decompile it:

```java
import java.util.stream.IntStream;

/* renamed from: Checker */
/* loaded from: java.class */
public class Checker {
    public static boolean hello_java(String str) {
        int[] iArr = {219, 227, 209, 154, 104, 97, 158, 163};
        return IntStream.range(0, str.length() - 1).mapToObj(i -> {
            return new Object[]{Integer.valueOf(i), Integer.valueOf(str.charAt(i)), Integer.valueOf(str.charAt(i + 1))};
        }).filter(objArr -> {
            return ((Integer) objArr[1]).intValue() + ((Integer) objArr[2]).intValue() == iArr[((Integer) objArr[0]).intValue()];
        }).count() == ((long) (str.length() - 1));
    }
}
```


what it does is, if you input the string ```ABC```, it build an array like
```
[
 [0, 0x41 /* A */, 0x42 /* B */]
 [1, 0x42 /* B */, 0x43 /* C */]
 [1, 0x43 /* C */, 0x44 /* D */]
]
```
and then check that:
```
 0x41 + 0x42 = iArr[0]
 0x42 + 0x43 = iArr[1]
 0x43 + 0x43 = iArr[2]
```

we can quickly reverse it:

```python

from z3 import *

iArr = [219, 227, 209, 154, 104, 97, 158, 163]

LEN = 9
flag = []

s = Solver()

for c in range(LEN):
    e = BitVec('c%d'%c, 8)
    flag.append(e)
    s.add(And(e >= 33, e <= 122))



for c in range(LEN - 1):
    s.add(flag[c] + flag[c + 1] == iArr[c])

out = ''
while s.check() == sat:
    m = s.model()
    condition = []

    out = ""
    for x in range(len(flag)):
        c = m[flag[x]].as_long()
        out += chr(c)

        condition.append(flag[x] != int(m[flag[x]].as_long()))
    s.add(Or(condition))

    print(out)
```

```
% python java_solver.py
irq`:.3k8
dwle53.p3
lot]=+6h;
kps^<,5i:
jqr_;-4j9
func710n5       << looking promising
gtob801m6
hspa9/2l7
nmv[?)8f=
pkxYA':d?
olwZ@(9e>
evmd62/o4
mnu\>*7g<
byjg35,r1
rizWC%<bA
cxkf44-q2
azih26+s0
qjyXB&;c@
```


```
% ./ffi
HTB{g3tt1ng_fr34ky_u51Ng_func710n5}
Correct!
```


notes: there program would validate other inputs for the java part:
```
% ./ffi                                      
HTB{g3tt1ng_fr34ky_u51Ng_gtob801m6}
Correct!

```

and the go function is just bugged:

```
% ./ffi
HTB{sxxxxxx_fr34ky_u51Ng_hspa9/2l7}
Correct!
```


# 8. Indefinite

Original files [here](rev_indefinite.zip).

I really liked this one because it implements nanomites.

It starts by forking:
- the child process will do the work
- the parent process will attach to the child process and "drive" it

```C
undefined8 main(int argc,char **argv)

{
    uint pid;
    
    if (argc != 2) {
        exit(-1);
    }
                    /* make text segment PROT_READ|PROT_WRITE|PROT_EXEC */
    mprotect((void *)0x101000,0x1000,7);
    pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME,0,0,0);
        child(argv[1]);
    }
    else {
        wait(NULL);
        ptrace(PTRACE_CONT,(ulong)pid,0,0);
        tracer(pid);
    }
    return 0;
}
```

let's first have a look at the ```child``` function

it will read 8 bytes from /dev/urandom and encrypt the file passed as argv[1]

```
    fd = fopen("/dev/urandom","r");
    fread(&buffer,8,1,fd);
    fclose(fd);
    do_encrypt_file(filename,0,buffer);
```

now let's look at the ```do_encrypt``` function:

```
                         *******************************************************
                         *                                                     *
                         *  FUNCTION                                           *
                         *******************************************************
                         undefined do_encrypt_file()
           undefined       AL:1           <RETURN>
                         do_encrypt_file                                              XREF[4]:   Entry Point(*), child:001014a7(c), 001015d8, 00101718(*)  
      001010ad 0f 0b                    UD2
      001010af c5                       ??                   C5h
      001010b0 00                       ??                   00h
      001010b1 0b                       ??                   0Bh
      001010b2 01                       ??                   01h
      001010b3 00                       ??                   00h
      001010b4 00                       ??                   00h
      001010b5 78                       ??                   78h    x
      001010b6 9c                       ??                   9Ch
      001010b7 0b                       ??                   0Bh
      001010b8 f5                       ??                   F5h
      001010b9 e8                       ??                   E8h
      001010ba 7c                       ??                   7Ch    |
      001010bb ea                       ??                   EAh
      001010bc d1                       ??                   D1h
      001010bd fc                       ??                   FCh
      001010be c6                       ??                   C6h
      001010bf c0                       ??                   C0h
....
```

the first instruction is a ```UD2``` which will trigger an invalid instruction and crash the process
the rest doesnt make sense... and this is where the parent "driver" process comes into play

The parent process as attach the child process with ptrace

```C
    while( true ) {
        /* wait for child pid */
        wait(&wstatus);


        /* read child process registers */
        ptrace(PTRACE_GETREGS,(ulong)pid,0,&child_context);
       
       /* bits/waitstatus.h

        if (!__WIFSTOPPED(status) || (__WEXITSTATUS(status) != 4)) */
        if (((wstatus & 0xff) != 0x7f) || (((int)wstatus >> 8 & 0xffU) != 4)) {
            exit(0);
        }


        rip = child_context.rip;
        
        /* read 8 bytes of data of child data at the address pointed by child's RIP */
        data_at_rip = ptrace(PTRACE_PEEKTEXT,(ulong)pid,child_context.rip,0);
        /* check that the instruction is a UD2
           if not, exit

           0x0b0f = UD2
        */
        if ((data_at_rip & 0xffff) != 0xb0f) {
            exit(-1);
        }
        

        /* read 2 bytes at rip+2 */
        compressed_size = (ushort)(data_at_rip >> 0x10);
        
        /* read 2 bytes at rip + 4 */
        deflate_size = (ushort)(data_at_rip >> 0x20);
        rip = rip + 8;
        
        /* read data in child's process starting at RIP+8 */
        deflate_buffer = calloc((ulong)deflate_size,1);
        compressed_buffer = (byte *)calloc((ulong)compressed_size,1);
        for (n = 0; n < (int)(uint)compressed_size; n = n + 8) {
            data = ptrace(PTRACE_PEEKTEXT,(ulong)pid,(long)n + rip,0);
            *(long *)(compressed_buffer + n) = data;
        }
        
        /* decompress the data */
        do_inflate(compressed_buffer,compressed_size,deflate_buffer,deflate_size);
        
        /* write them back at original child's RIP */
        local_iov.iov_base = deflate_buffer;
        local_iov.iov_len = (size_t.conflict)deflate_size;
        remote_iov.iov_base = (void *)child_context.rip;
        remote_iov.iov_len = (size_t.conflict)deflate_size;
        
        res = process_vm_writev(pid,&local_iov,1,&remote_iov,1,0);
        if (res == -1)
            break;
        free(deflate_buffer);
        free(compressed_buffer);

        /* allow child to continue */
        ptrace(PTRACE_CONT,(ulong)pid,0,0);
    }
```



So, when the child process will execute the UD2 instruction, the parent will *catch* it and will:
- read 8 bytes of memory at the child RIP
- verify the last 2 bytes are 0xb0f
  - UD2 instruction is 0FB0 - but little endian...
- read the next 2 bytes as the compressed data size
- read the next 4 bytes as the decompressed data size
- zlib decompress the compressed data following these 8 bytes
- write them back to the child process, starting from the crash (UD2) address
- resume child execution

so basically

```
                         *******************************************************
                         *                                                     *
                         *  FUNCTION                                           *
                         *******************************************************
                         undefined do_encrypt_file()
           undefined       AL:1           <RETURN>
                         do_encrypt_file  
      001010ad 0f 0b                    UD2
      001010af c5 00                    dw                   C5h                ; = 195
      001010b1 0b 01 00 00              ddw                  10Bh               ; = 267
                                    ; compressed data
      001010b5 78                       ??                   78h    x
      001010b6 9c                       ??                   9Ch
      001010b7 0b                       ??                   0Bh
      001010b8 f5                       ??                   F5h
```

the deflate is a simple zlib and if we look at the end of the ```do_encrypt_file``` function there's a bunch of NULL bytes, just enough to hold the deflated bytes.

with a simple ghidra script we can do the deflate in place and analyze the code.

```python
#HTB inflate indefinite
#@author Matthieu Walter
#@category matth.ctf.htb
#@keybinding
#@menupath
#@toolbar

import zlib
import jarray
import binascii


def decompress(addr):
    initial_addr = addr

    instr = getShort(addr)
    if instr != 0xb0f:
        raise Exception, "lol"

    addr = addr.add(2)
    comp_size = getShort(addr)
    print("comp size = %d"%comp_size)


    addr = addr.add(2)
    dec_size = getShort(addr)
    print("dec size = %d"%dec_size)

    addr = addr.add(4)

    data_buffer = jarray.zeros(comp_size,"b")
    currentProgram.getMemory().getBytes(addr,data_buffer)
    data_buffer = bytes(bytearray(data_buffer))

    uncompressed_data = zlib.decompress(data_buffer)


    addr = initial_addr
    for x in uncompressed_data:
        removeDataAt(addr)
        removeInstructionAt(addr)
        setByte(addr, ord(x))
        addr = addr.add(1)



addr = currentAddress

decompress(addr)
```

just put the cursor on the UD2 instruction and run the script, it will do in-place decompression.

Then press D to decompile and  ```do_file_encryption``` will change from:

```C
void do_encrypt_file(void)

{
    do {
        invalidInstructionException();
    } while( true );
}
```

to:

```C

void do_encrypt_file(char *filename,char *param_2,undefined8 random_8_bytes)

{
    char cVar1;
    size_t len;
    long file_size;
    undefined8 *memory_region;
    ulong uVar2;
    char *pcVar3;
    byte bVar4;
    char *outputfile;

    bVar4 = 0;
    outputfile = param_2;
    if (param_2 == NULL) {
        /*
         * output filename = filename.enc
         */
        len = strlen(filename);
        outputfile = (char *)malloc(len + 5);
        strcpy(outputfile,filename);
        uVar2 = 0xffffffffffffffff;
        pcVar3 = outputfile;
        do {
            if (uVar2 == 0) break;
            uVar2 = uVar2 - 1;
            cVar1 = *pcVar3;
            pcVar3 = pcVar3 + (ulong)bVar4 * -2 + 1;
        } while (cVar1 != '\0');
        *(undefined4 *)(outputfile + (~uVar2 - 1)) = 0x636e652e;
        *(undefined *)((long)(outputfile + (~uVar2 - 1)) + 4) = 0;
    }
    file_size = get_filesize(filename);
    file_size = file_size + (ulong)((uint)file_size & 7);

    /* allocate filesize + 8 bytes
     */
    memory_region = (undefined8 *)malloc(file_size + 8);

    /* write the key to the beginning of the file
     */
    *memory_region = random_8_bytes;
    
    /* read input file
     */
    read_file_data(filename,file_size,memory_region + 1);

    /* encrypt with key
     */
    do_encryption(file_size,memory_region + 1,random_8_bytes);

    /* write to output file
     */
    write_file_data(outputfile,file_size + 8,memory_region);
    return;
}
```

rinse and repeat with the other compressed functions.


the ```do_encryption``` is XORing input with the advance(key)

```C
void do_encryption(ulong size,ulong *dest,ulong key)

{
    ulong key_;
    ulong i;

    key_ = key;
    for (i = 0; i <= size; i = i + 8) {
        key_ = advance((byte *)key_);
        *(ulong *)(i + (long)dest) = *(ulong *)(i + (long)dest) ^ key_;
    }
    return;
}
```


and ```advance``` is based on CRC32.

```C

ulong advance(byte *param_1)

{
    ulong uVar1;
    byte local_40 [20];
    uint i;
    uint local_28;
    int local_20;
    
    local_28 = 0xffffffff;
    for (i = 0; i < 8; i = i + 1) {
        local_28 = local_28 ^ local_40[(int)i];
        for (local_20 = 7; -1 < local_20; local_20 = local_20 + -1) {
            local_28 = -(local_28 & 1) & 0xedb88320 ^ local_28 >> 1;
        }
    }
    uVar1 = swap_bytes((ulong)~local_28);
    return uVar1 | ~local_28;
}
```

but we do not need to reverse the whole thing.

We know that the first 8 bytes of the file are the initial key, we can just patch the file to read the key from a user controller file instead of /dev/urandom...

```python
# poor man's patch ....
open("indefinite.patch", "wb").write(open("indefinite", "rb").read().replace(b"/dev/urandom", b"keyfile_1111"))
```


and then

```
# read seed from encrypted file and write it to keyfile_1111
% dd if=flag.txt.enc bs=1 count=8 of=keyfile_1111
8+0 records in
8+0 records out
8 bytes copied, 0.000346225 s, 23.1 kB/s

# read encrypted content (after the key) and write it to flag file
% dd if=flag.txt.enc bs=1 skip=8 of=flag
212+0 records in
212+0 records out
212 bytes copied, 0.000657295 s, 323 kB/s


# 'encrypt' the file
% ./indefinite.patch flag

# profit
% cat flag.enc                
^�($����At 3730 Galactic Time, we will convene at our outpost the Phey forest, 4 miles from the Annara defense systems. Remember, the password for the bunker door is HTB{unr4v3ll1ng_th3_c0d3,unp4ck1ng_th3_s3cr3t}.
�35+��U%                                                                    
```
