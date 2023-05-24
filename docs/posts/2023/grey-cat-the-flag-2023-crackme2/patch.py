from pwn import p32
idx = 0x6d9 + 1
offset = 0xc0a0 + idx*4
xor_key = p32(0xd48c0a3a)

data = bytearray(open("crackme2", 'rb').read())

# syscall -> xor rax,rax
data[offset+5] = 0x31 ^ xor_key[1]
data[offset+6] = 0xc0 ^ xor_key[2]

open('crackme2.patch', 'wb').write(data)
