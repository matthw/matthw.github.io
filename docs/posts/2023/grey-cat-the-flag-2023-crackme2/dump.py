
from pwn import *
from capstone import *

# encrypted code region
CODE_OFFSET = 0xc0a0
CODE_SIZE   = 0x10000

def disasm(code):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(code, 0x0):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))


def dec(data, key, sz):
    key = p32(key)
    size = data[sz*4]   # read size
    code = xor(key, data[(sz+1)*4:(sz+1+size)*4])
    disasm(code)

# read encrypted code from binary
with open("crackme2.patch", "rb") as fp:
    fp.seek(CODE_OFFSET)
    data = fp.read(CODE_SIZE)

with open("trace_crack2.txt") as fp:
    for line in fp:
        line = line.split()

        key = int(line[1][2:], 16)
        idx = int(line[3][2:], 16)

        print("\n\n\n")
        print("bloc: 0x%x   0x%x"%(idx, key))
        dec(data, key, idx)
