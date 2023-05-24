# Gray Cat The Flag Crackme2 solve

import sys
from pwn import *
from capstone import *
from z3 import *


def disasm(code):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(code, 0x0):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

# encrypted code region
CODE_OFFSET = 0xc0a0
CODE_SIZE   = 0x10000

class Emu:
    def __init__(self):
        #self.data = open("data.bin", "rb").read()
        # load data
        with open("crackme2", "rb") as fp:
            fp.seek(CODE_OFFSET)
            self.data = fp.read(CODE_SIZE)

        # symbolic flag
        self.flag = []
        for x in range(41):
            self.flag.append(BitVec('f%d'%x, 8))

        # concrete flag
        self.out = bytearray(41)

    def dec(self, sz ,key):
        key = p32(key)
        size = self.data[sz*4]   # read size
        code = xor(key, self.data[(sz+1)*4:(sz+1+size)*4])
        #disasm(code)
        self.emu(code)

    def slv(self, x, y):
        s = Solver()
        s.add(x == y)
        assert s.check() == sat
        m = s.model()
        for x in m:
            return m[x].as_long()

    def emu(self, code):
        print("######################")

        st = {'r12': 0}

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for i in md.disasm(code, 0x0):
            op = i.mnemonic
            dat =  i.op_str.replace(",", "").split()
            #print(op, dat)
            match i.mnemonic:
                case 'mov':
                    st[dat[0]] = int(dat[1].replace("0x", ""), 16) & 0xffffffff
                case 'movabs': 
                    st[dat[0]] = int(dat[1].replace("0x", ""), 16) & 0xffffffff
                case 'sub':
                    st[dat[0]] -= st[dat[1]]
                    st[dat[0]] &= 0xffffffff
                case 'add':
                    st[dat[0]] += st[dat[1]]
                    st[dat[0]] &= 0xffffffff
                case 'xor':
                    st[dat[0]] ^= st[dat[1]]
                case 'or':
                    st[dat[0]] |= st[dat[1]]
                    if dat[0] == 'r12':
                        # r12 persist and must be 0 for last check to pass
                        #print(" ---------- R12")
                        #print(st[dat[1]])
                        print(st['r12'])
                        # solve dat[1] == 0
                        result = self.slv(st[dat[1]], 0)
                        self.out[pos] = result
                        print(self.out)
                case 'lea':
                    # load flag
                    if st[dat[0]] == 16488:
                        print("load flag")
                        st[dat[0]] = self.flag
                case 'movzx':
                    # load flag chr index
                    o1 = dat[-1][:-1]
                    o2 = dat[-3][1:]
                    if type(st[o1]) is list:
                        pos = st[o2]
                        st[dat[0]] = st[o1][pos]
                    elif type(st[o2]) is list:
                        pos = st[o1]
                        st[dat[0]] = st[o2][pos]
                    else:
                        print(op, dat)
                        print(st)
                        raise
                    print("checking flag pos %d"%pos)

                case 'cmp':
                    # decoy...
                    break
                case 'test':
                    break
                case 'ret':
                    break

                case _:
                    print(st)
                    print(op, dat)
                    print(self.out)
                    raise

z = Emu()

with open("trace_crack2.txt") as fp:
    for line in fp:
        line = line.split()

        key = int(line[1][2:], 16)
        idx = int(line[3][2:], 16)

        # skip first useless blocks
        if idx < 0x800:
            continue

        print("bloc: 0x%x   0x%x"%(idx, key))

        z.dec(idx, key)
