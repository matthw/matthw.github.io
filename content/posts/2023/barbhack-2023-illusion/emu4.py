from capstone import *
from unicorn import *
from unicorn.x86_const import *
from Crypto.Cipher import ARC4
from pwn import p32
import hashlib
import sys


DEBUG = True

def log(txt):
    if DEBUG:
        print(txt)

def get_code(start, end):
    with open("illusion.exe", "rb") as fp:
        fp.seek(start)
        return fp.read(end - start)


def is_good_block(code):
    ''' check if a decrypted block is 'valid' using advanced machine learning alg
    '''
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    valid_insn = 0
    for i in md.disasm(code, 0x0):
        valid_insn += 1
        #log("           !! 0x%x\t%s\t%s"%(i.address, i.mnemonic, i.op_str))
        if i.mnemonic not in ["mov", "add", "jmp", "int", "hlt"]:
            return False

    if valid_insn == 0:
        return False
    return True 


def disas_single(code, addr):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for i in md.disasm(code, addr):
        return (i.address, i.mnemonic, i.op_str)


def disas_all(code, addr):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for i in md.disasm(code, addr):
        print("0x%x\t%s\t%s"%(i.address, i.mnemonic, i.op_str))


def decrypt(key, data):
    h = hashlib.md5(p32(key)).digest()
    c = ARC4.new(key=h[:5])
    return c.decrypt(data)


class PathTest:
    ''' stripped down copy/paste of main emu to check for possible next room
    '''
    def hook_code(self, mu, addr, size, user_data):
        mem = mu.mem_read(addr, size)
        dis = disas_single(mem, addr)
        if dis is None:
            print("ERRRR: %r"%mem)
            return
        addr, mnemonic, op_str = dis
        log("        >>  0x%x\t%s\t%s"%(addr, mnemonic, op_str))

        # INT3
        if mem == b'\xcc':
            log("       checking sub block....")
            data = mu.mem_read(addr + 1, 0x38)
            data = decrypt(mu.reg_read(UC_X86_REG_EBX), data)
            if is_good_block(data):
                log("     goooood")
                self.good = True
            mu.emu_stop()

        # HLT
        elif mem == b'\xf4':
            # for some reason it fails to stop :)
            mu.emu_stop()
            print("win")
            sys.exit(0)
        

    def test_path(self, eip, eax, ecx, code):
        self.good = False
        log("DESCEND")
        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        mu.mem_map(0x400000,  0x300000)
        mu.mem_write(0x402595, bytes(code))
        mu.reg_write(UC_X86_REG_EAX, eax)
        mu.reg_write(UC_X86_REG_ECX, ecx)

        mu.hook_add(UC_HOOK_CODE, self.hook_code)
        try:
            mu.emu_start(eip, 0x400000+len(code))
        except UcError:
            return False
        return self.good



class Machine:
    def __init__(self, key):
        self.entry = 0x402595
        self.decrypted = []

        self.KEY = key
        self.next_key = []
        self.INDEX = 0

    def hook_err_mem(self, uc, access, address, size, value, user_data):
        return True

    def hook_code(self, mu, addr, size, user_data):
        mem = mu.mem_read(addr, size)
        dis = disas_single(mem, addr)

        addr, mnemonic, op_str = dis
        log("0x%x\t%s\t%s"%(addr, mnemonic, op_str))

        # int3
        if mem == b'\xcc':
            self.exception_handler_cc(mu)

        # hlt
        elif mem == b'\xf4':
            print("win")

    def decrypt_code(self, mu, key, eip):
        ''' rc4 decrypt 0x38 bytes of data after crash EIP
        and write it back to memory '''
        
        log("key = 0x%x eip=0x%x"%(key, eip))
        data = mu.mem_read(eip + 1, 0x38)
        data = decrypt(key, data)
        log(data)
        if DEBUG:
            disas_all(data, eip + 1)

        # block iznogood, abort mission
        if not is_good_block(data):
            mu.emu_stop()
            return False

        # write back decrypted code
        mu.mem_write(eip + 1, data)

        return True


    def exception_handler_cc(self, mu):
        ''' emulates exception handler
        '''
        keys = ['A', 'B', 'C', 'D']

        eip = mu.reg_read(UC_X86_REG_EIP)
        key = mu.reg_read(UC_X86_REG_EBX)


        if not self.decrypt_code(mu, key, eip):
            return

        # while we have a key for it, follow the given path
        if self.INDEX < len(self.KEY):
            k = self.KEY[self.INDEX]
            size = (ord(k) - 0x41) * 0xe
            new_eip = eip + size + 1
            log("using key %s"%k)
            mu.reg_write(UC_X86_REG_EIP, new_eip)
            self.INDEX += 1
            return

        # once we reach unknown territories, try all paths and return good candidates
        explorer = PathTest()
        for k in keys:
            size = (ord(k) - 0x41) * 0xe
            print("trying key %s"%k)
            new_eip = eip + size + 1

            res = explorer.test_path(new_eip, mu.reg_read(UC_X86_REG_EAX), mu.reg_read(UC_X86_REG_ECX), mu.mem_read(0x402595, 0x133b7f))
            if res:
                self.next_key.append(k)
        mu.emu_stop()



    def emu(self):
        ''' emulates key check, returns potential next key char
        '''
        ADDR_TEXT  = 0x400000
        ADDR_STACK = 0xa00000
        
        code = get_code(0x1995, 0x133b7f)

        mu = Uc(UC_ARCH_X86, UC_MODE_32)
       
        # setup memory segments
        mu.mem_map(ADDR_TEXT,  0x300000)
        mu.mem_map(ADDR_STACK, 0x10000)

        # write code
        mu.mem_write(self.entry, code)

        # setup registers
        esp = ADDR_STACK + 0x400
        ebp = ADDR_STACK + 0x1000
        mu.reg_write(UC_X86_REG_EBP, ebp)
        mu.reg_write(UC_X86_REG_ESP, esp)

        # initial value for jmp eax
        #mu.reg_write(UC_X86_REG_EAX, 0x004e9c17)
        mu.reg_write(UC_X86_REG_ECX, 4203916)

        # plant hooks
        mu.hook_add(UC_HOOK_CODE, self.hook_code)
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, self.hook_err_mem)

        mu.emu_start(self.entry, ADDR_TEXT + len(code))

        # return next path candidates
        return self.next_key


def check(key, nxt):
    '''' recursively check path
    '''
    for c in nxt:
        print("trying %s"%(key + c))
        m = Machine(key + c)
        n = m.emu()
        print("next_keys = %r"%n)
        if len(n):
            check(key + c, n)





if __name__ == "__main__":
    # because i tried, i know the first valid path is C
    check("C", ["A", "B", "C", "D"])


