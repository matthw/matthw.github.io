
FUNC_BASE = 0x004038a0

class Fixer:
    def __init__(self):

        self.box = [None, ]*128

        # read obfuscated function code
        with open("software.bin", "rb") as fp:
            fp.seek(0x38a0)
            self.code = bytearray(fp.read(29615))

        #print(self.code[:45])


    def parse_line(self, line):
        line = [_.strip() for _ in line.split(":")]
        addr = int(line[0], 16)
        insn = line[1]
        bc   = bytes.fromhex(line[2])

        return (addr, insn, bc)

    def fix_self_modifying_code(self):
        visited = []

        with open("interesting.trace", "r") as fp:
            lines = fp.readlines()

        for n, line in enumerate(lines):
            addr, insn, bc = self.parse_line(line)


            if insn.startswith("mov  al, byte ptr [rip + 0x"):
                _addr2, _insn2, _bc2 = self.parse_line(lines[n+1])
                if _insn2  == "xor  byte ptr [rip + 2], al":
                    offset = int.from_bytes(bc[2:], 'little') + _addr2 - 0x4b1110
                    #print(insn, bc)
                    #print(hex(offset))

                    _ = self.parse_line(lines[n+4])

                    patch_addr = _[0] - FUNC_BASE
                    patch_value = _[2][0]
                    
                    if patch_addr not in visited:
                        visited.append(patch_addr)
                        #print("patch 0x%x = 0x%02x (index: %d)"%(patch_addr,  patch_value, offset))
                        self.box[offset] = self.code[patch_addr] ^ patch_value
                        self.code[patch_addr] = patch_value
                        
                        # patch out xor
                        xor_ins_base = _addr2 - FUNC_BASE
                        for x in range(len(_bc2)):
                            self.code[xor_ins_base + x] = 0x90
                    
                        # erase writeback in case the block is called again
                        _ = self.parse_line(lines[n+5])
                        write_back_base = _[0] - FUNC_BASE
                        for x in range(len(_[2])):
                            self.code[write_back_base + x] = 0x90

    
    def dump(self, filename):
        with open(filename, "wb") as fp:
            fp.write(self.code)

        print(self.box)
                

def main():
    f = Fixer()
    f.fix_self_modifying_code()
    f.dump("fixed_function.bin")


if __name__ == "__main__":
    main()
