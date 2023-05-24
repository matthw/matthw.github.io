import gdb

def read_reg(reg):
    return gdb.parse_and_eval("${}".format(reg))


fd = open("trace_crack2.txt", "w")

gdb.execute('break *0x40133b')  # call decrypt_code
gdb.execute('run aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')

while 1:
    key = int(read_reg('esi')) & 0xffffffff
    idx = int(read_reg('edx'))
    if idx < 0:
        break
    
    print("key 0x%x idx 0x%x"%(key, idx))
    fd.write("key 0x%x idx 0x%x\n"%(key, idx))
    gdb.execute("continue")
