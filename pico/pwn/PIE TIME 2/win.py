from pwn import *

elf = ELF("./vuln")
p = process("./vuln")

win = elf.sym['win']
print(hex(win))

p.interactive()
