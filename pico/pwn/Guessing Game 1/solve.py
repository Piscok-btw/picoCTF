from pwn import *

for g in range(100):  # brute force semua kemungkinan
    p = process("./vuln")
    p.sendline(str(g))
    out = p.recvall(timeout=1).decode()
    if "Congrats" in out:
        print(f"[+] Ketemu jawaban: {g}")
        break

