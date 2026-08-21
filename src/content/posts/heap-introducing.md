---
title: Heap Introducing
published: 2024-07-29
category: "CTF"
tags: [PWN, CTF]
---

- Heap là vùng nhớ được phân bổ động dùng để lưu trữ dữ liệu
- Được tạo bởi các hàm như `malloc(), calloc(), ...`
# Chunk
- Khi chúng ta thực thi hàm gọi hàm `malloc()` thì sẽ trả về con trỏ trỏ tới vùng nhớ, vùng nhớ đó được gọi là chunk
- Cấu trúc của một chunk gồm 2 phần chính:
    - Metadata
    - Content
- Vùng metadata có 0x10 byte gồm 0x8 byte là của kích thước chunk trước(Previous Chunk Size) và 0x8 byte là kích thước chunk hiện tại (Chunk Size)
```
----------------------------------------------------------
| 0x8 byte (previous chunk size) | 0x8 byte (chunk size) | <-- Metadata
----------------------------------------------------------
```
- Malloc sẽ tạo ra chunk có size bao gồm cả metadata và vùng content
- Dùng lệnh `heap chunks` trong bản debug `gef`, `chunks` trong `pwndbg` để xem các chunk
> malloc(0x20) để xem
- Size chunk là 0x30 vì cộng 0x10 của metadata
- 0x8 byte của chunk size sẽ cộng với 1 bit đánh dấu
```
0x1:     Previous in Use     - Specifies that the chunk before it in memory is in use
0x2:    Is MMAPPED               - Specifies that the chunk was obtained with mmap()
0x4:     Non Main Arena         - Specifies that the chunk was obtained from outside of the main arena
```
- `0x1` chỉ định là chunk trước đó đang được sử dụng 
- `0x2` chỉ định là vùng nhớ được phân bổ không phải vùng nhớ heap mà là một vùng nhớ khác, được bật lên khi ta tạo một vùng nhớ quá lớn so với heap
- `0x4` là vùng nhớ được lấy từ bên ngoài vùng nhớ chính

> Ví dụ tạo vùng nhớ có kích thước là 0x200000 byte
- Ta thấy địa chỉ trả về của vùng nhớ nằm ngoài heap 
- Vùng nhớ heap chỉ có size là 21000
- Ta trừ địa chỉ trả về cho 0x10 để thấy được vùng metadata của chunk, bit sau cùng là 0x2 bật lên vì vùng nhớ được tạo ra lớn hơn kích thước của heap

# Bin
- Khi malloc giải phóng một khối, nó thường sẽ chèn khối đó vào một trong các danh sách bin. Sau đó, với một lần phân bổ sau, nó sẽ kiểm tra các bin để xem có khối nào được giải phóng mà nó có thể phân bổ để phục vụ yêu cầu hay không. Mục đích của việc này là để nó có thể sử dụng lại các khối đã giải phóng trước đó, nhằm cải thiện hiệu suất
- Có 5 loại bin:
    - Fast Bins
    - tcache
    - Unsorted
    - Large Bins 
    - Small Bins
## Fast Bins
- Đối với libc phiên bản nhỏ hơn 2.27 thì chỉ có Fast Bins không có tcache
- Khi `free()` các chunk có kích thước từ 0x20 đến 0x80 thì được đưa vào Fast Bin
- Fast Bin bao gồm 7 danh sách liên kết được tham chiếu bằng `idx`
- Mỗi `idx` được phân chia theo kích thước
    - Khối có kích thước 0x20 - 0x2f sẽ có `idx = 0`
    - Không có kích thước 0x30 - 0x3f sẽ có `idx = 1`
    - ....
```
────────────────────── Fastbins for arena 0x7ffff7dd1b20 ──────────────────────
Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0x602010, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x602030, size=0x20, flags=PREV_INUSE)
Fastbins[idx=1, size=0x20]  ←  Chunk(addr=0x602050, size=0x30, flags=PREV_INUSE)
Fastbins[idx=2, size=0x30]  ←  Chunk(addr=0x602080, size=0x40, flags=PREV_INUSE)
Fastbins[idx=3, size=0x40]  ←  Chunk(addr=0x6020c0, size=0x50, flags=PREV_INUSE)
Fastbins[idx=4, size=0x50]  ←  Chunk(addr=0x602110, size=0x60, flags=PREV_INUSE)
Fastbins[idx=5, size=0x60]  ←  Chunk(addr=0x602170, size=0x70, flags=PREV_INUSE)
Fastbins[idx=6, size=0x70]  ←  Chunk(addr=0x6021e0, size=0x80, flags=PREV_INUSE)
```
- Fast Bin được đưa vào theo cơ chế giống stack là LIFO
- Khi `malloc()` có kích thước cùng với size đã `free()` thì chương trình sẽ sử dụng lại chunk đó để sử dụng

## tcache
- Về cơ bản tcache giống với Fast Bin nhưng có vài điểm khác
- Tcahce là một loại cơ chế binning mới được giới thiệu trong phiên bản libc 2.26(trước đó sẽ không thấy tcahce)
- tcache dành riêng cho từng luồng
- chứa tối đa 7 chunk trong 1 size nhưng kích thước lớn hơn và đa dạng hơn
- Trong các biên bản libc có tcache thì tcache là nơi đầu tiên sẽ tìm đến để phân bổ các chunk hoặc đặt các chunk đã giải phóng vì nó nhanh hơn Fast Bin
- Xem ví dụ:
```c 
#include <stdlib.h>

void main(void)
{
  char *p0, *p1, *p2, *p3, *p4, *p5, *p6, *p7;

  p0 = malloc(0x10);
  p1 = malloc(0x10);
  p2 = malloc(0x10);
  p3 = malloc(0x10);
  p4 = malloc(0x10);
  p5 = malloc(0x10);
  p6 = malloc(0x10);
  p7 = malloc(0x10);

  malloc(10); // Here to avoid consolidation with Top Chunk

  free(p0);
  free(p1);
  free(p2);
  free(p3);
  free(p4);
  free(p5);
  free(p6);
  free(p7);
}

```
- Sau khi `free()` tất cả 
```
gef➤  heap bins
───────────────────── Tcachebins for arena 0x7ffff7faec40 ─────────────────────
Tcachebins[idx=0, size=0x10] count=7  ←  Chunk(addr=0x555555559320, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559300, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555592e0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555592c0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555592a0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559280, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559260, size=0x20, flags=PREV_INUSE)
────────────────────── Fastbins for arena 0x7ffff7faec40 ──────────────────────
Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0x555555559340, size=0x20, flags=PREV_INUSE)
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
───────────────────── Unsorted Bin for arena 'main_arena' ─────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────── Small Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────── Large Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 large non-empty bins.

```
- Ta thấy tcache chỉ chứa tối đa 7 chunk nhưng ta giải phóng 8 chunk nên 7 chunk đầu tiên nằm trong tcache còn chunk thứ 8 nằm ở Fast Bin
- Có thể chứa tổng cộng 64 danh sách tcache, với `idx` từ  0-63, có kích thước chunk từ `0x20-0x410` -> kích thước content của chunk là `0x10-0x400`
```
gef➤  heap bins
─────────────────────────────────────────────────────────────────────────────────── Tcachebins for arena 0x7ffff7faec40 ───────────────────────────────────────────────────────────────────────────────────
Tcachebins[idx=0, size=0x10] count=1  ←  Chunk(addr=0x555555559260, size=0x20, flags=PREV_INUSE)
Tcachebins[idx=1, size=0x20] count=1  ←  Chunk(addr=0x555555559280, size=0x30, flags=PREV_INUSE)
Tcachebins[idx=2, size=0x30] count=1  ←  Chunk(addr=0x5555555592b0, size=0x40, flags=PREV_INUSE)
Tcachebins[idx=3, size=0x40] count=1  ←  Chunk(addr=0x5555555592f0, size=0x50, flags=PREV_INUSE)
Tcachebins[idx=4, size=0x50] count=1  ←  Chunk(addr=0x555555559340, size=0x60, flags=PREV_INUSE)
Tcachebins[idx=5, size=0x60] count=1  ←  Chunk(addr=0x5555555593a0, size=0x70, flags=PREV_INUSE)
Tcachebins[idx=6, size=0x70] count=1  ←  Chunk(addr=0x555555559410, size=0x80, flags=PREV_INUSE)
Tcachebins[idx=7, size=0x80] count=1  ←  Chunk(addr=0x555555559490, size=0x90, flags=PREV_INUSE)
Tcachebins[idx=8, size=0x90] count=1  ←  Chunk(addr=0x555555559520, size=0xa0, flags=PREV_INUSE)
Tcachebins[idx=9, size=0xa0] count=1  ←  Chunk(addr=0x5555555595c0, size=0xb0, flags=PREV_INUSE)
Tcachebins[idx=10, size=0xb0] count=1  ←  Chunk(addr=0x555555559670, size=0xc0, flags=PREV_INUSE)
Tcachebins[idx=11, size=0xc0] count=1  ←  Chunk(addr=0x555555559730, size=0xd0, flags=PREV_INUSE)
Tcachebins[idx=12, size=0xd0] count=1  ←  Chunk(addr=0x555555559800, size=0xe0, flags=PREV_INUSE)
Tcachebins[idx=13, size=0xe0] count=1  ←  Chunk(addr=0x5555555598e0, size=0xf0, flags=PREV_INUSE)
Tcachebins[idx=14, size=0xf0] count=1  ←  Chunk(addr=0x5555555599d0, size=0x100, flags=PREV_INUSE)
Tcachebins[idx=15, size=0x100] count=1  ←  Chunk(addr=0x555555559ad0, size=0x110, flags=PREV_INUSE)
Tcachebins[idx=16, size=0x110] count=1  ←  Chunk(addr=0x555555559be0, size=0x120, flags=PREV_INUSE)
Tcachebins[idx=17, size=0x120] count=1  ←  Chunk(addr=0x555555559d00, size=0x130, flags=PREV_INUSE)
Tcachebins[idx=18, size=0x130] count=1  ←  Chunk(addr=0x555555559e30, size=0x140, flags=PREV_INUSE)
Tcachebins[idx=19, size=0x140] count=1  ←  Chunk(addr=0x555555559f70, size=0x150, flags=PREV_INUSE)
Tcachebins[idx=20, size=0x150] count=1  ←  Chunk(addr=0x55555555a0c0, size=0x160, flags=PREV_INUSE)
Tcachebins[idx=21, size=0x160] count=1  ←  Chunk(addr=0x55555555a220, size=0x170, flags=PREV_INUSE)
Tcachebins[idx=22, size=0x170] count=1  ←  Chunk(addr=0x55555555a390, size=0x180, flags=PREV_INUSE)
Tcachebins[idx=23, size=0x180] count=1  ←  Chunk(addr=0x55555555a510, size=0x190, flags=PREV_INUSE)
Tcachebins[idx=24, size=0x190] count=1  ←  Chunk(addr=0x55555555a6a0, size=0x1a0, flags=PREV_INUSE)
Tcachebins[idx=25, size=0x1a0] count=1  ←  Chunk(addr=0x55555555a840, size=0x1b0, flags=PREV_INUSE)
Tcachebins[idx=26, size=0x1b0] count=1  ←  Chunk(addr=0x55555555a9f0, size=0x1c0, flags=PREV_INUSE)
Tcachebins[idx=27, size=0x1c0] count=1  ←  Chunk(addr=0x55555555abb0, size=0x1d0, flags=PREV_INUSE)
Tcachebins[idx=28, size=0x1d0] count=1  ←  Chunk(addr=0x55555555ad80, size=0x1e0, flags=PREV_INUSE)
Tcachebins[idx=29, size=0x1e0] count=1  ←  Chunk(addr=0x55555555af60, size=0x1f0, flags=PREV_INUSE)
Tcachebins[idx=30, size=0x1f0] count=1  ←  Chunk(addr=0x55555555b150, size=0x200, flags=PREV_INUSE)
Tcachebins[idx=31, size=0x200] count=1  ←  Chunk(addr=0x55555555b350, size=0x210, flags=PREV_INUSE)
Tcachebins[idx=32, size=0x210] count=1  ←  Chunk(addr=0x55555555b560, size=0x220, flags=PREV_INUSE)
Tcachebins[idx=33, size=0x220] count=1  ←  Chunk(addr=0x55555555b780, size=0x230, flags=PREV_INUSE)
Tcachebins[idx=34, size=0x230] count=1  ←  Chunk(addr=0x55555555b9b0, size=0x240, flags=PREV_INUSE)
Tcachebins[idx=35, size=0x240] count=1  ←  Chunk(addr=0x55555555bbf0, size=0x250, flags=PREV_INUSE)
Tcachebins[idx=36, size=0x250] count=1  ←  Chunk(addr=0x55555555be40, size=0x260, flags=PREV_INUSE)
Tcachebins[idx=37, size=0x260] count=1  ←  Chunk(addr=0x55555555c0a0, size=0x270, flags=PREV_INUSE)
Tcachebins[idx=38, size=0x270] count=1  ←  Chunk(addr=0x55555555c310, size=0x280, flags=PREV_INUSE)
Tcachebins[idx=39, size=0x280] count=1  ←  Chunk(addr=0x55555555c590, size=0x290, flags=PREV_INUSE)
Tcachebins[idx=40, size=0x290] count=1  ←  Chunk(addr=0x55555555c820, size=0x2a0, flags=PREV_INUSE)
Tcachebins[idx=41, size=0x2a0] count=1  ←  Chunk(addr=0x55555555cac0, size=0x2b0, flags=PREV_INUSE)
Tcachebins[idx=42, size=0x2b0] count=1  ←  Chunk(addr=0x55555555cd70, size=0x2c0, flags=PREV_INUSE)
Tcachebins[idx=43, size=0x2c0] count=1  ←  Chunk(addr=0x55555555d030, size=0x2d0, flags=PREV_INUSE)
Tcachebins[idx=44, size=0x2d0] count=1  ←  Chunk(addr=0x55555555d300, size=0x2e0, flags=PREV_INUSE)
Tcachebins[idx=45, size=0x2e0] count=1  ←  Chunk(addr=0x55555555d5e0, size=0x2f0, flags=PREV_INUSE)
Tcachebins[idx=46, size=0x2f0] count=1  ←  Chunk(addr=0x55555555d8d0, size=0x300, flags=PREV_INUSE)
Tcachebins[idx=47, size=0x300] count=1  ←  Chunk(addr=0x55555555dbd0, size=0x310, flags=PREV_INUSE)
Tcachebins[idx=48, size=0x310] count=1  ←  Chunk(addr=0x55555555dee0, size=0x320, flags=PREV_INUSE)
Tcachebins[idx=49, size=0x320] count=1  ←  Chunk(addr=0x55555555e200, size=0x330, flags=PREV_INUSE)
Tcachebins[idx=50, size=0x330] count=1  ←  Chunk(addr=0x55555555e530, size=0x340, flags=PREV_INUSE)
Tcachebins[idx=51, size=0x340] count=1  ←  Chunk(addr=0x55555555e870, size=0x350, flags=PREV_INUSE)
Tcachebins[idx=52, size=0x350] count=1  ←  Chunk(addr=0x55555555ebc0, size=0x360, flags=PREV_INUSE)
Tcachebins[idx=53, size=0x360] count=1  ←  Chunk(addr=0x55555555ef20, size=0x370, flags=PREV_INUSE)
Tcachebins[idx=54, size=0x370] count=1  ←  Chunk(addr=0x55555555f290, size=0x380, flags=PREV_INUSE)
Tcachebins[idx=55, size=0x380] count=1  ←  Chunk(addr=0x55555555f610, size=0x390, flags=PREV_INUSE)
Tcachebins[idx=56, size=0x390] count=1  ←  Chunk(addr=0x55555555f9a0, size=0x3a0, flags=PREV_INUSE)
Tcachebins[idx=57, size=0x3a0] count=1  ←  Chunk(addr=0x55555555fd40, size=0x3b0, flags=PREV_INUSE)
Tcachebins[idx=58, size=0x3b0] count=1  ←  Chunk(addr=0x5555555600f0, size=0x3c0, flags=PREV_INUSE)
Tcachebins[idx=59, size=0x3c0] count=1  ←  Chunk(addr=0x5555555604b0, size=0x3d0, flags=PREV_INUSE)
Tcachebins[idx=60, size=0x3d0] count=1  ←  Chunk(addr=0x555555560880, size=0x3e0, flags=PREV_INUSE)
Tcachebins[idx=61, size=0x3e0] count=1  ←  Chunk(addr=0x555555560c60, size=0x3f0, flags=PREV_INUSE)
Tcachebins[idx=62, size=0x3f0] count=1  ←  Chunk(addr=0x555555561050, size=0x400, flags=PREV_INUSE)
Tcachebins[idx=63, size=0x400] count=1  ←  Chunk(addr=0x555555561450, size=0x410, flags=PREV_INUSE)
──────────────────────────────────────────────────────────────────────────────────── Fastbins for arena 0x7ffff7faec40 ────────────────────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
─────────────────────────────────────────────────────────────────────────────────── Unsorted Bin for arena 'main_arena' ───────────────────────────────────────────────────────────────────────────────────
[+] unsorted_bins[0]: fw=0x555555561850, bk=0x555555561850
 →   Chunk(addr=0x555555561860, size=0x19b0, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
──────────────────────────────────────────────────────────────────────────────────── Small Bins for arena 'main_arena' ────────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────────────────────────────────────────────────────────────────────── Large Bins for arena 'main_arena' ────────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```
- tcache với fast bin đều là danh sách liên kết đơn
- Khi 1 chunk được đưa vào tcache hoặc fast bin sẽ có một con trỏ trỏ tới chunk tiếp theo
- Ví dụ 
```
Tcachebins[idx=0, size=0x10] count=7  ←  Chunk(addr=0x555555559320, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559300, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555592e0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555592c0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555592a0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559280, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559260, size=0x20, flags=PREV_INUSE)
```

- khi ta đưa chunk tiếp theo có addr = 0x555555559300 thì con trỏ của chunk trước đó có địa chỉ addr = 0x555555559320 trỏ tới nó 
## Unsorted, Large Bin và Small Bins
- unsorted, large và small bin có cấu trúc là danh sách liên kết đôi
- Về cơ bản chúng giống nhau
- Mỗi bin có các chỉ mục khác nhau
```
0x00:         Not Used
0x01:         Unsorted Bin
0x02 - 0x3f:  Small Bin
0x40 - 0x7e:  Large Bin
```
- Khi free() 1 chunk có kích thước lớn hơn 0x410 thì được đưa vào unsorted bin
- Có đoạn code C 
```
#include <stdio.h>
#include <stdlib.h>

int main()
{
	char* p1[8];
	char* p2[8];

	for (int i=0; i<8; i++)
		p1[i] = malloc(0x20); 
	for (int i=0; i<8; i++)
		p2[i] = malloc(0x410); 

	char* p3 = malloc(0x2000);
	char* p4 = malloc(0x20000);
	for (int i=0; i<8; i++)
		free(p1[i]); 
	for (int i=0; i<8; i++) 
		free(p2[i]); 
	free(p3);
	free(p4);
}
```
- Khi free dòng for đầu tiên ta thấy 7 chunk được đưa vào tcache và 1 chunk được đưa và fast bin 
- Khi free 1 lần p2
- Khi free 2 lần p2
- Ta thấy 2 chunk đã bị gộp lại và có kích thước 0x840 chứ không tạo 2 chunk có kích thước là 0x420
- Đây là dạng gộp chunk của unsorted bin 
- Khi đó danh sách liên kết đôi có 2 con trỏ là fw(forward ptr) và bk(backward ptr) cùng trỏ tới 1 vùng main arena
