---
title: "Linux Security Features"
description: "Linux"
Categories:
    - Linux
tag: Security_Features
---

## 0x00 checksec

在运行程序之前，我们可以使用 checksec 命令查看程序开启了那些保护。

[checksec](https://github.com/slimm609/checksec.sh/)是一个shell编写的脚本软件。

checksec 用来检查可执行文件属性，例如PIE, RELRO, PaX, Canaries, ASLR, Fortify Source等等属性。

Terminal中和 gdb中的 checksec稍有不同。Terminal中查询结果包括RELRO, canary, NX, PIE, RWX, Packer。gdb中查询结果包括CANARY, FORTIFY, NX, PIE, RELRO。

<!-- more -->

## 0x01 canary: 金丝雀

canary与GS的原理是一样。他们都是在函数执行之前保存一个 Security cookie，也就是在堆栈中的返回地址之前。等函数准备返回时检查这个 cookie，如果和原来的值不一样就停止运行。攻击者攻击堆栈，造成堆栈溢出覆盖返回地址，那么返回地址前面的这个 cookie也一定会被覆盖，这栈保护检测不能通过，也就无法按原来的意愿执行shellcode。

这个canary名字来自矿工的金丝雀。金丝雀对瓦斯这种气体十分敏感。空气中哪怕有极其微量的瓦斯，金丝雀也会停止歌唱；而当瓦斯含量超过一定限度时，金丝雀却早已毒发身亡。以前采矿设备相对简陋，矿工们就用金丝雀作为“瓦斯检测指标”，好及时发现危险撤离。

```shell
$ gcc -fno-stack-protector test.c  //canary全部关闭
$ gcc -fstack-protector test.c   //对含有char数组的函数启用canary
$ gcc -fstack-protector-all test.c //为所有函数都使用canary
```

## 0x02 NX: 不可执行内存

NX (No-eXecute, 不可执行) 与windows下的DEP (Data Execution Prevention, 数据执行保护) 一个意思。

其原理是将数据所在的内存页标识为不可执行，当程序成功溢出转入shellcode时，程序会尝试在数据页面上执行指令，此时CPU就会抛出异常，而不是去执行恶意指令。

```shell
$ gcc -z execstack test.c   //关闭NX
$ gcc -z noexecstack test.c   //开启NX，NX是默认开启的，所以这个参数其实可以不加
```

## 0x03 ASLR: 地址空间布局随机化

ASLR通过将加载地址随机化来防止攻击者跳转到内存的特定位置。

在Linux上，ASLR主要栈地址随机化、LIBS/MMAP随机化、EXEC随机化、BRK随机化、VDSO (Virtual Dynamically-linked Shared Object, 虚拟动态共享库) 随机化

在Linux系统中，ASLR被分为 __0__ __1__ __2__ 三个等级，ASLR的等级信息就存在 `/proc/sys/kernel/randomize_va_space` 中。

查看ASLR等级: `cat /proc/sys/kernel/randomize_va_space`  
修改ASLR等级(root权限): `sudo sh -c "echo <ASLR等级> > /proc/sys/kernel/randomize_va_space"`

__0__ : 没有随机化。  
__1__ : 部分随机化。共享库、栈、mmap() 分配的内存空间以及VDSO将被随机化。  
__2__ : 完全的随机化。在1的基础上，通过 brk() 分配的内存空间也将被随机化，也就是堆随机。(默认)  

上面列出的几项内存空间中我们没有看见代码段和数据段 (data段和bss段)，那么 ASLR是否负责它们的随机化呢。

编写一个程序来测试一下，编译命令是`gcc addr.c -o addr -no-pie` 。

```c
//addr.c

#include <stdio.h>

void func();

int uninitialGlobalVar;
int globalVar = 1;

int main(void){
    int localVar = 1;

    printf("Address of func() is %p, in text segment\n", func);
    printf("Address of uninitialGlobalVar is %p, in bss segment\n", &uninitialGlobalVar);
    printf("Address of globalVar is %p, in data segment\n", &globalVar);
    printf("Address of localVar is %p, in stack\n", &localVar);

    return 0;
}

void func(){
    ;
}
```

实验前先确保打开 ASLR, `sudo sh -c "echo 2 > /proc/sys/kernel/randomize_va_space"`。运行结果如下：

![img_1](/images/posts/Linux安全机制/img_1.png)

可见栈的地址被随机化了，但是代码段和数据段的地址均未发生变化。因此我们可以知道 ASLR并不负责代码段和数据段的随机化工作。实际上，该工作是由PIE来负责的。

## 0x04 PIE

PIE(position-independent executables, 位置独立的可执行区域)主要负责代码段和数据段的随机，但是只有在开启 ASLR时，PIE才会有效。

我们继续使用 ASLR部分实验时使用的代码，不过编译命令需要修改一下， `gcc addr.c -o addr -fpie -pie` 。

首先我们启动 ASLR, `sudo echo 2 > /proc/sys/kernel/randomize_va_space` 。运行结果如下：

![img_2](/images/posts/Linux安全机制/img_2.png)

关掉 ASLR再来一次 `sudo echo 0 > /proc/sys/kernel/randomize_va_space`：

![img_3](/images/posts/Linux安全机制/img_3.png)

由上面两张图我们可以知道，__只有在开启 ASLR 之后，PIE 才会生效。__

启用PIE `-fpie -pie`  
关闭PIE `-no-pie`  

## 0x05 RELRO

RELRO(RELocation Read-Only，只读重定位)让加载器将重定位表中加载时解析的符号标记为只读，这减少了GOT覆写攻击的面积。

RELRO可以分为Partial RELRO(部分RELRO)和Full RELRO(完整RELRO)。开启Partial RELRO的话GOT表是可写的；开启FULL RELRO的话GOT表是只读的。

开启-Wl,-z,relro选项即可开启Partial RELRO；开启-Wl,-z,relro,-z,now选项即可开启Full RELRO。

## 0x06 FORTIFY

这个保护机制我也是弄得稀里糊涂的，所以就直接仍一个链接，有兴趣的可以看看，[Object size checking to prevent (some) buffer overflows](https://gcc.gnu.org/ml/gcc-patches/2004-09/msg02055.html) 。

## 0x07 参考资料

+ 岁月别催. [WINDOWS和LINUX的内存防护机制](https://blog.csdn.net/x_nirvana/article/details/61420056)
+ houjingyi. [linux漏洞缓解机制介绍](https://bbs.pediy.com/thread-226696.htm)
+ Yun. [checksec及其包含的保护机制](http://yunnigu.dropsec.xyz/2016/10/08/checksec%E5%8F%8A%E5%85%B6%E5%8C%85%E5%90%AB%E7%9A%84%E4%BF%9D%E6%8A%A4%E6%9C%BA%E5%88%B6/)
+ 加号减减号. [Linux平台的ASLR机制](https://blog.csdn.net/plus_re/article/details/79199772)
+ hardenedlinux. [RELRO分析](https://hardenedlinux.github.io/2016/11/25/RelRO.html)
+ Jakub Jelinek. [Object size checking to prevent (some) buffer overflows](https://gcc.gnu.org/ml/gcc-patches/2004-09/msg02055.html)
+ 爱甲健二. 周自恒译. 有趣的二进制 软件安全与逆向分析. 人民邮电出版社
+ 王清. 0day安全：软件漏洞分析技术(第二版). 北京:电子工业出版社，2011
+ Wikipedia. [Canary](https://en.wikipedia.org/wiki/Buffer_overflow_protection#Canaries)
+ Wikipedia. [NX bit](https://en.wikipedia.org/wiki/NX_bit)
+ Wikipedia. [Address space layout randomization](https://en.wikipedia.org/wiki/Address_space_layout_randomization)
+ Wikipedia. [PIE](https://en.wikipedia.org/wiki/Position-independent_code)