#!/usr/bin/env python3

from pwn import *
import pow as pw
import base64
import hashlib

r = remote("up23.zoolab.org", 10363)
pw.solve_pow(r)

tmp = r.recvuntil(b'complete', drop=True).decode()
tmp = r.recvuntil(b'challenges', drop=True).decode()
n = int(tmp.split(' ')[2])
print('n:', n)

for i in range(0, n):
    tmp = r.recvuntil(b':', drop=True).decode()
    tmp = r.recvuntil(b'?', drop=True).decode()
    a = int(tmp.split()[0])
    op = tmp.split()[1]
    b = int(tmp.split()[2])
    print(i, a, op, b)
    ans = 0
    if(op == '+'):
        ans = a + b
    elif(op == '*'):
        ans = a * b
    elif(op == '//'):
        ans = a // b
    elif(op == '%'):
        ans = a % b
    elif(op == '**'):
        ans = pow(a, b)

    res = ans.to_bytes((ans.bit_length() + 7) // 8, byteorder='little')
    r.sendline(base64.b64encode(res))

r.interactive()
r.close()