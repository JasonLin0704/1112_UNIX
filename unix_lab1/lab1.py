#!/usr/bin/env python3

from pwn import * # note: source ~/pwntools/bin/activate
import pow as pw
import base64
import hashlib

r = remote("up23.zoolab.org", 10363)
pw.solve_pow(r)

# how many loops
tmp = r.recvuntil(b'complete', drop=True).decode()
tmp = r.recvuntil(b'challenges', drop=True).decode()
n = int(tmp.split(' ')[2])

# calculate
for i in range(0, n):
    tmp = r.recvuntil(b':', drop=True).decode()
    tmp = r.recvuntil(b'=', drop=True).decode()
    a, op, b = int(tmp.split(' ')[1]), tmp.split(' ')[2], int(tmp.split(' ')[3])
    print(i + 1, a, op, b)
    
    if(op == '+'): ans = a + b
    elif(op == '*'): ans = a * b
    elif(op == '//'): ans = a // b
    elif(op == '%'): ans = a % b
    elif(op == '**'): ans = pow(a, b)

    res = ans.to_bytes((ans.bit_length() + 7) // 8, byteorder='little')
    r.sendlineafter(b'?', base64.b64encode(res))

r.interactive()
r.close()
