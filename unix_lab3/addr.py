from pwn import *
elf = ELF('./chals')
print("main =", hex(elf.symbols['main']))
print("{:<12s} {:<8s} {:<8s}".format("Func", "GOT", "Address"))

data = []
for g in sorted(elf.got):
    if "code_" in g:
        print("{:<12s} {:<8x} {:<8x}".format(g, elf.got[g], elf.symbols[g]))
        data.append([g, elf.got[g], elf.symbols[g]])

for l in data:
    num = int(l[0][5:])
    l.insert(0, num)

# for d in sorted(data): print('"{:x}", '.format(d[3]), end='')