from pwn import *
elf = ELF('./chals')
print("main =", hex(elf.symbols['main']))
print("{:<12s} {:<8s} {:<8s}".format("Func", "GOT", "Address"))
data = []
cnt = 0
for g in elf.got:
    print(g)
    if "code_" in g:
        # print("{:<12s} {:<8x} {:<8x}".format(g, elf.got[g], elf.symbols[g]))
        data.append([g, elf.got[g], elf.symbols[g]])
        cnt += 1
print(cnt)
for l in data:
    num = int(l[0][5:])
    l.insert(0, num)
for d in sorted(data):
    pass
    # print("{}, ".format(d[1]))

print(len(data))