from pwn import *
elf = ELF('./launcher')
print("{:<12s} {:<8s} {:<8s}".format("Func", "GOT", "Address"))

for g in sorted(elf.got):
    print("{:<12s} {:<8x} {:<8x}".format(g, elf.got[g], elf.symbols[g]))