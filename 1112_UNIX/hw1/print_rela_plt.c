#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>

void print_rela_plt(const char *filename) {
    // 開啟檔案，取得檔案描述符號(fd)
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return;
    }

    // 取得檔案的大小
    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return;
    }

    // 將整個檔案映射到記憶體
    void *addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return;
    }

    // 取得 ELF header
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)addr;

    // 取得 section name string table 的 section header
    Elf64_Shdr *shdr_strtab = (Elf64_Shdr *)(addr + ehdr->e_shoff + ehdr->e_shstrndx * ehdr->e_shentsize);

    // 取得 .rela.plt section header 的索引值
    int shdr_idx_rela_plt = -1;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *shdr = (Elf64_Shdr *)(addr + ehdr->e_shoff + i * ehdr->e_shentsize);
        const char *name = (const char *)(addr + shdr_strtab->sh_offset + shdr->sh_name);
        if (strcmp(name, ".rela.plt") == 0) {
            shdr_idx_rela_plt = i;
            break;
        }
    }

    // 如果找不到 .rela.plt section header 則離開函式
    if (shdr_idx_rela_plt < 0) {
        printf("No .rela.plt section found\n");
        munmap(addr, st.st_size);
        close(fd);
        return;
    }

    // 取得 .rela.plt section header
    Elf64_Shdr *shdr_rela_plt = (Elf64_Shdr *)(addr + ehdr->e_shoff + shdr_idx_rela_plt * ehdr->e_shentsize);

    // 取得 .rela.plt section 的起始位置
    void *rela_plt_addr = (void *)(addr + shdr_rela_plt->sh_offset);

    // 取得 .rela.plt section 的項目數量
    int num_rela_plt = shdr_rela_plt->sh_size / shdr_rela_plt->sh_entsize;

    // 逐一列印 .rela.plt section 的資訊
    for (int i = 0; i < num_rela_plt; i++) {
        Elf64_Rela rela = ((Elf64_Rela *)rela_plt_addr)[i];
        Elf64_Word sym_idx = ELF64_R_SYM(rela.r_info);
        Elf64_Xword type = ELF64_R_TYPE(rela.r_info);
        Elf64_Addr offset = rela.r_offset;
        printf("Relocation #%d\n", i);
        printf("\tSymbol index: %u\n", sym_idx);
        printf("\tRelocation type: %lu\n", type);
        printf("\tOffset: 0x%lx\n", offset);
        printf("\tAddend: %ld\n", rela.r_addend);
    }

    // 釋放記憶體，關閉檔案
    munmap(addr, st.st_size);
    close(fd);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <ELF file>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];

    print_rela_plt(filename);

    return 0;
}

