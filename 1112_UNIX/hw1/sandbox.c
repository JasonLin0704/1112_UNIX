#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <errno.h>
#include <elf.h>
#include <sys/socket.h>

#define errquit(m)	{ perror(m); _exit(-1); }

int LOGGER_FD;
char *CONFIG;

typedef int (*open_ptr_t)(const char *, int, mode_t);
open_ptr_t real_open;


uint64_t got_addr_open = 0;
uint64_t got_addr_read = 0;
uint64_t got_addr_write = 0;
uint64_t got_addr_connect = 0;
uint64_t got_addr_getaddrinfo = 0;
uint64_t got_addr_system = 0;

uint64_t got_val_open = 0;
uint64_t got_val_read = 0;
uint64_t got_val_write = 0;
uint64_t got_val_connect = 0;
uint64_t got_val_getaddrinfo = 0;
uint64_t got_val_system = 0;

int __libc_start_main(int *(main) (int, char * *, char * *), int argc, char * * ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end));
void hijack(int argc, char * * ubp_av);
void modify_got(uint64_t addr, uint64_t target);
int fake_open(const char *pathname, int flags, mode_t mode);
ssize_t fake_read(int fd, void *buf, size_t count);
ssize_t fake_write(int fd, const void *buf, size_t count);
int fake_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

int __libc_start_main(int *(main) (int, char * *, char * *),
                      int argc, char * * ubp_av, 
                      void (*init) (void), 
                      void (*fini) (void), 
                      void (*rtld_fini) (void), 
                      void (* stack_end)){
    // printf("__libc_start_main() start\n");
    void *handle = dlopen("/usr/lib/x86_64-linux-gnu/libc-2.31.so", RTLD_LAZY);
    if(!handle) errquit("dlopen");

    LOGGER_FD = atoi(getenv("LOGGER_FD"));
    CONFIG = getenv("SANDBOX_CONFIG");

    hijack(argc, ubp_av);

    typeof(&__libc_start_main) real_main = dlsym(handle, "__libc_start_main");
    return real_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}

void hijack(int argc, char * * ubp_av){
    // printf("%d\n", argc);
    // printf("argument: %s %s\n", *ubp_av, *(ubp_av + 1));

    // char command[128];
    char command[128] = "/usr/bin/";
    strcat(command, *ubp_av);
    // printf("command: %s\n\n", command);
    
    int fd, sz;
    char buf[16384], *s = buf;
    if ((fd = open("/proc/self/maps", O_RDONLY)) < 0) printf("1");
    while ((sz = read(fd, s, sizeof(buf) - 1 - (s - buf))) > 0){ s += sz; }
    *s = 0;
    s = buf;
    close(fd);
    // for (int i = 0; i < 100; i++) printf("%c", buf[i]); printf("\n");
    
    char base_str[16];
    strncpy(base_str, buf, 12);
    unsigned long int base = strtol(base_str, NULL, 16);
    // printf("base: %lx\n\n", base);
    
    FILE* file = fopen(command, "rb");
    if(!file) errquit("fopen command");

    Elf64_Ehdr ehdr;
    fread(&ehdr, sizeof(Elf64_Ehdr), 1, file);
    // printf("e_shoff: %lx\n", ehdr.e_shoff);
    // printf("e_shnum: %u\n", ehdr.e_shnum);
    // printf("e_shentsize: %u\n", ehdr.e_shentsize);
    // printf("e_shstrndx: %u\n", ehdr.e_shstrndx);

    Elf64_Shdr shdr_strtab;
    fseek(file, ehdr.e_shoff + ehdr.e_shstrndx * ehdr.e_shentsize, SEEK_SET);
    fread(&shdr_strtab, sizeof(Elf64_Shdr), 1, file);

    Elf64_Shdr shdr_rela_plt;
    Elf64_Shdr shdr_dynsym;
    Elf64_Shdr shdr_dynstr;
    for(int i = 0; i < ehdr.e_shnum; i++){
        Elf64_Shdr shdr;
        char name[16];
        fseek(file, ehdr.e_shoff + i * ehdr.e_shentsize, SEEK_SET);
        fread(&shdr, sizeof(Elf64_Shdr), 1, file);
        fseek(file, shdr_strtab.sh_offset + shdr.sh_name, SEEK_SET);
        fread(name, sizeof(char), 16, file);
        if(strcmp(name, ".rela.plt") == 0) shdr_rela_plt = shdr;
        if(strcmp(name, ".dynsym") == 0) shdr_dynsym = shdr;
        if(strcmp(name, ".dynstr") == 0) shdr_dynstr = shdr;
    }

    for (int i = 0; i < shdr_rela_plt.sh_size / shdr_rela_plt.sh_entsize; i++) {
        Elf64_Rela rela;
        fseek(file, shdr_rela_plt.sh_offset + i * shdr_rela_plt.sh_entsize, SEEK_SET);
        fread(&rela, sizeof(Elf64_Rela), 1, file);

        Elf64_Addr offset = rela.r_offset;
        Elf64_Word sym_idx = ELF64_R_SYM(rela.r_info);

        Elf64_Sym sym;
        fseek(file, shdr_dynsym.sh_offset + sym_idx * shdr_dynsym.sh_entsize, SEEK_SET);
        fread(&sym, sizeof(Elf64_Sym), 1, file);

        char sym_name[32];
        fseek(file, shdr_dynstr.sh_offset + sym.st_name, SEEK_SET);
        fread(sym_name, sizeof(char), 32, file);
        //printf("0x%lx %u %s\n", offset, sym_idx, sym_name);

        uint64_t addr = base + offset;
        int PageSize = sysconf(_SC_PAGE_SIZE);
        void *a = (void *)(addr & ~(PageSize - 1));
        if (mprotect(a, PageSize, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) errquit("mprotect");
        if(strcmp(sym_name, "open") == 0){
            got_addr_open = addr;
            got_val_open = *(uint64_t*)addr;
            real_open = (open_ptr_t) got_val_open;
            modify_got(addr, (uint64_t)fake_open);
        } else if(strcmp(sym_name, "read") == 0){
            got_addr_read = addr;
            got_val_read = *(uint64_t*)addr;
            modify_got(addr, (uint64_t)fake_read);
        } else if(strcmp(sym_name, "write") == 0){
            got_addr_write = addr;
            got_val_write = *(uint64_t*)addr;
            modify_got(addr, (uint64_t)fake_write);
        } else if(strcmp(sym_name, "connect") == 0){
            got_addr_connect = addr;
            got_val_connect = *(uint64_t*)addr;
            modify_got(addr, (uint64_t)fake_connect);
        } else if(strcmp(sym_name, "getaddrinfo") == 0){
            continue;
        } else if(strcmp(sym_name, "system") == 0){
            continue;
        }
    }
    fclose(file);
}

void modify_got(uint64_t addr, uint64_t target){
    // printf("modify_got\n");
    // printf("addr: %lu\n", addr);
    // printf("target: %lu\n", target);
    // printf("val: %lx\n", *(uint64_t*)addr);
    *(uint64_t*)addr = target;
    // printf("val: %lx\n", *(uint64_t*)addr);
}

int fake_open(const char *pathname, int flags, mode_t mode){
    // printf("fake_open\n");

    FILE *file = fopen(CONFIG, "r");
    if(!file) errquit("fopen config");
    
    int flag = 0;
    
    char *contents = NULL;
    size_t len = 0;
    while (getline(&contents, &len, file) != -1){
        if(strcmp(contents, "BEGIN open-blacklist\n") == 0) flag = 1;
        else if(strcmp(contents, "END open-blacklist\n") == 0) break;
        else if(flag == 1){
            contents[strlen(contents) - 1] = '\0';
            struct stat buf;
            int x;
            char path1[256], path2[256];
            strcpy(path1, pathname);
            while(1){
                printf("%s %s\n", contents, path1);
                if(strcmp(contents, path1) == 0){
                    flag = -1;
                    errno = EACCES;
                    break;
                }
                x = lstat(path1, &buf);
                if(S_ISLNK(buf.st_mode)){        
                    if(readlink(path1, path2, sizeof(path2)) == -1) errquit("readlink");
                    strcpy(path1, path2);
                }
                else break;
            }
        }
    }
    fclose(file);
    free(contents);
    if(flag == -1) return -1; 

    //modify_got(got_addr_open, got_val_open);
    if(~(flags & O_CREAT || flags & __O_TMPFILE)) mode = 0;
    int res = real_open(pathname, flags, mode);
    dprintf(LOGGER_FD, "[logger] open(\"%s\", %d, %u) = %d\n", pathname, flags, mode, res);
    return res;
}

ssize_t fake_read(int fd, void *buf, size_t count){
    printf("fake_read\n");
    
    FILE *file = fopen(CONFIG, "r");
    if(!file) errquit("fopen config");
    
    /* Create fd if needed */
    char filename[32];
    pid_t pid = getpid();
    sprintf(filename, "%d-%d-read.log", pid, fd);
    printf("%s\n", filename);
    int log_fd = open(filename, O_CREAT, S_IRWXU);
    

    int flag = 0;

    char *contents = NULL;
    size_t len = 0;
    while (getline(&contents, &len, file) != -1){
        if(strcmp(contents, "BEGIN read-blacklist\n") == 0) flag = 1;
        else if(strcmp(contents, "END read-blacklist\n") == 0) break;
        else if(flag == 1){
            contents[strlen(contents) - 1] = '\0';
            break;
        }
    }
    fclose(file);
    
    /* check */
    printf("%s\n", contents);

    free(contents);

    modify_got(got_addr_read, got_val_read);
    ssize_t res = read(fd, buf, count);
    // printf("%s\n", (char *)buf);
    dprintf(LOGGER_FD, "[logger] read(%d, %p, %ld) = %ld\n", fd, buf, count, res);
    return res;
}

ssize_t fake_write(int fd, const void *buf, size_t count){
    printf("fake_write\n");

    modify_got(got_addr_write, got_val_write);
    ssize_t res = write(fd, buf, count);
    // printf("%s\n", (char *)buf);
    dprintf(LOGGER_FD, "[logger] write(%d, %p, %ld) = %ld\n", fd, buf, count, res);
    return res;
}

int fake_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    printf("\nfake_connect\n");
    printf("%c\n", addr->sa_data[0]);
    
    // FILE *file = fopen(CONFIG, "r");
    // if(!file) errquit("fopen config");
    
    // int flag = 0;

    // char *contents = NULL;
    // size_t len = 0;
    // while (getline(&contents, &len, file) != -1){
    //     if(strcmp(contents, "BEGIN connect-blacklist\n") == 0) flag = 1;
    //     else if(strcmp(contents, "END connect-blacklist\n") == 0) break;
    //     else if(flag == 1){
    //         contents[strlen(contents) - 1] = '\0';
    //         if(strcmp(strtok(contents, ":"), )){
    //             flag = -1;
    //             errno = ECONNREFUSED;
    //             break;
    //         }
    //     }
    // }
    // fclose(file);
    // free(contents);
    // if(flag == -1) return -1;

    modify_got(got_addr_connect, got_val_connect);
    int res = connect(sockfd, addr, addrlen);
    printf("res: %d\n", res);
    return res;
}

