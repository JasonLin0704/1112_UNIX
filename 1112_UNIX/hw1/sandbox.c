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


int __libc_start_main(int *(main) (int, char * *, char * *), int argc, char * * ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end));
void hijack(int argc, char * * ubp_av);
int fake_open(const char *pathname, int flags, mode_t mode);
ssize_t fake_read(int fd, void *buf, size_t count);
ssize_t fake_write(int fd, const void *buf, size_t count);
int fake_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

typedef int (*open_ptr_t)(const char *, int, mode_t);
typedef ssize_t (*read_ptr_t)(int, void *, size_t);
typedef ssize_t (*write_ptr_t)(int, const void *, size_t);
typedef int (*connect_ptr_t)(int, const struct sockaddr *, socklen_t);

open_ptr_t real_open;
read_ptr_t real_read;
write_ptr_t real_write;
connect_ptr_t real_connect;

int LOGGER_FD;
char *CONFIG;

int fd_len = 0;
int fd_list[10000];

int __libc_start_main(int *(main) (int, char * *, char * *),
                      int argc, char * * ubp_av, 
                      void (*init) (void), 
                      void (*fini) (void), 
                      void (*rtld_fini) (void), 
                      void (* stack_end)){
    void *handle = dlopen("/usr/lib/x86_64-linux-gnu/libc-2.31.so", RTLD_LAZY);
    if(!handle) errquit("dlopen");
    printf("%d\n", getpid());
    LOGGER_FD = atoi(getenv("LOGGER_FD"));
    CONFIG = getenv("SANDBOX_CONFIG");

    hijack(argc, ubp_av);

    typeof(&__libc_start_main) real_main = dlsym(handle, "__libc_start_main");
    return real_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}

void hijack(int argc, char * * ubp_av){
    // printf("argument: %s %s\n", *ubp_av, *(ubp_av + 1));

    // char command[128];
    char command[128] = "/usr/bin/";
    strcat(command, *ubp_av);
    // printf("command: %s\n\n", command);
    
    int fd, sz;
    char buf[16384], *s = buf;
    if((fd = open("/proc/self/maps", O_RDONLY)) < 0) errquit("open /proc/self/maps");
    while((sz = read(fd, s, sizeof(buf) - 1 - (s - buf))) > 0){ s += sz; }
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
    // printf("%lx %u %u %u\n", ehdr.e_shoff, ehdr.e_shnum, ehdr.e_shentsize, ehdr.e_shstrndx);
    

    /* .strtab is used for getting section header name */
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
        fseek(file, shdr_strtab.sh_offset + shdr.sh_name, SEEK_SET); /* sh_name is the index in strtab */
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
        if(mprotect(a, PageSize, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) errquit("mprotect");
        
        if(strcmp(sym_name, "open") == 0){
            real_open = (open_ptr_t) *(uint64_t*)addr; /* set original open to "real_open" */
            *(uint64_t*)addr = (uint64_t)fake_open;    /* modify got value into the address of "fake_open" */
        } 
        else if(strcmp(sym_name, "read") == 0){
            real_read = (read_ptr_t) *(uint64_t*)addr;
            *(uint64_t*)addr = (uint64_t)fake_read; 
        } 
        else if(strcmp(sym_name, "write") == 0){
            real_write = (write_ptr_t) *(uint64_t*)addr;
            *(uint64_t*)addr = (uint64_t)fake_write; 
        } 
        else if(strcmp(sym_name, "connect") == 0){
            real_connect = (connect_ptr_t) *(uint64_t*)addr;
            *(uint64_t*)addr = (uint64_t)fake_connect; 
        } 
        else if(strcmp(sym_name, "getaddrinfo") == 0){
            continue;
        } 
        else if(strcmp(sym_name, "system") == 0){
            continue;
        }
    }
    fclose(file);
}

int fake_open(const char *pathname, int flags, mode_t mode){
    printf("\nfake_open\n");

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
                // printf("%s %s\n", contents, path1);
                if(strcmp(contents, path1) == 0){
                    flag = -1;
                    errno = EACCES;
                    break;
                }
                /* Check if it's a symbolic link, and follow the link if yes */
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

    if(~(flags & O_CREAT || flags & __O_TMPFILE)) mode = 0;
    int res = real_open(pathname, flags, mode);
    dprintf(LOGGER_FD, "[logger] open(\"%s\", %d, %u) = %d\n", pathname, flags, mode, res);
    return res;
}

ssize_t fake_read(int fd, void *buf, size_t count){
    printf("\nfake_read\n");
    printf("%d\n", getpid());
    FILE *file = fopen(CONFIG, "r");
    if(!file) errquit("fopen config");
    
    /* Create fd if needed */
    // char filename[32];
    // sprintf(filename, "%d-%d-read.log", getpid(), fd);
    // printf("%s\n", filename);
    // int log_fd = open(filename, O_CREAT, S_IRWXU);
    // int visit = 0;
    // for(int i = 0; i < fd_len; i++) if(fd_list[i] == fd) visit = 1;

    // if(visit == 0){

    // }

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
    
    /* Check */
    printf("%s\n", contents);
    printf("%s\n", (char *)buf);
    
    free(contents);

    ssize_t res = real_read(fd, buf, count);
    dprintf(LOGGER_FD, "[logger] read(%d, %p, %ld) = %ld\n", fd, buf, count, res);
    return res;
}

ssize_t fake_write(int fd, const void *buf, size_t count){
    printf("\nfake_write\n");

    ssize_t res = real_write(fd, buf, count);
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

    int res = real_connect(sockfd, addr, addrlen);
    printf("res: %d\n", res);
    return res;
}

