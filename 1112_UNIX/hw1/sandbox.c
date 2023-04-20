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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>

#define errquit(m) { perror(m); _exit(-1); }
#define max(a, b) ((a) > (b) ? (a):(b))

int __libc_start_main(int *(main) (int, char * *, char * *), int argc, char * * ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end));
void hijack(int argc, char * * ubp_av);
int fake_open(const char *pathname, int flags, mode_t mode);
ssize_t fake_read(int fd, void *buf, size_t count);
ssize_t fake_write(int fd, const void *buf, size_t count);
int fake_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int fake_getaddrinfo(const char *restrict node, const char *restrict service, const struct addrinfo *restrict hints, struct addrinfo **restrict res);
int fake_system(const char *command);
int fake_close(int fd);

int find_fd_index(int fd);

typedef int (*open_ptr_t)(const char *, int, mode_t);
typedef ssize_t (*read_ptr_t)(int, void *, size_t);
typedef ssize_t (*write_ptr_t)(int, const void *, size_t);
typedef int (*connect_ptr_t)(int, const struct sockaddr *, socklen_t);
typedef int (*getaddrinfo_ptr_t)(const char *restrict, const char *restrict, const struct addrinfo *restrict, struct addrinfo **restrict);
typedef int (*system_ptr_t)(const char *);
typedef int (*close_ptr_t)(int);

open_ptr_t real_open;
read_ptr_t real_read;
write_ptr_t real_write;
connect_ptr_t real_connect;
getaddrinfo_ptr_t real_getaddrinfo;
system_ptr_t real_system;
close_ptr_t real_close;

int LOGGER_FD;
char *CONFIG;

int fd_len = 0;
int fd_list[10000];
int fd_start[10000];

int __libc_start_main(int *(main) (int, char * *, char * *),
                      int argc, char * * ubp_av, 
                      void (*init) (void), 
                      void (*fini) (void), 
                      void (*rtld_fini) (void), 
                      void (* stack_end)){
    void *handle = dlopen("/usr/lib/x86_64-linux-gnu/libc-2.31.so", RTLD_LAZY);
    if(!handle) errquit("dlopen");

    printf("pid: %d\n", getpid());
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
            real_getaddrinfo = (getaddrinfo_ptr_t) *(uint64_t*)addr;
            *(uint64_t*)addr = (uint64_t)fake_getaddrinfo;
        } 
        else if(strcmp(sym_name, "system") == 0){
            real_system = (system_ptr_t) *(uint64_t*)addr;
            *(uint64_t*)addr = (uint64_t)fake_system; 
        }
        else if(strcmp(sym_name, "close") == 0){
            real_close = (close_ptr_t) *(uint64_t*)addr;
            *(uint64_t*)addr = (uint64_t)fake_close; 
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
    int ret = real_open(pathname, flags, mode);
    dprintf(LOGGER_FD, "[logger] open(\"%s\", %d, %u) = %d\n", pathname, flags, mode, ret);
    return ret;
}

ssize_t fake_read(int fd, void *buf, size_t count){
    printf("\nfake_read\n");

    /* Get the keyword from the config.txt */
    FILE *file = fopen(CONFIG, "r");
    if(!file) errquit("fopen config");
    int flag = 0;
    char *keyword = NULL;
    size_t len = 0;
    while (getline(&keyword, &len, file) != -1){
        if(strcmp(keyword, "BEGIN read-blacklist\n") == 0) flag = 1;
        else if(strcmp(keyword, "END read-blacklist\n") == 0) break;
        else if(flag == 1){
            keyword[strlen(keyword) - 1] = '\0'; // printf("%s\n", keyword);
            break;
        }
    }
    fclose(file);
    
    
    int log_fd;
    char log_content[65536];
    char filename[32];
    sprintf(filename, "%d-%d-read.log", getpid(), fd);

    ssize_t pre, ret;
    
    /* Log file is already existed */
    if(access(filename, F_OK) == 0){
        log_fd = real_open(filename, O_APPEND | O_RDWR, S_IRWXU);

        /* Combine with previous content from log file and do filtering */
        int index = find_fd_index(log_fd);
        lseek(log_fd, fd_start[index], SEEK_SET);
        pre = max(0, real_read(log_fd, log_content, strlen(log_content) - 1));
        ret = real_read(fd, buf, count);
        strcat(log_content, buf); // printf("log_content:\n %s\n", log_content);
        if(strstr(log_content, keyword) != NULL){
            close(fd);
            errno = EIO;
            ret = -1;
        }
        else{
            real_write(log_fd, log_content, pre + ret);
            real_close(log_fd);
        }
    }
    /* Log file isn't existed */                    
    else{
        ret = real_read(fd, buf, count);
        strcat(log_content, buf); 
        if(strstr(log_content, keyword) != NULL){
            close(fd);
            errno = EIO;
            ret = -1;
        }
        else{
            log_fd = real_open(filename, O_CREAT | O_RDWR, S_IRWXU);
            real_write(log_fd, log_content, ret);
            real_close(log_fd);
        }
    } 
    
    free(keyword);

    dprintf(LOGGER_FD, "[logger] read(%d, %p, %ld) = %ld\n", fd, buf, count, ret);
    return ret;
}

ssize_t fake_write(int fd, const void *buf, size_t count){
    printf("\nfake_write\n");

    int log_fd;
    char filename[32];
    sprintf(filename, "%d-%d-write.log", getpid(), fd);
    
    /* Log file is already existed or not */
    if(access(filename, F_OK) == 0) log_fd = real_open(filename, O_APPEND | O_RDWR, S_IRWXU);                    
    else log_fd = real_open(filename, O_CREAT | O_RDWR, S_IRWXU);

    real_write(log_fd, buf, count);
    real_close(log_fd);

    ssize_t ret = real_write(fd, buf, count);
    dprintf(LOGGER_FD, "[logger] write(%d, %p, %ld) = %ld\n", fd, buf, count, ret);
    return ret;
}

int fake_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    printf("\nfake_connect\n");

    char ip_in[INET_ADDRSTRLEN];
    int port_in;
    struct sockaddr_in *addr_in = (struct sockaddr_in *)addr; 
    if(addr->sa_family == AF_INET){
        inet_ntop(AF_INET, &(addr_in->sin_addr), ip_in, INET_ADDRSTRLEN);
        port_in = ntohs(addr_in->sin_port);
        printf("IP address: %s\n", ip_in);
        printf("Port: %d\n", port_in);
    }
    
    FILE *file = fopen(CONFIG, "r");
    if(!file) errquit("fopen config");
    
    int flag = 0;

    char *contents = NULL;
    size_t len = 0;
    while (getline(&contents, &len, file) != -1){
        if(strcmp(contents, "BEGIN connect-blacklist\n") == 0) flag = 1;
        else if(strcmp(contents, "END connect-blacklist\n") == 0) break;
        else if(flag == 1){
            contents[strlen(contents) - 1] = '\0';
            char *hostname = strtok(contents, ":");
            char *port = strtok(NULL, ":");
            printf("%s\n", hostname);
            printf("%s\n", port);

            struct addrinfo hints, *servinfo;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;

            if(getaddrinfo(hostname , "http" , &hints , &servinfo) != 0) errquit("resolve hostname by ip");
            for(struct addrinfo *p = servinfo; p != NULL; p = p->ai_next){
                struct sockaddr_in *h = (struct sockaddr_in *) p->ai_addr;
                printf("%s\n", inet_ntoa(h->sin_addr));
                printf("%d\n", ntohs(h->sin_port));
            }
            freeaddrinfo(servinfo);
        }
    }
    fclose(file);
    free(contents);
    if(flag == -1) return -1;

    int res = real_connect(sockfd, addr, addrlen);
    printf("res: %d\n", res);
    return res;
}

int fake_getaddrinfo(const char *restrict node, const char *restrict service, const struct addrinfo *restrict hints, struct addrinfo **restrict res){
    printf("\nfake_getaddrinfo\n");


    int ret = real_getaddrinfo(node, service, hints, res);
    return ret;
}

int fake_system(const char *command){
    printf("\nfake_system\n");
}

int fake_close(int fd){
    printf("\nfake_close\n");

    int index = find_fd_index(fd);
    
    char buffer[65536];
    ssize_t bytes = real_read(fd, &buffer, strlen(buffer) - 1);
    fd_start[index] += bytes;

    int ret = real_close(fd);
    return ret;
}

int find_fd_index(int fd){
    int index;
    for(index = 0; index <= fd_len; index++){
        if(index == fd_len){
            fd_list[fd_len] = fd;
            fd_start[index] = 0;
            fd_len += 1;
            break;
        }
        if(fd_list[index] == fd){
            break;
        }
    }
    return index;
}
