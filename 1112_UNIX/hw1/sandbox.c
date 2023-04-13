#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <errno.h>
#include <elf.h>

#define errquit(m)	{ perror(m); _exit(-1); }

int __libc_start_main(int *(main) (int, char * *, char * *),
                      int argc, char * * ubp_av, 
                      void (*init) (void), 
                      void (*fini) (void), 
                      void (*rtld_fini) (void), 
                      void (* stack_end)){
    void *handle = dlopen("/usr/lib/x86_64-linux-gnu/libc-2.31.so", RTLD_LAZY);
    if(!handle) errquit("dlopen");



    typeof(&__libc_start_main) real_main = dlsym(handle, "__libc_start_main");
    return real_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}