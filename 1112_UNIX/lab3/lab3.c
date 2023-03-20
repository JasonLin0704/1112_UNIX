#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libunwind.h>
#include <sys/mman.h>
#include <dlfcn.h>

#include "shuffle.h"

char code[] = {

};



int init(){
    int fd, sz;
    char buf[16384];
    if((fd = open("/proc/self/maps", O_RDONLY)) < 0) printf("1");
    if((sz = read(fd, buf, sizeof(buf)-1)) < 0) printf("2");
    
    printf("### lab3 ###\n");
    for(int i = 0; i < 1000; i++){
        printf("%c", buf[i]);
    }
    printf("### lab3 ###\n");
    close(fd);

    char base_str[12];
    strncpy(base_str, buf, 12);
    printf("%s\n", base_str);
    unsigned long int base  = strtol(base_str, NULL, 16);
    printf("%lx\n", base);

    void *handle = dlopen("libpoem.so", RTLD_LAZY);
    if(handle == NULL) printf("3");

    int n = sizeof(ndat)/sizeof(int); printf("%d\n", n);
    for(int i = 0; i < n; i++){
        //printf("%d %d\n", i, ndat[i]);
        char code_name[20] = "code_";
        char s[10];
        sprintf(s, "%d", i);
        strcat(code_name, s);
        void *ptr = dlsym(handle, code_name);
        //printf("%s %p\n", code_name, ptr);
    }
    void *ptr = dlsym(handle, "123");
    //printf("%p\n", ptr);
    printf("Done!\n");
}