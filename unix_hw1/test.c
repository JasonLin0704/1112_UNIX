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

typedef int (*open_ptr_t)(const char *, int, mode_t);

open_ptr_t real_open;

int main(){
    system("cat /etc/hosts");
    // system("readelf -r /usr/bin/cat");

    return 0;
}