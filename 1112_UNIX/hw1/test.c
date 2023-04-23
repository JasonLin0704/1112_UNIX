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

int main(){
    // system("readelf -r /usr/bin/cat");

    char filename[20] = "aaa";
    int log_fd = open(filename, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO);


    return 0;
}