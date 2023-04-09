#include <stdio.h>

typedef int (*printf_ptr_t)(const char *format, ...);

void solver(printf_ptr_t fptr) {
	// char msg[8];
	// fptr("canary=%016lx\n", *(unsigned long *)&msg[8]);
	// fptr("rbp=%016lx\n", *(unsigned long *)&msg[16]);
	// fptr("return address=%016lx\n", *(unsigned long *)&msg[24]);
	char format[8] = "%lx%lx\n";
	fptr(format, 
		*(unsigned long *)&format[8], 
		*(unsigned long *)&format[16]
	);
	fptr(format, 
		*(unsigned long *)&format[24], 
		*(unsigned long *)&format[8]
	);
}

int main() {
	char fmt[16] = "** main = %p\n";
	printf(fmt, main);
	solver(printf);
	return 0;
}
