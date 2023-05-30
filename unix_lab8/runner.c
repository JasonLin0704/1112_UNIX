#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <string.h>

void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

int main(int argc, char *argv[]) {
	pid_t child;
	if(argc < 2) {
		fprintf(stderr, "usage: %s program [args ...]\n", argv[0]);
		return -1;
	}
	if((child = fork()) < 0) errquit("fork");
	if(child == 0) {
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace@child");
		execvp(argv[1], argv + 1);
		errquit("execvp");
	} else {
		int status;
        int cc = 0, num = 0;
        unsigned long magic_pos;
        long ret1, ret2;
        char *c1, *c2;
        struct user_regs_struct regs, restart_regs;
		if(waitpid(child, &status, 0) < 0) errquit("waitpid");
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
        ptrace(PTRACE_CONT, child, 0, 0);
		while(waitpid(child, &status, 0) > 0) {
			if(!WIFSTOPPED(status)) continue;
            if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
            cc += 1;
            // printf("%llx cc%d\n", regs.rip, cc);
            if(cc == 2){
                magic_pos = regs.rax;
            }
            else if(cc == 3){
                restart_regs = regs;
                break;
            }
			ptrace(PTRACE_CONT, child, 0, 0);
		}
        /* Iteration */
        ptrace(PTRACE_CONT, child, 0, 0);
		while(waitpid(child, &status, 0) > 0) {
			if(!WIFSTOPPED(status)) continue;
            if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
            cc += 1;
            if(cc == 5 && regs.rax != 0){
                num += 1;
                
                ret1 = ptrace(PTRACE_PEEKTEXT, child, magic_pos, NULL);
                ret2 = ptrace(PTRACE_PEEKTEXT, child, magic_pos + 8, NULL);
                c1 = (char *)&ret1;
                c2 = (char *)&ret2;
                
                // for(int i = 0; i < 8; i++) printf("%c", c1[i]); printf(" ");
                // for(int i = 0; i < 8; i++) printf("%c", c2[i]); printf("\n");

                int tmp = num;
                for(int i = 0; i < 8; i++){
                    c1[i] = '0' + (tmp % 2);
                    tmp >>= 1;
                }
                c2[0] = '0' + (tmp % 2);

                // for(int i = 0; i < 8; i++) printf("%c", c1[i]); printf(" ");
                // for(int i = 0; i < 8; i++) printf("%c", c2[i]); printf("\n"); break;

                long data1, data2;
                for(int i = 8; i >= 0; i--){
                    data1 = (data1 << 8) | c1[i];
                    data2 = (data2 << 8) | c2[i];
                } 
                if(ptrace(PTRACE_POKETEXT, child, magic_pos, data1) != 0) errquit("ptrace(POKETEXT)");
                if(ptrace(PTRACE_POKETEXT, child, magic_pos + 8, data2) != 0) errquit("ptrace(POKETEXT)");
                
                /* Set back to original regs */
                if(num < 512){
                    if(ptrace(PTRACE_SETREGS, child, 0, &restart_regs) != 0) errquit("ptrace(SETREGS)");
                    cc = 3;
                }
            }
            ptrace(PTRACE_CONT, child, 0, 0);
		}
	}
	return 0;
}

