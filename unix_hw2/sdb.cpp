#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <elf.h>

#include <capstone/capstone.h>
#include "ptools.h"

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
using namespace std;

struct Instruction {
	unsigned char bytes[16];
	int size;
	string mnemonic;
	string operands;
};

struct Memory_section {
	unsigned long begin, end;
	vector<unsigned long long> mem;
};

static csh cshandle = 0;
static unordered_map<long long, Instruction> instructions;
static Instruction null_instrcution;
static unordered_map<unsigned long, int> breakpoints;
static vector<Memory_section> memory;

unsigned long long int start_addr = 0;
unsigned long long int end_addr = 0;

void errquit(const char *msg) {
	perror(msg); cs_close(&cshandle);
	exit(-1);
}

void disassemble(pid_t proc, char *proc_name) {
	FILE* file = fopen(proc_name, "rb");
    if(!file) errquit("fopen command");

    Elf64_Ehdr ehdr;
    fread(&ehdr, sizeof(Elf64_Ehdr), 1, file);

	/* .strtab is used for getting section header name */
    Elf64_Shdr shdr_strtab;
    fseek(file, ehdr.e_shoff + ehdr.e_shstrndx * ehdr.e_shentsize, SEEK_SET);
    fread(&shdr_strtab, sizeof(Elf64_Shdr), 1, file);

    Elf64_Shdr shdr_text;
    for(int i = 0; i < ehdr.e_shnum; i++){
        Elf64_Shdr shdr;
        char name[16];
        fseek(file, ehdr.e_shoff + i * ehdr.e_shentsize, SEEK_SET);
        fread(&shdr, sizeof(Elf64_Shdr), 1, file);
        fseek(file, shdr_strtab.sh_offset + shdr.sh_name, SEEK_SET); /* sh_name is the index in strtab */
        fread(name, sizeof(char), 16, file);
        if(strcmp(name, ".text") == 0) shdr_text = shdr;
    }
	// printf("%lu %lx %lx %lx\n", shdr_text.sh_size, shdr_text.sh_addr, shdr_text.sh_offset, ehdr.e_entry);
	
	start_addr = shdr_text.sh_addr;
	end_addr = shdr_text.sh_addr + shdr_text.sh_size;

	char text_data[512];
	fseek(file, shdr_text.sh_offset, SEEK_SET);
	fread(text_data, sizeof(char), shdr_text.sh_size, file);
	fclose(file);
	// for (int i = 0; i < shdr_text.sh_size; i++) printf("%02hhx ", text_data[i]); printf("\n");

	int count;
	cs_insn *insn;
	if(cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK) errquit("cs_open");
	if((count = cs_disasm(cshandle, (uint8_t*) text_data, shdr_text.sh_size, shdr_text.sh_addr, 0, &insn)) > 0) {
		for(int i = 0; i < count; i++) {
			Instruction in;
			in.size = insn[i].size;
			in.mnemonic  = insn[i].mnemonic;
			in.operands = insn[i].op_str;
			memcpy(in.bytes, insn[i].bytes, insn[i].size);
			instructions[insn[i].address] = in;
		}
		cs_free(insn, count);
	}
	cs_close(&cshandle);
	return;
}

void print_instruction(long long addr, Instruction *in) {
	int i;
	char bytes[128] = "";
	if(in == NULL) {
		fprintf(stderr, "      %llx:\t<cannot disassemble>\n", addr);
	} else {
		for(i = 0; i < in->size; i++) {
			snprintf(&bytes[i*3], 4, "%2.2x ", in->bytes[i]);
		}
		fprintf(stderr, "      %llx: %-32s%-10s%s\n", addr, bytes, in->mnemonic.c_str(), in->operands.c_str());
	}
}

void print_5_instructions(long long rip){
	sleep(0.00001);
	for(int i = 0; i < 5; i++){
		if(rip >= end_addr){
			fprintf(stderr, "** the address is out of the range of the text section.\n");
			break;
		}
		if(instructions.count(rip)) print_instruction(rip, &instructions[rip]);
		else print_instruction(rip, NULL);
		rip += instructions[rip].size;
	}
}

void set_breakpoint(pid_t child, unsigned long long int addr){
	long data = ptrace(PTRACE_PEEKTEXT, child, addr, 0);
	breakpoints[addr] = data & 0x00000000000000ff;
	if(ptrace(PTRACE_POKETEXT, child, addr, (data & 0xffffffffffffff00) | 0xcc) != 0) errquit("PTRACE_POKETEXT@set_breakpoint");
}

void clear_breakpoint(pid_t child, unsigned long long int addr){
	long data = ptrace(PTRACE_PEEKTEXT, child, addr, 0);
	if(ptrace(PTRACE_POKETEXT, child, addr, (data & 0xffffffffffffff00) | breakpoints[addr]) != 0) errquit("PTRACE_POKETEXT@clear_breakpoint");
}

bool check_breakpoint(pid_t child, unsigned long long int addr){
	if(breakpoints.count(addr)){
		fprintf(stderr, "** hit a breakpoint 0x%llx\n", addr);
		return true;
	}
	return false;
}

int sdb(pid_t child, char *child_name){

	/* Disasm .text section in the .elf file */
	disassemble(child, child_name);

	/* Start the debugger */
	struct user_regs_struct regs;
	int wait_status;
	if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
	if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("PTRACE_GETREGS");
	fprintf(stderr, "** program '%s' loaded. entry point 0x%llx\n", child_name, regs.rip);
	print_5_instructions(regs.rip);

	string op;
	unsigned long long int rip;
	unsigned long long int addr;
	bool hit = false;
	unsigned long long int hit_addr;
	struct user_regs_struct anchor_regs;
	map<range_t, map_entry_t> m;
	map<range_t, map_entry_t>::iterator mi;

	/*	My Method  */
	/*	
		There're total 5 ops: si, cont, break, anchor, timetravel.
		When we need to set breakpoints (bps), we modify instructions to "0xcc".
		Initialize a boolean variable "hit" as false, and use it to determine hit a bp or not.
		
		There'are two scenarios leading to "hit = true":
		1. After si or cont
		- After executing si and rip = addr of bp 			=> "0xcc" haven't been executed. 
		- After executing cont and rip - 1 = addr of bp 	=> "0xcc" have already been executed.
		
		2. Set bp to rip, or timetravel back to the bp

		For all cases we should set "hit" to true and record the hit addr, in order to recover the bp in the next loop.
		
	*/
	while(WIFSTOPPED(wait_status)){
		while(1){
			fprintf(stderr, "(sdb) ");
			getline(cin, op);

			/* "0xcc" wouldn't be executed */
			if(op == "si"){
				if(hit){
					clear_breakpoint(child, hit_addr);

					if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) errquit("PTRACE_SINGLESTEP");
					if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
					if(!WIFSTOPPED(wait_status)) break;

					hit = false;
					set_breakpoint(child, hit_addr);
				}
				else{
					if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) errquit("PTRACE_SINGLESTEP");
					if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
					if(!WIFSTOPPED(wait_status)) break;
				}
				
				if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("PTRACE_GETREGS");
				if(breakpoints.count(regs.rip)){
					fprintf(stderr, "** hit a breakpoint 0x%llx\n", regs.rip);
					hit = true;
					hit_addr = regs.rip;
				}
				print_5_instructions(regs.rip);
				break;
			}
			/* "0xcc" would be executed */
			else if(op == "cont"){
				if(hit){
					clear_breakpoint(child, hit_addr);

					if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) errquit("PTRACE_SINGLESTEP");
					if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
					if(!WIFSTOPPED(wait_status)) break;

					hit = false;
					set_breakpoint(child, hit_addr);

					/* There's also another adjacent breakpoint here */
					if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("PTRACE_GETREGS");
					if(check_breakpoint(child, regs.rip)){
						hit = true;
						hit_addr = regs.rip;
						print_5_instructions(regs.rip);
						break;
					}
				}
				if(ptrace(PTRACE_CONT, child, 0, 0) < 0) errquit("PTRACE_CONT");
				if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
				if(!WIFSTOPPED(wait_status)) break;

				if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("PTRACE_GETREGS");
				if(check_breakpoint(child, regs.rip - 1)){
					hit = true;
					hit_addr = regs.rip - 1;
					regs.rip--;
					if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) errquit("PTRACE_SETREGS");
					print_5_instructions(regs.rip);
				}
				break;
			}
			/* Modify the first byte to "0xcc" unless position = rip */
			else if(op.substr(0, 5) == "break"){
				fprintf(stderr, "** set a breakpoint at %s\n", op.substr(6).c_str());
				addr = stoi(op.substr(8), 0, 16);
				if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("PTRACE_GETREGS");
				set_breakpoint(child, addr);

				/* If there's a breakpoint on the anchor, should not break */
				if(addr == regs.rip){
					hit = true;
					hit_addr = regs.rip;
				}
			}
			else if(op == "anchor"){
				fprintf(stderr, "** dropped an anchor\n");
				if(ptrace(PTRACE_GETREGS, child, 0, &anchor_regs) != 0) errquit("PTRACE_GETREGS");
				if(load_maps(child, m) > 0) {
					memory.clear();
					for(mi = m.begin(); mi != m.end(); mi++) {
						if(mi->second.perm & 2){ /* only record blocks that can be writen */
							Memory_section ms;
							ms.begin = mi->second.range.begin;
							ms.end = mi->second.range.end;
							for(unsigned long ptr = ms.begin; ptr < ms.end; ptr += 8){
								unsigned long long peek = ptrace(PTRACE_PEEKTEXT, child, ptr, NULL);
								ms.mem.push_back(peek);
							}
							memory.push_back(ms);
						}
					}
				}
			}
			else if(op == "timetravel"){
				fprintf(stderr, "** go back to the anchor point\n");
				if(ptrace(PTRACE_SETREGS, child, 0, &anchor_regs) != 0) errquit("PTRACE_SETREGS");
				for(int i = 0; i < memory.size(); i++) {
					auto ms = memory[i];
					for(unsigned long ptr = ms.begin; ptr < ms.end; ptr += 8){
						unsigned long long data = ms.mem[(ptr - ms.begin) / 8];
						if(ptrace(PTRACE_POKETEXT, child, ptr, data) != 0) errquit("PTRACE_POKETEXT@timetravel");
					}
				}
				if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("PTRACE_GETREGS");
				print_5_instructions(regs.rip);

				/* If there's a breakpoint on the anchor, should not break */
				if(breakpoints.count(regs.rip)){
					hit = true;
					hit_addr = regs.rip;
				}
			}
			else{
				// Do nothing
			}
		}
	}
	fprintf(stderr, "** the target program terminated.\n");
	return 0;
}

int main(int argc, char *argv[]) {
	pid_t child;
	if(argc < 2) {
		fprintf(stderr, "usage: %s program [args ...]\n", argv[0]);
		return -1;
	}
	if((child = fork()) < 0) errquit("fork");
	int res = 0;
	if(child == 0) {
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("PTRACE_TRACEME");
		execvp(argv[1], argv + 1);
		errquit("execvp");
	} else {
		res = sdb(child, argv[1]);
	}
	return res;
}
