/*
 *
 * Copyright 2021 Kenichi Yasukata
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <dis-asm.h>
#include <sched.h>

extern void syscall_addr(void);
extern long enter_syscall(long number, ...);
extern void asm_syscall_hook(void);

void ___enter_syscall(void)
{
	asm volatile (
	".globl enter_syscall \n\t"
	"enter_syscall: \n\t"
	"movq %rdi, %rax \n\t"
	"movq %rsi, %rdi \n\t"
	"movq %rdx, %rsi \n\t"
	"movq %rcx, %rdx \n\t"
	"movq %r8, %r10 \n\t"
	"movq %r9, %r8 \n\t"
	"movq 8(%rsp),%r9 \n\t"
	".globl syscall_addr \n\t"
	"syscall_addr: \n\t"
	"syscall \n\t"
	"ret \n\t"
	);
}

long syscall_hook(int64_t a1, int64_t a2, int64_t a3,
		  int64_t a4, int64_t a5, int64_t a6,
		  int64_t a7, int64_t retptr)
{
	long ret;
	/*
	 * here is our user-space system call hook
	 * a1 is the system call number, and
	 * a2~a7 are the arguments passed to
	 * the requested system call.
	 *
	 * retptr is the caller's address.
	 * this is necessary to set push it to
	 * the stack of a newly created pthread.
	 *
	 * NOTE: we should not use the functions of the
	 * rewritten binaries including libc and so on.
	 * that's why we use self-implemented "enter_syscall"
	 * to print the example message below.
	 */
#define DEMO 1
#ifdef DEMO
	/*
	 * example of the system call hook function.
	 * this prints a colored message if the system call is
	 * one of read, write, open, and close.
	 */
	switch (a1) { /* system call number */
	case __NR_read:
		enter_syscall(__NR_write, 1 /* stdout */,
			"\x1b[35msyscall hook: read system call\n\x1b[39m", 41);
		break;
	case __NR_write:
		enter_syscall(__NR_write, 1 /* stdout */,
			"\x1b[36msyscall hook: write system call\n\x1b[39m", 42);
		break;
	case __NR_open:
		enter_syscall(__NR_write, 1 /* stdout */,
			"\x1b[32msyscall hook: open system call\n\x1b[39m", 41);
		break;
	case __NR_close:
		enter_syscall(__NR_write, 1 /* stdout */,
			"\x1b[33msyscall hook: close system call\n\x1b[39m", 42);
		break;
	}
#endif
	if (a1 == __NR_clone) {
		if (a4 & CLONE_VM) { // pthread creation
			/* push return address to the stack */
			a3 -= sizeof(uint64_t);
			*((uint64_t *) a3) = retptr;
		}
	}

	/*
	 * here enters the kernel context by using
	 * the syscall instruction in enter_syscall.
	 *
	 * if you wish to emulate a system call,
	 * you can do it here instead of calling enter_syscall.
	 */
	ret = enter_syscall(a1, a2, a3, a4, a5, a6, a7);

	/* here, we can check the system call result stored in ret */

	return ret;
}

struct disassembly_state {
	char *code;
	size_t off;
};

/*
 * this actually rewrites the code.
 * this is called by the disassembler.
 */
static int fprintf_fn(void *data, const char *fmt, ...) {
	struct disassembly_state *s = (struct disassembly_state *) data;
	char buf[4096];
	va_list arg;
	va_start(arg, fmt);
	vsprintf(buf, fmt, arg);
	/* replace syscall and sysenter with callq *%rax */
	if (!strncmp(buf, "syscall", 7) || !strncmp(buf, "sysenter", 8)) {
		uint8_t *ptr = (uint8_t *)(((uintptr_t) s->code) + s->off);
		if ((uintptr_t) ptr == (uintptr_t) syscall_addr) {
			/*
			 * skip the syscall replacement for
			 * our system call hook (enter_syscall)
			 * so that it can issue system calls.
			 */
			goto skip;
		}
		ptr[0] = 0xff; // callq
		ptr[1] = 0xd0; // *%rax
	}
skip:
	va_end(arg);
	return 0;
}

/* find syscall and sysenter using the disassembler, and rewrite them */
static void disassemble_and_rewrite(char *code, size_t code_size, int mem_prot)
{
	struct disassembly_state s = { 0 };
	/* add PROT_WRITE to rewrite the code */
	assert(!mprotect(code, code_size, PROT_WRITE | PROT_READ | PROT_EXEC));
	disassemble_info disasm_info = { 0 };
	init_disassemble_info(&disasm_info, &s, fprintf_fn);
	disasm_info.arch = bfd_arch_i386;
	disasm_info.mach = bfd_mach_x86_64;
	disasm_info.buffer = (bfd_byte *) code;
	disasm_info.buffer_length = code_size;
	disassemble_init_for_target(&disasm_info);
	disassembler_ftype disasm;
	disasm = disassembler(bfd_arch_i386, false, bfd_mach_x86_64, NULL);
	s.code = code;
	while (s.off < code_size)
		s.off += disasm(s.off, &disasm_info);
	/* restore the memory protection */
	assert(!mprotect(code, code_size, mem_prot));
}

/* entry point for binary rewriting */
static void rewrite_code(void)
{
	FILE *fp;
	char buf[4096];

	/* get memory mapping information from procfs */
	assert((fp = fopen("/proc/self/maps", "r")) != NULL);

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char addr[65];
		int i = 0;
		size_t j;
		char *c;

		/* we do not touch stack and vsyscall memory */
		if (strstr(buf, "stack") != NULL || strstr(buf, "vsyscall") != NULL)
			continue;

		c = strtok(buf, " ");

		while (c != NULL) {
			switch (i) {
			case 0:
				strncpy(addr, c, sizeof(addr) - 1);
				break;
			case 1:
				{
					int mem_prot = 0;
					for (j = 0; j < strlen(c); j++) {
						if (c[j] == 'r')
							mem_prot |= PROT_READ;
						if (c[j] == 'w')
							mem_prot |= PROT_WRITE;
						if (c[j] == 'x')
							mem_prot |= PROT_EXEC;
					}
					/* rewrite code if the memory is executable */
					if (mem_prot & PROT_EXEC) {
						size_t k;
						int64_t from, to;
						for (k = 0; k < strlen(addr); k++) {
							if (addr[k] == '-') {
								addr[k] = '\0';
								break;
							}
						}
						from = strtol(&addr[0], NULL, 16);
						if (from == 0) {
							/*
							 * this is trampoline code.
							 * so skip it.
							 */
							break;
						}
						to = strtol(&addr[k+1], NULL, 16);
						disassemble_and_rewrite((char *) from,
								(size_t) to - from,
								mem_prot);
						break;
					}
				}
				break;
			}
			if (i == 1)
				break;
			c = strtok(NULL, " ");
			i++;
		}
	}

	fclose(fp);
}

void ____asm_syscall_hook(void)
{
	/*
	 * asm_syscall_hook is the address where the
	 * trampoline code first jumps to.
	 *
	 * the procedure below calls the C function
	 * namded syscall_hook.
	 *
	 * at the entry point of this,
	 * the register values follow the calling convention
	 * of the system calls. the following  transforms
	 * to the calling convention of the C functions.
	 *
	 * we do this just for writing the hook in C.
	 * so, this part would not be performance optimal.
	 *
	 */
	asm volatile (
	".globl asm_syscall_hook \n\t"
	"asm_syscall_hook: \n\t"
	"popq %rax \n\t" /* restore %rax saved in the trampoline code */
	"cmpq $15, %rax \n\t" // rt_sigreturn
	"je do_rt_sigreturn \n\t"
	"movq (%rsp), %rcx \n\t"
	"subq $16,%rsp \n\t"
	"movq %rcx,8(%rsp) \n\t"
	"movq %r9,(%rsp) \n\t"
	"movq %r8, %r9 \n\t"
	"movq %r10, %r8 \n\t"
	"movq %rdx, %rcx \n\t"
	"movq %rsi, %rdx \n\t"
	"movq %rdi, %rsi \n\t"
	"movq %rax, %rdi \n\t"
	"call syscall_hook \n\t"
	"addq $16,%rsp \n\t"
	"retq \n\t"
	"do_rt_sigreturn:"
	"addq $8, %rsp \n\t"
	"jmp syscall_addr \n\t"
	);
}

#define NR_syscalls (512) // bigger than max syscall number

static void setup_trampoline(void)
{
	void *mem;

	/* allocate memory at virtual address 0 */
	mem = mmap(0 /* virtual address 0 */, 0x1000,
			PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
			-1, 0);
	if (mem == MAP_FAILED) {
		printf("map failed\n");
		printf("NOTE: /proc/sys/vm/mmap_min_addr should be set 0\n");
		exit(1);
	}

	/* fill with nop 0x90 */
	memset(mem, 0x90, NR_syscalls);

	/* 
	 * put code for jumping to asm_syscall_hook.
	 *
	 * here we embed the following code which jumps
	 * to the address written on 0xff8
	 *
	 * push   %rax
	 * mov    $0xff8,%rax
	 * jmpq   *(%rax)
	 *
	 */

	/*
	 * save %rax on stack before overwriting
	 * with "mov $0xff8,%rax",
	 * and the saved value is resumed in asm_syscall_hook.
	 */
	// 50                      push   %rax
	((uint8_t *) mem)[NR_syscalls + 0] = 0x50;

	// 48 c7 c0 f8 0f 00 00    mov    $0xff8,%rax
	((uint8_t *) mem)[NR_syscalls + 1] = 0x48;
	((uint8_t *) mem)[NR_syscalls + 2] = 0xc7;
	((uint8_t *) mem)[NR_syscalls + 3] = 0xc0;
	((uint8_t *) mem)[NR_syscalls + 4] = 0xf8;
	((uint8_t *) mem)[NR_syscalls + 5] = 0x0f;
	((uint8_t *) mem)[NR_syscalls + 6] = 0x00;
	((uint8_t *) mem)[NR_syscalls + 7] = 0x00;

	// ff 20                   jmpq   *(%rax)
	((uint8_t *) mem)[NR_syscalls + 8] = 0xff;
	((uint8_t *) mem)[NR_syscalls + 9] = 0x20;

	/* finally, this sets the address of asm_syscall_hook at 0xff8 */
	*(uint64_t *)(&((uint8_t *) mem)[0xff8]) = (uint64_t) asm_syscall_hook;
}

__attribute__((constructor(0xffff))) static void __zpoline_init(void)
{
	printf("Initializing Zpoline ...\n");

	printf("-- Setting up trampoline code\n"); fflush(stdout);
	setup_trampoline();

	printf("-- Rewriting the code\n"); fflush(stdout);
	rewrite_code();

	printf("Zpoline initialization OK\n");
	printf("Start main program\n");
}
