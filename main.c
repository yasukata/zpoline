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
#include <dlfcn.h>

#define SUPPLEMENTAL__REWRITTEN_ADDR_CHECK 1

#ifdef SUPPLEMENTAL__REWRITTEN_ADDR_CHECK

/*
 * SUPPLEMENTAL: rewritten address check
 *
 * NOTE: this ifdef section is supplemental.
 *       if you wish to quicly know the core
 *       mechanism of zpoline, please skip here.
 *
 * the objective of this part is to terminate
 * a null pointer function call.
 *
 * an example is shown below.
 * --
 * void (*null_fn)(void) = NULL;
 *
 * int main(void) {
 *   null_fn();
 *   return 0;
 * }
 * --
 *
 * usually, the code above will cause a segmentation
 * fault because no memory is mapped to address 0 (NULL).
 *
 * however, zpoline maps memory to address 0. therefore, the
 * code above continues to run without causing the fault.
 *
 * this behavior is unusual, thus, we wish to avoid this.
 *
 * our approach here is:
 *
 *   1. during the binrary rewriting phase, record
 *      the addresses of the rewritten syscall/sysenter
 *      instructions (record_replaced_instruction_addr).
 *
 *   2. in the hook function, we check wheter the caller's
 *      address is the one that we conducted the rewriting
 *      or not (is_replaced_instruction_addr).
 *
 *      if not, it means that the program reaches the hook
 *      funtion without going through our replaced callq *%rax.
 *      this typically occurs the program was like the example
 *      code above. after we detect this type of irregular hook
 *      entry, we terminate the program.
 *
 * the costs of this mechanism are:
 *   - 1GB of memory to maintain a bitmap to cover entire
 *     64-bit address space (replaced_instruction_addr_bitmap).
 *   - bitmap operation at every hook entry, that includes
 *     a small number of bit operations (is_replaced_instruction_addr).
 */

static void bitmap_set(char bm[], unsigned int val)
{
	bm[val >> 3] |= (1 << (val & 7));
}

static bool is_bitmap_set(char bm[], unsigned int val)
{
	return (bm[val >> 3] & (1 << (val & 7)) ? true : false);
}

/*
 * we divide the 64-bit address range to two of 32-bit ranges
 * so that we can save the required memory for the bitmap.
 */
struct addr64_bitmap { // 1GB in total
	char h[0x20000000]; // for high 32-bit
	char l[0x20000000]; // for low  32-bit
};

static struct addr64_bitmap replaced_instruction_addr_bitmap = { 0 };

static void record_replaced_instruction_addr(uintptr_t addr)
{
	bitmap_set(replaced_instruction_addr_bitmap.h, addr >> 32);
	bitmap_set(replaced_instruction_addr_bitmap.l, addr & 0xffffffff);
}

static bool is_replaced_instruction_addr(uintptr_t addr)
{
	return (is_bitmap_set(replaced_instruction_addr_bitmap.h, addr >> 32)
		&& is_bitmap_set(replaced_instruction_addr_bitmap.l, addr & 0xffffffff)
			? true : false);
}

#endif

static long (*hook_fn)(int64_t a1, int64_t a2, int64_t a3,
		       int64_t a4, int64_t a5, int64_t a6,
		       int64_t a7) = NULL;

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

long syscall_hook(int64_t rdi, int64_t rsi,
		  int64_t rdx, int64_t __rcx __attribute__((unused)),
		  int64_t r8, int64_t r9,
		  int64_t r10_on_stack /* 4th arg for syscall */,
		  int64_t rax_on_stack,
		  int64_t retptr)
{
#ifdef SUPPLEMENTAL__REWRITTEN_ADDR_CHECK
	/*
	 * retptr is the caller's address, namely.
	 * "supposedly", it should be callq *%rax that we replaced.
	 */
	if (!is_replaced_instruction_addr(retptr - 2 /* 2 is the size of syscall/sysenter */)) {
		/*
		 * here, we detected that the program comes here
		 * without going through our replaced callq *%rax.
		 *
		 * this can should a bug of the program.
		 *
		 * therefore, we stop the program by int3.
		 */
		asm volatile ("int3");
	}
#endif

	if (rax_on_stack == __NR_clone) {
		if (rdi & CLONE_VM) { // pthread creation
			/* push return address to the stack */
			rsi -= sizeof(uint64_t);
			*((uint64_t *) rsi) = retptr;
		}
	}

	/* enter_syscall is used while hook_fn is not ready */

	if (hook_fn)
		return hook_fn(rax_on_stack, rdi, rsi, rdx, r10_on_stack, r8, r9);
	else
		return enter_syscall(rax_on_stack, rdi, rsi, rdx, r10_on_stack, r8, r9);
}

struct disassembly_state {
	char *code;
	size_t off;
};

/*
 * this actually rewrites the code.
 * this is called by the disassembler.
 */
static int do_rewrite(void *data, const char *fmt, ...) {
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
#ifdef SUPPLEMENTAL__REWRITTEN_ADDR_CHECK
		record_replaced_instruction_addr((uintptr_t) ptr);
#endif
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
	init_disassemble_info(&disasm_info, &s, do_rewrite);
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
	 * trampoline code first lands.
	 *
	 * the procedure below calls the C function
	 * named syscall_hook.
	 *
	 * at the entry point of this,
	 * the register values follow the calling convention
	 * of the system calls.
	 *
	 * this part is a bit complicated.
	 * commit e5afaba has a bit simpler versoin.
	 *
	 */
	asm volatile (
	".globl asm_syscall_hook \n\t"
	"asm_syscall_hook: \n\t"
	"popq %rax \n\t" /* restore %rax saved in the trampoline code */
	"cmpq $15, %rax \n\t" // rt_sigreturn
	"je do_rt_sigreturn \n\t"
	"pushq %rbp \n\t"
	"movq %rsp, %rbp \n\t"

	/*
	 * NOTE: for xmm register operations such as movaps
	 * stack is expected to be aligned to a 16 byte boundary.
	 */

	"andq $-16, %rsp \n\t" // 16 byte stack alignment

	/* assuming callee preserves r12-r15 and rbx  */

	"pushq %r11 \n\t"
	"pushq %r9 \n\t"
	"pushq %r8 \n\t"
	"pushq %rdi \n\t"
	"pushq %rsi \n\t"
	"pushq %rdx \n\t"
	"pushq %rcx \n\t"

	/* arguments for syscall_hook */

	"pushq 8(%rbp) \n\t"	// return address
	"pushq %rax \n\t"
	"pushq %r10 \n\t"

	/* up to here, stack has to be 16 byte aligned */

	"callq syscall_hook \n\t"

	"popq %r10 \n\t"
	"addq $16, %rsp \n\t"	// discard arg7 and arg8

	"popq %rcx \n\t"
	"popq %rdx \n\t"
	"popq %rsi \n\t"
	"popq %rdi \n\t"
	"popq %r8 \n\t"
	"popq %r9 \n\t"
	"popq %r11 \n\t"

	"leaveq \n\t"

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

	assert(!mprotect(0, 0x1000, PROT_READ | PROT_EXEC));
}

static void load_hook_lib(void)
{
	void *handle;
	int (*hook_init)(void);
	const char *filename;

	filename = getenv("LIBZPHOOK");
	if (!filename) {
		printf("-- env LIBZPHOOK is empty, so skip to load a hook library\n");
		return;
	}

	printf("-- load %s\n", filename);

	handle = dlmopen(LM_ID_NEWLM, filename, RTLD_NOW | RTLD_LOCAL);
	if (!handle) {
		printf("\n");
		printf("dlmopen failed: %s\n", dlerror());
		printf("\n");
		printf("NOTE: this may occur when the compilation of your hook function library misses some specifications in LDFLAGS. or if you are using a C++ compiler, dlmopen may fail to find a symbol, and adding 'extern \"C\"' to the definition may resolve the issue.\n");
		exit(1);
	}

	hook_init = dlsym(handle, "__hook_init");
	assert(hook_init);
	printf("-- call hook init\n");
	assert(hook_init() == 0);

	printf("-- set hook function\n");
	hook_fn = dlsym(handle, "__hook_fn");
	assert(hook_fn);
}

__attribute__((constructor(0xffff))) static void __zpoline_init(void)
{
	printf("Initializing zpoline ...\n");

	printf("-- Setting up trampoline code\n"); fflush(stdout);
	setup_trampoline();

	printf("-- Rewriting the code\n"); fflush(stdout);
	rewrite_code();

	printf("Loading hook library ...\n"); fflush(stdout);
	load_hook_lib();

	printf("Start main program\n");
}
