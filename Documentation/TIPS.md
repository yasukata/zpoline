# Tips

## Tracing system calls executed in JIT code

authored by [@retrage](https://github.com/retrage)

zpoline hooks system calls by binary-rewriting instructions in the executable region before the main function starts.
However, this doesn't work for JIT-generated code.

To hook system calls in JIT code:

1. Hook the `mprotect` syscall when it's setting a region as executable.
2. Before calling `mprotect`, scan the region for syscall instructions.
3. Perform binary-rewriting on any found syscall instructions.
4. Then allow `mprotect` to proceed.

This method leverages how JIT compilers typically generate code in a read-write region, then use `mprotect` to make it executable.
By applying binary-rewriting at this stage, zpoline can hook system calls in both static and JIT-generated code.

To try this, please replace `zpoline/apps/basic/main.c` with the following code.

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <syscall.h>
#include <sys/mman.h>
#include <dis-asm.h>

typedef long (*syscall_fn_t)(long, long, long, long, long, long, long);

static syscall_fn_t next_sys_call = NULL;

static char *bm_mem = NULL;

static void bitmap_set(char bm[], unsigned long val)
{
    bm[val >> 3] |= (1 << (val & 7));
}

static void record_replaced_instruction_addr(uintptr_t addr)
{
    assert(addr < (1UL << 48));
    bitmap_set(bm_mem, addr);
}

struct disassembly_state {
    char *code;
    size_t off;
};

#if defined(DIS_ASM_VER_239)
static int do_rewrite(void *data, enum disassembler_style style ATTRIBUTE_UNUSED, const char *fmt, ...)
#else
static int do_rewrite(void *data, const char *fmt, ...)
#endif
{
    struct disassembly_state *s = (struct disassembly_state *) data;
    char buf[4096];
    va_list arg;
    va_start(arg, fmt);
    vsprintf(buf, fmt, arg);
    if (strstr(buf, "(%rsp)") && !strncmp(buf, "-", 1)) {
        int32_t off;
        sscanf(buf, "%x(%%rsp)", &off);
        if (-0x78 > off && off >= -0x80) {
            printf("\x1b[41mthis cannot be handled: %s\x1b[39m\n", buf);
            assert(0);
        } else if (off < -0x80) {
            /* this is skipped */
        } else {
            off &= 0xff;
            {
                uint8_t *ptr = (uint8_t *)(((uintptr_t) s->code) + s->off);
                {
                    int i;
                    for (i = 0; i < 16; i++) {
                        if (ptr[i] == 0x24 && ptr[i + 1] == off) {
                            ptr[i + 1] -= 8;
                            break;
                        }
                    }
                }
            }
        }
    } else
    if (!strncmp(buf, "syscall", 7) || !strncmp(buf, "sysenter", 8)) {
        uint8_t *ptr = (uint8_t *)(((uintptr_t) s->code) + s->off);
        ptr[0] = 0xff; // callq
        ptr[1] = 0xd0; // *%rax
#ifdef SUPPLEMENTAL__REWRITTEN_ADDR_CHECK
        record_replaced_instruction_addr((uintptr_t) ptr);
#endif
    }
    va_end(arg);
    return 0;
}

/* find syscall and sysenter using the disassembler, and rewrite them */
static void disassemble_and_rewrite(char *code, size_t code_size, int mem_prot)
{
    struct disassembly_state s = { 0 };
    assert(!mprotect(code, code_size, PROT_WRITE | PROT_READ | PROT_EXEC));
    disassemble_info disasm_info = { 0 };
#if defined(DIS_ASM_VER_239)
    init_disassemble_info(&disasm_info, &s, (fprintf_ftype) printf, do_rewrite);
#else
    init_disassemble_info(&disasm_info, &s, do_rewrite);
#endif
    disasm_info.arch = bfd_arch_i386;
    disasm_info.mach = bfd_mach_x86_64;
    disasm_info.buffer = (bfd_byte *) code;
    disasm_info.buffer_length = code_size;
    disassemble_init_for_target(&disasm_info);
    disassembler_ftype disasm;
#if defined(DIS_ASM_VER_229) || defined(DIS_ASM_VER_239)
    disasm = disassembler(bfd_arch_i386, false, bfd_mach_x86_64, NULL);
#else
    bfd _bfd = { .arch_info = bfd_scan_arch("i386"), };
    assert(_bfd.arch_info);
    disasm = disassembler(&_bfd);
#endif
    s.code = code;
    while (s.off < code_size)
        s.off += disasm(s.off, &disasm_info);
    assert(!mprotect(code, code_size, mem_prot));
}

static long hook_function(long a1, long a2, long a3,
              long a4, long a5, long a6,
              long a7)
{
    if (a1 == __NR_mprotect && (a4 & PROT_EXEC)) {
        disassemble_and_rewrite((char *) a2, (size_t) a3, (int) a4);
        return 0;
    }
    return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

int __hook_init(long placeholder __attribute__((unused)),
        void *sys_call_hook_ptr
#ifdef SUPPLEMENTAL__REWRITTEN_ADDR_CHECK
        ,
        void *bm_ptr
#endif
        )
{
#ifdef SUPPLEMENTAL__REWRITTEN_ADDR_CHECK
    bm_mem = bm_ptr;
#endif
    next_sys_call = *((syscall_fn_t *) sys_call_hook_ptr);
    *((syscall_fn_t *) sys_call_hook_ptr) = hook_function;
    return 0;
}
```

Please replace the content of `zpoline/apps/basic/Makefile` with the following code.

```Makefile
PROGS = libzphook_basic.so

CC = gcc

CLEANFILES = $(PROGS) *.o *.d

SRCDIR ?= ./

NO_MAN=
CFLAGS = -O3 -pipe
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -Wextra
CFLAGS += -shared -fPIC
CFLAGS += -DSUPPLEMENTAL__REWRITTEN_ADDR_CHECK

LD_VERSION = $(shell ld --version | head -1 | grep -oP '[\d\.]+' | sed 's/\.//' | sed 's/\..*//' | head -1 )
# differentiate the code according to the library version
ifeq ($(shell test $(LD_VERSION) -ge 239; echo $$?),0)
  CFLAGS += -DDIS_ASM_VER_239
else ifeq ($(shell test $(LD_VERSION) -ge 229; echo $$?),0)
  CFLAGS += -DDIS_ASM_VER_229
endif

LDFLAGS += -lopcodes

C_SRCS = main.c
OBJS = $(C_SRCS:.c=.o)

.PHONY: all
all: $(PROGS)

$(PROGS): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)
```

Use the following sample code `jit.c` to test the JIT code.

```c
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

// This is a simple application that runs a syscall from JIT code.

void dump(const void *data, size_t size) {
    const unsigned char *p = data;
    size_t i = 0;

    for (i = 0; i < size; i++) {
        printf("%02x ", p[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }

    printf("\n");
}

int main() {
    printf("[*] Running JIT code\n");

    const size_t size = 4096;

    void *code = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    printf("[*] Allocated memory at %p\n", code);

    unsigned char shellcode[] = {
        0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, // mov rax, 0x3c (syscall number for exit)
        0x48, 0x31, 0xff, // xor rdi, rdi
        0x0f, 0x05, // syscall
        0xc3 // ret
    };

    printf("[*] Writing shellcode to memory\n");

    memcpy(code, shellcode, sizeof(shellcode));

    printf("[*] Shellcode:\n");
    dump(code, sizeof(shellcode));

    mprotect(code, size, PROT_READ | PROT_EXEC);

    printf("[*] Shellcode:\n");
    dump(code, sizeof(shellcode));

    ((void (*)())code)();

    return 0;
}
```

Build the sample code and run it.

```sh
gcc -o jit jit.c
make -C apps/basic
make
LIBZPHOOK=./apps/basic/libzphook_basic.so LD_PRELOAD=./libzpoline.so ./jit
```

You should see the following output.

```
[*] Running JIT code
[*] Allocated memory at 0x79369f10e000
[*] Writing shellcode to memory
[*] Shellcode:
48 c7 c0 3c 00 00 00 48 31 ff 0f 05 c3
[*] Shellcode:
48 c7 c0 3c 00 00 00 48 31 ff ff d0 c3
```

As you can see, the `syscall` instruction in the JIT code has been replaced with a `callq *%rax` instruction.
