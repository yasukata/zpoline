# Supplemental documentation

## Use of dlmopen (November 2021)

Users of the zpoline technique should pay attention to the use of rewritten functions, otherwise, the system call hook may fall into an infinite loop.

Let's think about the printf library call which internally invokes a write system call.
When zpoline is applied to the user-space program, the write system call triggered in printf will be hooked by zpoline.
The problem occurs when the system call hook calls printf.
It will result in an infinite loop because the write system call in printf, called by the hook function, will be hooked and redirected to the same hook function.

But, in this example, the hook function can use printf.

This is realized by dlmopen. In ```libzpoline.so```, a function named ```load_hook_lib``` calls dlmopen and loads ```apps/basic/libzphook_basic.so```. In particular, ```load_hook_lib``` specifies ```LM_ID_NEWLM``` for dlmopen, and this requests to load ```apps/basic/libzphook_basic.so``` in a new namespace. At the same time, dlmopen also loads other required libraries including libc in the same namespace to which ```apps/basic/libzphook_basic.so``` belongs.

Now, libc for ```apps/basic/libzphook_basic.so``` is newly instantiated in the new namespace, and it is different from the one used by the primary user-space program. Here, ```libzpoline.so``` does not replace syscall and sysenter instructions in the newly instantiated libc. Therefore, the functions implemented in ```apps/basic/libzphook_basic.so``` does not cause an infinite loop.

Note that dlmopen does not only load libc but also other shared libraries associated with the hook function library. The association is done by the compiler. If you forget to specify the library to link (e.g., ```-lpthread``` for libpthread, ```-lm``` for libmath) for the compiler, dlmopen may fail to load them.

## Coping with NULL pointer exceptions (April 2022)

Since zpoline uses address 0, that is normally considered NULL, by default, some NULL pointer errors do not cause a segmentation fault. The current version implements metigations for this issue.

Mainly, we think about three cases, write to NULL, read from NULL, and execute the program at NULL.

### 1. Write to NULL

We wish to cause a segmentation fault when running the following exmaple program.

```c
#include <stdio.h>
#include <string.h>

int main(int argc, char const* argv[])
{
	printf("write 0x90 to NULL\n");

	printf("if memory is properly configured, this causes segfault\n");

	memset(NULL, 0x90, 1);

	printf("memory is not configured!\n");

	return 0;
}
```

The solution for this case is simple. We just use the mprotect system call without specifying PROT_WRITE.

### 2. Read from NULL

The next case is read access to NULL, and the example is shown below.


```c
#include <stdio.h>
#include <string.h>

int main(int argc, char const* argv[])
{
	char c;

	printf("read 1 byte from NULL\n");

	printf("if XOM is properly configured, this causes segfault\n");

	memcpy(&c, NULL, sizeof(c));

	printf("XOM is not configured!\n");

	printf("addr NULL has value : 0x%02x\n", c & 0xff);

	return 0;
}
```

Our solution is using eXecute-Only Memory (XOM). On Linux, when the CPU supports Intel PKU, the mprotect system call, that only specifies PROT_EXEC (meaning PROT_WRITE and PROT_READ are not specified), will configure the specified region as XOM.

So, in summary, in zpoline, the protection aginst NULL read/write can be done by

```
mprotect(NULL, trampoline_code_size, PROT_EXEC);
```

### 3. Execute NULL (Unintentionally)

We wish to trap unintended jump/call to the trampoline code at NULL. The example is below.

```c
#include <stdio.h>

static void (*dummy_function)(long, long, long) = NULL;

int main(int argc, char const* argv[])
{
	printf("call function at NULL\n");

	printf("normally, this causes segfault\n");

	dummy_function(0, 0, 0); // this will be read(0, NULL, 0) for default zpoline

	printf("NULL function is executed\n");

	return 0;
}
```

In zpoline, the address 0 (NULL) has the trampoline code, therefore, we cannot remove the executable flag from it.

What we wish to do here is, to allow only our replaced ```callq *%rax``` to go through the trampoline code, and never allow for the other cases.

Our solution is to
- keep addresses of ```callq *%rax``` that we replaced in the rewriting phase.
- check, at the entry point of the hook function, if the caller comes from our ```callq *%rax```.

This implementation contains this check mechanism in the ifdef section named ```SUPPLEMENTAL__REWRITTEN_ADDR_CHECK```.

## USENIX ATC 2023 reviews Q&A (May 2023)

### How does zpoline compare to DBI tools such as Intel PIN?

We have run an experiment to see the hook overhead of Intel Pin System Call API, whose pointer is provided in the review.

We used pin-3.27-98718-gbeaa5d51e-gcc-linux and implement a simple system call hook program, whose hook function just returns without doing anything, and the hook function is registered with the PIN_AddSyscallEntryFunction API.

We apply this hook program for the getpid benchmark program used in Section 3.2 and we observed 2703 ns for each getpid system call invocation; this number includes the time for the kernel-space getpid system call execution, which is 74 ns on our hardware, therefore, we see the hook overhead of Intel PIN is 2629 ns.

We found that, compared to the overhead of zpoline (41 ns shown in Table 1), Intel PIN's overhead is substantially higher.

### Can the suggestion proposed by anonymous reviwer C reduce the nop overhead?

Context: for reducing the nop overhead in the trampoline code, anonymous reviewer C had proposed to employ the virtual addresses corresponding to deprecated system calls such as epoll_ctl_old and epoll_wait_old for putting short jump rather than nop.

For the experimentation, we have added the following lines in setup_trampoline() to embed a short jump at address 214 (NR_epoll_ctl_old) and 215 (NR_epoll_wait_old); thanks to this approach, we could skip 127 nops (the range of a short jump is -128 to +127 according to the CPU implementation).

```c
        ((uint8_t *) mem)[NR_syscalls + 0xb] = 0xff;
        ((uint8_t *) mem)[NR_syscalls + 0xc] = 0xe0;
 
+       // optimization introduced by reviewer C
+       ((uint8_t *) mem)[214 /* __NR_epoll_ctl_old */] = 0xeb; /* short jmp */
+       ((uint8_t *) mem)[215 /* __NR_epoll_wait_old */] = 127; /* range of a short jmp : -128 ~ +127 */
+
        /*
         * mprotect(PROT_EXEC without PROT_READ), executed
```

We run the same experiment done in Section 3.2 for Table 1, and observed 31 ns as the result; this means the proposed approach reduces the overhead by 24% compared to our zpoline result 41 ns.

***We would like to thank anonymous reviewer C for bringing up this idea.***

### What are the average numbers of nops executed in the benchmarks?

For the implementation used in the experiments, we have statically set the number of nops as 512.

Therefore, in the getpid experiment in Section 3.2, each hook invocation runs through 473 nops (syscall number of getpid is 39; 512 - 39 = 473); since we only run getpid, 473 is the average.

For Section 3.3, we have checked which system calls are triggered in the primary loops of the simple HTTP server and Redis server.

For the benchmarks in Section 3.3, we counted the number of system calls executed in 1 second during the simple HTTP server and Redis server benchmark workload; the following is the results.

(from left, syscall number, name of the syscall, and the number of invocation in 1 second)

Simple HTTP server
- 0   read       : 1185497
- 1   write      : 1185497
- 232 epoll_wait : 1185497

=> ((512 - 0) * 1185497 + (512 - 1) * 1185497 + (512 - 232) * 1185497) / (1185497 + 1185497 + 1185497) = 434; 434 nops is the average in the simple HTTP server case.

Redis
- 0   read       : 665983
- 1   write      : 665973
- 3   close      : 10
- 232 epoll_wait : 665997
- 257 openat     : 10

=> ((512 - 0) * 665983 + (512 - 1) * 665973 + (512 - 3) * 10 + (512 - 232) * 665997 + (512 - 257) * 10) / (665983 + 665973 + 10 + 665997 + 10) = 434; 434 nops is the average for the Redis server case as well.

### How many pages are modified by binary rewriting?

A system can save physical memory consumption by sharing the memory pages, having the code of a user-space program, among different user-space processes that may execute the same code block; however, the pages having rewritten code cannot be shared.

To see how our binary rewriting approach reduces the shareable pages, we counted the number of modified pages for the code of libc that is the primary residence of syscall/sysenter; we found glibc-2.35, loaded on the memory, has 544 syscall/sysenter instructions which are put across 62 of 4~KB pages.

We think this number is acceptable particularly on modern servers typically installing tens or hundreds of gigabytes of DRAM.

## Reducing nop overhead by 0xeb 0x6a 0x90 (May 2023)

For reducing the cost to slide down the nops in the trampoline code, [anonymous reviewer C at USENIX ATC 2023](#can-the-suggestion-proposed-by-anonymous-reviwer-c-reduce-the-nop-overhead) proposed to employ the virtual addresses corresponding to deprecated system calls to embed short jump rather than nop and anonymous reviewer D suggested to instrument the program to make a list of system calls used in the program and put jump instructions at the virtual addresses corresponding to non-used system calls.

This suggestion gave us the inspiration for the enhancement leveraging the short jump instruction; again, we appreciate anonymous reviewer C and D for their suggestions.

After a bit of investigation, we came up with an idea to use 0xeb 0x6a 0x90, rather than full of nops, for sliding down the top part of the trampoline code.

The complicated part is that x86 CPUs consider the instruction starts at the address that the execution jumps to, and the replaced code (```callq *%rax```) can jump to any address between 0 and the maximum system call number; our previous solution was to fill this range with the single-byte nop instruction (0x90), however, it is costly to run through the nops.

The optimization fills the address range from 0 to THE_MAX_SYSCALL_NUMBER - 0x6a (106) - 2 with 0xeb 0x6a 0x90, and the range between THE_MAX_SYSCALL_NUMBER - 0x6a (106) - 1 to THE_MAX_SYSCALL_NUMBER is still filled with nops; the content of the trampoline code will be as follows.
```
 ----------  virtual address ---------- : -- value --
0                                       :    0xeb
1                                       :    0x6a
2                                       :    0x90
                  ...                   : repeat 0xeb 0x6a 0x90
THE_MAX_SYSCALL_NUMBER - 0x6a (106) - 1 :    0x90 (nop)
THE_MAX_SYSCALL_NUMBER - 0x6a (106) - 0 :    0x90 (nop)
                  ...                   : repeat 0x90 (nop)
THE_MAX_SYSCALL_NUMBER                  :    0x90 (nop)
```

The meaning of 0xeb 0x6a 0x90 0xeb 0x6a ... depends on the address that the execution lands at by ```callq *%rax```, and there are three cases: the following shows how x86 CPUs consider the byte sequence in each case.

1. ```0xeb 0x6a``` : jmp 0x6a (the execution lands at n * 3 + 0)
2. ```0x6a 0x90``` : push 0x90 (the execution lands at n * 3 + 1)
3. ```0x90 0xeb 0x6a``` : nop, jmp 0x6a (the execution lands at n * 3 + 2)

Therefore, the trampoline code will be considered as follows.

case 1: land at n * 3 + 0

```asm
jmp 0x6a
nop
jmp 0x6a
nop
...
```

case 2: land at n * 3 + 1

```asm
push 0x90
jmp 0x6a
nop
jmp 0x6a
nop
...
```

case 3: land at n * 3 + 2

```asm
nop
jmp 0x6a
nop
jmp 0x6a
...
```

The thing we need to care about is that case 2 pushes the value 0x90 to the stack; to cope with this, we check the address, we landed at, and discard 0x90 on the stack when we find we come from n * 3 + 1 (case 2).

After we apply this optimization, we run the same experiment done in Section 3.2 for Table 1 of the paper; as a result, we observed 10 ns as the hook overhead and this is 4 times faster than the previous version shown in the paper (41 ns is reported as the hook overhead).
