# Technical Details of Zpoline

Zpoline is based on binary rewriting.
Technically, Zpoline resolves the longstanding problem in the binary rewriting techniques: replacing a small-size instruction with a bigger instruction.
This document describes the details of the problem and how Zpoline resolves it.

## Motivation

Zpoline is motivated by a fact that none of the existing system call hook mechanisms is perfect.

- ptrace is slow. [Syscall User Dispatch](https://www.kernel.org/doc/html/latest/admin-guide/syscall-user-dispatch.html) (SUD) is also not fast enough.
- the LD_PRELOAD trick cannot exhaustively hook system calls.
- the existing binary rewriting techniques cannot guarantee 100% coverage.
- system call hooks, relying on changes to the OS kernel or a tailor-made kernel module, lose portability.

## System Call on x86-64

System calls are the primary interface for user-space programs to communicate with the kernel.
On x86-64, user-space programs can trigger a system call using one of the ```syscall``` and ```sysenter``` CPU instructions.
When one of them is executed, the context is switched into the kernel, and a pre-configured system call handler will be executed.

### Calling Convention

To request the kernel to execute a particular system call, user-space programs follow a calling convention.
On Linux, a user-space program sets a pre-defined system call number (e.g., 0 is ```read```, 1 is ```write```, and 2 is ```open```) to the ```rax``` CPU register before triggering a system call.
In the kernel context, the system call handler executes one of the system calls according to the ```rax``` register value.

## Challenge

Since Zpoline is a binary rewriting approach, it encounters the common problem of binary rewriting: replacing a small-size instruction with a bigger instruction.
In opcode, both ```syscall``` and ```sysenter``` are two bytes, and represented by ```0x0f 0x05``` and ```0x0f 0x34``` respectively.
To implement a system call hook, we wish to replace them with one of the jump-relevant CPU instructions such as ```jmp``` and ```call```.
However, the problem is that the jump-related instructions usually occupy more than two bytes because they need to specify the jump destination address.
In short, two-byte is too small to locate ```jmp``` or ```call``` for jumping to a user-defined system call hook.

## Zpoline

Zpoline resolves the problem above by introducing a novel binary rewriting strategy and a special trampoline code.

The overview is shown in the picture below.

<img src="img/zpoline.png" width="500px">

### Binary Rewriting

The setup procedure of Zpoline performs binary rewriting to the code binary loaded onto the memory, just before the user-space program's main function starts.

In the rewriting phase, it traverses all executable memory regions in the user-space of the target process, and replaces the two bytes of ```syscall``` and ```sysenter``` instructions
with ```callq *%rax``` that is represented by two bytes ```0xff 0xd0``` in opcode.

What ```callq *%rax``` does is to push the current instruction pointer, namely the caller's address, to the stack, and jump to the address stored in ```%rax```.

The insight is that, according to the calling convention, ```%rax``` always has the system call number that is between 0 and several hundred.
Therefore, the consequence of ```callq *%rax``` is the jump to a virtual address between 0 and the maximum system call number.

The key idea is to prepare a tram**poline** code starting at the virtual address 0 (**Z**ero) for redirecting the execution to a user-defined system call hook, and it is the reason why this technique is named Zpoline.

### Trampoline Code

For instantiating a trampoline code, the setup procedure first allocates memory at the virtual address 0 by using the ```mmap``` system call.
(In Linux, by default, the memory mapping to the virtual address 0 is not allowed for non-root users, but it can be permitted for all non-root users by setting 0 to ```/proc/sys/vm/mmap_min_addr```.)

Then, it fills the address range between 0 and the maximum system call number with the single-byte ```nop``` instruction (```0x90``` in opcode).

Lastly, the setup procedure locates, next to the last ```nop``` instruction, a code to jump to a particular hook function.

### Execution Flow

After the setup procedure finishes the trampoline code setup and the binary rewriting, the main function of the user-space program will start.

During the execution of the user-space program, the rewritten part, ```callq *%rax```, will jump to one of the ```nop``` instructions in the trampoline while pushing the caller's address on the stack,
and  fall through the subsequent ```nop```s until it hits the code to jump to the hook function.

After the hook function finishes, it will execute the ```ret``` instruction, and it pops the caller's address saved on the stack and jumps back to the caller.

## Limitations

- Zpoline can be applied only for system calls whose calling convention guarantees a particular range of value is stored in one of the CPU registers (```%rax``` in Linux).
- Zpoline must be able to occupy the virtual address 0 and a few subsequent virtual memory pages for locating the trampoline code. I think this address range is not commonly used and the conflicts with other systems are rare.

## Performance

### Setup

- CPU: two 8-core Intel Xeon E5-2640 v3 CPUs clocked at 2.60GHz
- OS: Linux-5.11 ( Ubuntu 20.04 LTS )

### Benchmark 1: System Call Hook Overhead

The first benchmark quantifies the overhead of the system call hook by executing ```getpid``` that is one of the simplest system calls.
Zpoline is compared with ptrace and [Syscall User Dispatch](https://www.kernel.org/doc/html/latest/admin-guide/syscall-user-dispatch.html) (SUD). SUD is recently added to Linux and it redirects system calls to a user-space ```signal``` handler registered for the ```SIGSYS``` signal.
Each case implements an optimization that caches the pid value so that it can returun the cached value without executing the getpid system call.

The following table shows the measured CPU cycles consumed for a single getpid execution.

|Hook Mechanism|without pid cache|with pid cache|
|---|---|---|
|ptrace|17820|16403|
|SUD|5957|4563|
|Zpoline|1459|138|

The pure hook overhead is seen in the "with pid cache" case because it does not involve the overhead of the system call.
In this case, Zpoline's overhead is 118 times smaller than ptrace.

### Benchmark 2: Setup Time

Since Zpoline is initialized before the main function of a user-space program, its setup time delays the start-up of the user-space program.
This benchmark measures the setup time of Zpoline by running the ```ls``` command.

In this test, 7.9 us and 425.6 ms are spent on the trampoline code instantiation and binary rewriting respectively.
Compared to binary rewriting, the time for the trampoline code initialization is negligibly small.
Even though the binary rewriting procedure is a millisecond-scale task, I think 425.6 ms is quite acceptable.

For an in-depth analysis, the following table reports the breakdown of the binary rewriting time.

|Object | Memory Size (KiB) | Time (ms)|
|---|---|---|
| /usr/bin/ls | 80 | 15.1 |
| libpthread.so | 68 | 12.6 |
| libdl.so | 8 | 1.8 |
| libpcre2.so | 400 | 71.9 |
| libopcodes.so | 44 | 8.3 |
| libc.so | 1504 | 269.1 |
| libselinux.so | 100 | 18.6 |
| ld.so | 140 | 25.2 |
| Other | - | 3.0 |
| Total | - | 425.6 |

63% of the time is spent on libc which uses the biggest memory for locating its code binary.
The reported numbers indicate that it takes more time for binaries that occupy bigger memory.
This is because the setup procedure scans the memory having the code binary to find the ```syscall``` and ```sysenter``` instructions.
Although Zpoline's setup time is already acceptably low, I guess it can be further shortened by parallelizing the binary rewriting task.
