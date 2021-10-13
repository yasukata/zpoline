# Zpoline: hooking system calls without pain

Zpoline is a novel system call hook mechanism that offers the following advantages.
- 100 times faster than ptrace.
- 100% coverage, namely, it can exhaustively hook system calls.
- No need for the source code of user-space programs.
- No need for the change to the OS kernel and no kernel module is necessary.

Therefore, Zpoline is a quite good option if you think...
- ptrace is too slow for your project.
- the LD_PRELOAD trick is not enough because it cannot exhaustively hook system calls.
- you cannot anticipate the availability of the source code of your hook target.
- you do not want to modify the OS kernel or install a kernel module.


Zpoline is categorized into binary rewriting, but you do not need to worry that your program binary files are overwritten. The setup procedure of Zpoline rewrites the code binary *loaded on the memory*, just before the user-space program starts its main function. Therefore, it does not overwrite your program binary files.

The cool part of Zpoline is that it does not fail to hook system calls, which is difficult for existing binary rewriting techniques.

The key ideas of Zpoline are to exploit the calling convention and instantiate a special trampoline code.
The overview is shown in the picture below.

<img src="Documentation/img/zpoline.png" width="500px">

In a nutshell, Zpoline replaces the ```syscall``` and ```sysenter``` instructions with ```callq *%rax```, and crafts a tram**poline** code at virtual address 0 (**Z**ero). That is why this technique is named Zpoline.

For more technical details, please check [Documentation/README.md](Documentation/README.md).

## Target Platform

Currently, this implementation assumes Linux on the x86-64 architecture.

## Dependency

Zpoline uses the disassembler in ```libopcodes``` that is part of binutils.

```
$ sudo apt install binutils-dev
```

## Build

Please simply type ```make``` in this directory, and it will generate a file named ```libzpoline.so```.

## Setup

To use Zpoline, please set 0 to ```/proc/sys/vm/mmap_min_addr```.

```
$ sudo sh -c "echo 0 > /proc/sys/vm/mmap_min_addr"
```

## How to Use

Please specify ```libzpoline.so``` for the ```LD_PRELOAD``` variable so that Zpoline's initialization procedure can perform binary rewriting before the main function of your program starts.

```
$ LD_PRELOAD=./libzpoline.so [program you wish to run]
```

The following is the example output.

```
$ LD_PRELOAD=./libzpoline.so ls
Initializing Zpoline ...
-- Setting up trampoline code
-- Rewriting the code
syscall hook: read system call
syscall hook: read system call
syscall hook: read system call
syscall hook: read system call
syscall hook: close system call
syscall hook: write system call
Zpoline initialization OK
syscall hook: write system call
Start main program
syscall hook: close system call
syscall hook: close system call
syscall hook: close system call
syscall hook: write system call
.  ..  .git  libzpoline.so  LICENSE  main.c  main.o  Makefile  _moge  README.md
syscall hook: close system call
```

The messages ```syscall hook: XXX system call``` are printed by the Zpoline-based system call hook.

## How to Develop A Zpoline-based System Call Hook

In this repository, the function named ```syscall_hook``` in ```main.c``` is the system call hook.
So, it is the part that you should change for implementing your own hook function.

Firstable, if you remove the line ```#define DEMO 1``` or the corresponding ifdef part in ```main.c```,
you can eliminate the output of the demo.

### Note

Similar to other system call hook mechanisms such as the existing binary rewriting techniques and [Syscall User Dispatch](https://www.kernel.org/doc/html/latest/admin-guide/syscall-user-dispatch.html) (SUD),
users of the Zpoline technique should pay attention to the use of functions called by the primary user-space program, otherwise, the system call hook may cause a deadlock.

Let's say, we have a function named ```function_A``` which first acquires a lock, then invokes a system call, and finally releases the lock.
When a user-space program calls ```function_A```, the system call in it will be hooked by Zpoline.
The problem occurs when the system call hook also calls ```function_A```.
It will result in a deadlock because the lock is not released in the first call of ```function_A```.

Therefore, users of the Zpoline technique should assign dedicated in-memory assets to Zpoline-based system call hooks. For example, the demo program uses a self-implemented function ```enter_syscall``` rather than the ```syscall``` wrapper function in libc.

## Further Information

You may be able to have a better understanding by checking the comments in the source code and [Documentation/README.md](Documentation/README.md).
