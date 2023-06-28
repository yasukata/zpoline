# zpoline: system call hook for Linux

zpoline is a novel system call hook mechanism that offers the following advantages.
- 100 times faster than ptrace.
- 100% coverage, namely, it can exhaustively hook system calls.
- No need for the source code of user-space programs.
- No need for the change to the OS kernel and no kernel module is necessary.

Therefore, zpoline is a quite good option if you think...
- ptrace is too slow for your project.
- the LD_PRELOAD trick is not enough because it cannot exhaustively hook system calls.
- you cannot anticipate the availability of the source code of your hook target.
- you do not want to modify the OS kernel or install a kernel module.

zpoline is categorized into binary rewriting, but you do not need to worry that your program binary files are overwritten. The setup procedure of zpoline rewrites the code binary *loaded on the memory*, just before the user-space program starts its main function. Therefore, it does not overwrite your program binary files.

The cool part of zpoline is that it does not fail to hook system calls, which is difficult for existing binary rewriting techniques.

The key ideas of zpoline are to exploit the calling convention and instantiate a special trampoline code.
The overview is shown in the picture below.

<img src="Documentation/img/zpoline.png" width="500px">

In a nutshell, zpoline replaces the ```syscall``` and ```sysenter``` instructions with ```callq *%rax```, and crafts a tram**poline** code at virtual address 0 (**z**ero); this is why this technique is named zpoline.

For more technical details, please check the [Further Information](#further-information) section.

## Target Platform

Currently, this implementation assumes Linux on the x86-64 architecture.

## Dependency

zpoline uses the disassembler in ```libopcodes``` that is part of binutils.

```
sudo apt install binutils-dev
```

## Files

This example uses two shared libraries.

1. ```apps/basic/libzphook_basic.so``` only implements the hook function. (we call the hook function library).
2. ```libzpoline.so``` is loaded by LD_PRELOAD. This configures the trampoline code, conducts binary rewriting, and loads ```./apps/basic/libzphook_basic.so``` using dlmopen.

## Build

To build ```apps/basic/libzphook_basic.so```, please type the following command.

```
make -C apps/basic
```

For ```libzpoline.so```, please type the following command.

```
make
```

## Setup

To use zpoline, please set 0 to ```/proc/sys/vm/mmap_min_addr```.

```
sudo sh -c "echo 0 > /proc/sys/vm/mmap_min_addr"
```

## How to Use

Pleae specify ```apps/basic/libzphook_basic.so``` for the ```LIBZPHOOK``` environment variable, and ```libzpoline.so``` for LD_PRELOAD. The example command is as follows.

```
$ LIBZPHOOK=./apps/basic/libzphook_basic.so LD_PRELOAD=./libzpoline.so [program you wish to run]
```

```LIBZPHOOK``` is defined in ```main.c``` of ```libzpoline.so```.
```libzpoline.so``` performs dlmopen for a shared library file specified by ```LIBZPHOOK```.

Currently, the hook function in ```apps/basic/libzphook_basic.so``` prints the system call number using printf. The following is the example output.

```
$ LIBZPHOOK=./apps/basic/libzphook_basic.so LD_PRELOAD=./libzpoline.so /bin/ls
output from __hook_init: we can do some init work here
output from hook_function: syscall number 257
output from hook_function: syscall number 262
output from hook_function: syscall number 9
output from hook_function: syscall number 3
output from hook_function: syscall number 16
output from hook_function: syscall number 16
output from hook_function: syscall number 257
output from hook_function: syscall number 262
output from hook_function: syscall number 217
output from hook_function: syscall number 217
output from hook_function: syscall number 3
output from hook_function: syscall number 262
output from hook_function: syscall number 1
apps  Documentation  libzpoline.so  LICENSE  main.c  main.o  Makefile  README.md
output from hook_function: syscall number 3
```

### How to implement my own system call hook

Currently, ```libzpoline.so``` is independent of the hook function library. So, you can build your own hook function library, and to activate it, you only need to specify it to the ```LIBZPHOOK``` environment variable.

In the hook function library, you should implement ```__hook_init```.
It will have the pointer to the hook function address as the argument, and by overwriting it, the hook function library can apply an arbitrary hook function.

For details, please check ```apps/basic/main.c```.

## Further Information

The following materials provide more information.

### Paper

A paper about zpoline appears at USENIX ATC 2023 ( [https://www.usenix.org/conference/atc23/presentation/yasukata](https://www.usenix.org/conference/atc23/presentation/yasukata) ).

This paper includes a technical overview (Section 2) and comparison with other existing hook mechanisms (Section 1 and 3); for busy readers, the abstract of the paper summarises 1) advantages over the previous mechanisms, 2) the challenge that this work addresses, 3) the overview of the solution, and 4) rough numbers of the experiment results.

We would appreciate it if you cite this paper when you refer to zpoline in your work.

### Supplemental documentation in this repository

[Documentation/README.md](Documentation/README.md) is supplemental documentation.

### Comments in the source code

The source code contains comments that explain how actually the system is implemented; these comments are the most detailed documentation currently we have.

The starting point of the program (```main.c```) is ```__zpoline_init```, that is triggered by ```LD_PRELOAD```, and this executes the following functions:
- ```setup_trampoline``` instantiates the trampoline code.
- ```rewrite_code``` performs binary rewriting.
- ```load_hook_lib``` loads the core library function using ```dlmopen```.
