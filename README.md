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

You can find a simpler version at commit ```e5afaba``` which does not use dlmopen.

## Target Platform

Currently, this implementation assumes Linux on the x86-64 architecture.

## Dependency

Zpoline uses the disassembler in ```libopcodes``` that is part of binutils.

```
$ sudo apt install binutils-dev
```

## Files

This example uses two shared libraries.

1. ```apps/basic/libzphook_basic.so``` only implements the hook function. (we call the hook function library).
2. ```libzpoline.so``` is loaded by LD_PRELOAD. This configures the trampoline code, conducts binary rewriting, and loads ```./apps/basic/libzphook_basic.so``` using dlmopen.

## Build

To build ```apps/basic/libzphook_basic.so```, please type the following command.

```
$ make -C apps/basic
```

For ```libzpoline.so```, please type the following command.

```
$ make
```

## Setup

To use Zpoline, please set 0 to ```/proc/sys/vm/mmap_min_addr```.

```
$ sudo sh -c "echo 0 > /proc/sys/vm/mmap_min_addr"
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
Initializing Zpoline ...
-- Setting up trampoline code
-- Rewriting the code
Loading hook library ...
-- load ./apps/basic/libzphook_basic.so
-- call hook init
output from __hook_init: we can do some init work here
-- set hook function
output from __hook_fn: syscall number 1
Start main program
output from __hook_fn: syscall number 257
output from __hook_fn: syscall number 5
output from __hook_fn: syscall number 9
output from __hook_fn: syscall number 3
output from __hook_fn: syscall number 16
output from __hook_fn: syscall number 16
output from __hook_fn: syscall number 257
output from __hook_fn: syscall number 5
output from __hook_fn: syscall number 217
output from __hook_fn: syscall number 217
output from __hook_fn: syscall number 3
output from __hook_fn: syscall number 1
apps  Documentation  libzpoline.so  LICENSE  main.c  main.o  Makefile  README.md
output from __hook_fn: syscall number 3
```

## Why do we need to separate files and load by dlmopen?

Users of the Zpoline technique should pay attention to the use of rewritten functions, otherwise, the system call hook may fall into an infinite loop.

Let's think about the printf library call which internally invokes a write system call.
When Zpoline is applied to the user-space program, the write system call triggered in printf will be hooked by Zpoline.
The problem occurs when the system call hook calls printf.
It will result in an infinite loop because the write system call in printf, called by the hook function, will be hooked and redirected to the same hook function.

dlmopen releases users of Zpoline from this issue.

The implementation of the hook function is ```__hook_fn``` in ```apps/basic/main.c```.

As mentioned above, the hook function may fall into an infinite loop when it uses a library call such as printf. But, in this example, the hook function (```__hook_fn```) can use printf.

This is realized by dlmopen. In ```libzpoline.so```, a function named ```load_hook_lib``` calls dlmopen and loads ```apps/basic/libzphook_basic.so```. In particular, ```load_hook_lib``` specifies ```LM_ID_NEWLM``` for dlmopen, and this requests to load ```apps/basic/libzphook_basic.so``` in a new namespace. At the same time, dlmopen also loads other required libraries including libc in the same namespace to which ```apps/basic/libzphook_basic.so``` belongs.

Now, libc for ```__hook_fn``` is newly instantiated in the new namespace, and it is different from the one used by the primary user-space program. Here, ```libzpoline.so``` does not replace syscall and sysenter instructions in the newly instantiated libc. Therefore, ```__hook_fn``` does not cause an infinite loop.

After ```apps/basic/libzphook_basic.so``` is loaded, ```libzpoline.so``` accesses ```__hook_fn``` in ```apps/basic/libzphook_basic.so``` through a pointer named ```hook_fn``` in this example.

Note that dlmopen does not only load libc but also other shared libraries associated with the hook function library. The association is done by the compiler. If you forget to specify the library to link (e.g., ```-lpthread``` for libpthread, ```-lm``` for libmath) for the compiler, dlmopen may fail to load them.

## How to Implement My Own System Call Hook

Currently, ```libzpoline.so``` is independent of the hook function library. So, you can build your own hook function library, and to activate it, you only need to specify it to the ```LIBZPHOOK``` environment variable.

In the hook function library, you should implement these two. 

1. ```__hook_fn``` is the system call hook function.
2. ```__hook_init``` is called just after trampoline code instantiation and binary rewriting are completed. We can use this for some specific initialization tasks.

Please keep these function names so that dlsym in ```main.c``` can find your own implementations. Or, please change the argument for dlsym in ```load_hook_lib``` accordingly.

## Coping with NULL pointer exceptions

Since zpoline uses address 0, that is normally considered NULL, by default, some NULL pointer errors do not cause a segmentation fault. The current version implements metigations for this issue.

Mainly, we think about three cases, write to NULL, read from NULL, and execute the program at NULL.

### 1. Write to NULL

We wish to cause a segmentation fault when running the following exmaple program.

```
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


```
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

```
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

## Further Information

You may be able to have a better understanding by checking the comments in the source code and [Documentation/README.md](Documentation/README.md).
