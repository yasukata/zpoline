#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <syscall.h>

#define __syscall_ret_errno(...)	    \
	({				    \
		long ret;		    \
		errno = 0;		    \
		ret = syscall(__VA_ARGS__); \
		if (errno) {		    \
			ret = -errno;	    \
		}			    \
		ret;			    \
	})

long __hook_fn(int64_t a1, int64_t a2, int64_t a3,
	       int64_t a4, int64_t a5, int64_t a6,
	       int64_t a7)
{
	printf("output from __hook_fn: syscall number %ld\n", a1);
	return __syscall_ret_errno(a1, a2, a3, a4, a5, a6, a7);
}

int __hook_init(void)
{
	printf("output from __hook_init: we can do some init work here\n");
	return 0;
}
