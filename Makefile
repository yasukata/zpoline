PROGS = libzpoline.so

CC = gcc

CLEANFILES = $(PROGS) *.o *.d

SRCDIR ?= ./

NO_MAN=
CFLAGS = -O3 -pipe
CFLAGS += -g -rdynamic
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -Wextra
CFLAGS += -shared -fPIC

CFLAGS += -DSUPPLEMENTAL__REWRITTEN_ADDR_CHECK

LD_VERSION = $(shell ld --version | head -1 | awk '{ print $$NF }' | awk -F'-' '{ print $$1 }' | sed 's/\.//')
# differentiate the code according to the library version
ifeq ($(shell test $(LD_VERSION) -ge 239; echo $$?),0)
  CFLAGS += -DDIS_ASM_VER_239
else ifeq ($(shell test $(LD_VERSION) -ge 229; echo $$?),0)
  CFLAGS += -DDIS_ASM_VER_229
endif

LDFLAGS += -lopcodes -ldl

C_SRCS = main.c
OBJS = $(C_SRCS:.c=.o)

.PHONY: all
all: $(PROGS)

$(PROGS): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)
