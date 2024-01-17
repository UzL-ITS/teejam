TEST = test2

DEBUG = true
CC = gcc
COPT ?= -O0
ifdef $(DEBUG)
COPT += -g
endif
CFLAGS = $(COPT)
CFLAGS += -fstack-protector-strong
CFLAGS += -fPIC # position independent code
CFLAGS += -D_FORTIFY_SOURCE=2 # fortify source
CFLAGS += -Wformat -Wformat-security # format string vulnerabilities
CFLAGS += -Wall
INCLUDES = -I/usr/include -I../include
CFLAGS += $(INCLUDES) 

LDFLAGS ?=
LDFLAGS += -z noexecstack # stack execution protection
LDFLAGS += -z relro -z now # data relocation and projection
LDFLAGS += -L/usr/lib64 -L../lib -lcpu -lrt

all: lib_pnp_build test

test: $(TEST)

run_test: test
	@LD_LIBRARY_PATH=../lib:$LD_LIBRARY_PATH ./$(TEST)

$(TEST): $(TEST).c.o
	$(CC) -o $@ $< $(LDFLAGS)

$(TEST).c.o: $(TEST).c
	$(CC) $(CFLAGS) -o $@ -c $<
	
lib_pnp_build:
	$(MAKE) -C ../ all

lib_pnp_clean:
	$(MAKE) -C ../ clean
	
clean: lib_pnp_clean
	$(RM) $(TEST) $(TEST).c.o