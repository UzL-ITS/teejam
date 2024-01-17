TEST = test_bench

DEBUG = true
CC = gcc
COPT ?= -O2
ifdef $(DEBUG)
COPT += -g
endif
CFLAGS = $(COPT)
CFLAGS += -I/usr/include
CFLAGS += -fstack-protector-strong
CFLAGS += -fPIC # position independent code
CFLAGS += -D_FORTIFY_SOURCE=2 # fortify source
CFLAGS += -Wformat -Wformat-security # format string vulnerabilities
CFLAGS += -Wall
CFLAGS += -I../include

LDFLAGS ?=
LDFLAGS += -z noexecstack # stack execution protection
LDFLAGS += -z relro -z now # data relocation and projection
LDFLAGS += -L/usr/lib64 -L../lib -lcpu -lrt

all: test

test: $(TEST)

run_test: test
	@LD_LIBRARY_PATH=../lib:$LD_LIBRARY_PATH ./$(TEST)

$(TEST): $(TEST).c.o
	$(CC) -o $@ $< $(LDFLAGS)

$(TEST).c.o: $(TEST).c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	@rm -rf *.o
