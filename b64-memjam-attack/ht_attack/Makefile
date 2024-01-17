NAME = 4kattack

# ASM compiler flags
AA = nasm
AAFLAGS = -f elf64

ifdef DEBUG
AAFLAGS += -g -F dwarf
endif

# C compiler flags
CC = gcc
LD = gcc
COPT ?= -O0

ifdef DEBUG
COPT += -g
endif

ifeq (,$(CFLAGS))
CFLAGS = $(COPT)
endif

CFLAGS += -I/usr/include
CFLAGS += -I./include
CFLAGS += -fstack-protector-strong
CFLAGS += -fPIC # position independent code
CFLAGS += -D_FORTIFY_SOURCE=2 # fortify source
CFLAGS += -Wformat -Wformat-security # format string vulnerabilities
CFLAGS += -Wall

# Linker flags
LDFLAGS ?=
LDFLAGS += -z noexecstack # stack execution protection
LDFLAGS += -z relro -z now # data relocation and projection
#LDFLAGS += -pie # position independent execution

LIBS_PATH ?= -L/usr/lib64
LDFLAGS += $(LIBS_PATH) $(LIBS)


####################
## Files & folders
####################
HDRDIR = include
SRCDIR = src
SRCDIR_A = $(SRCDIR)/s
SRCDIR_C = $(SRCDIR)/c
OBJDIR = obj
OUTDIR = build

HDRS = $(addprefix $(HDRDIR)/,$(shell ls $(HDRDIR)))
SRC_A = $(shell find $(SRCDIR_A)/ -name "*.s")
SRC_C = $(shell find $(SRCDIR_C)/ -name "*.c")
OBJ_A = $(subst $(SRCDIR_A),$(OBJDIR),$(addsuffix .o,$(SRC_A)))
OBJ_C = $(subst $(SRCDIR_C),$(OBJDIR),$(addsuffix .o,$(SRC_C)))
OBJS = $(OBJ_A) $(OBJ_C)

####################
## Additional flags
####################
AAFLAGS += -i./$(SRCDIR_A)/
CFLAGS += -I./$(OBJDIR)

####################
## Targets
####################
all: app

app: $(NAME)

$(NAME): $(OBJS) | outdir
	$(LD) $(OBJS) $(LDFLAGS) -o $@ 

$(OBJDIR)/%.s.o: $(SRCDIR_A)/%.s | objdir
	$(AA) $(AAFLAGS) -o $@ $<

$(OBJDIR)/%.c.o: $(SRCDIR_C)/%.c | objdir
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -rf $(OBJDIR)
	rm -rf $(OUTDIR)

objdir:
	@mkdir -p $(OBJDIR)

outdir:
	@mkdir -p $(OUTDIR)

.PHONY: all clean test
