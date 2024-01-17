LIBSGXSTEP_DIR       = ../sgx-step
LIBSGXSTEP           = $(LIBSGXSTEP_DIR)/libsgxstep
-include $(LIBSGXSTEP)/Makefile.config

ifeq ($(SGX_SDK),)
    SGX_SDK          = /opt/intel/sgxsdk
endif
export SGX_SDK
ifneq ($(SGX_SDK), /opt/intel/sgxsdk)
    URTS_LD_LIBRARY_PATH = LD_LIBRARY_PATH=$(LIBSGXSTEP_DIR)/linux-sgx/psw/urts/linux
endif

include $(SGX_SDK)/buildenv.mk

ENCLAVE              = Enclave
LIBCACHE             = ../libcache
SUBDIRS              = $(ENCLAVE) $(LIBCACHE) $(LIBSGXSTEP)


CC                   = gcc
AS                   = gcc
LD                   = gcc

LIB_SUFX = 64

CFLAGS              += -fPIC -fno-stack-protector -fno-builtin -fno-jump-tables \
                       -fno-common -Wno-attributes -D_GNU_SOURCE -O0
INCLUDE              = -I$(SGX_SDK)/include/ -I$(LIBSGXSTEP_DIR) -I$(LIBCACHE)/include
LDFLAGS             += -lcpu -lsgx-step -lencl_proxy -lsgx_urts -lsgx_usgxssl \
                       -lsgx_uae_service -pthread -lrt $(SUBDIRS:%=-L %) -L$(LIBCACHE)/lib -L$(SGX_TRUSTED_LIBRARY_PATH) \
                       -L$(LIBSGXSTEP_DIR)/linux-sgx/psw/urts/linux -L/usr/lib64 -L./Enclave/lib64


SOURCES              = $(shell ls *.c)
OBJECTS              = $(SOURCES:.c=.o)
OUTPUT               = b64-attack

BUILDDIRS            = $(SUBDIRS:%=build-%)
CLEANDIRS            = $(SUBDIRS:%=clean-%)

WATCH                = watch -n 0.1 #-e

.SILENT:
all: $(OUTPUT)
	
run: clean all
	sudo $(URTS_LD_LIBRARY_PATH) ./basic_experiment

repeat: clean all
	while true; do \
        $(WATCH) sudo $(URTS_LD_LIBRARY_PATH) ./basic_experiment ; \
	done;

$(OUTPUT): $(BUILDDIRS) $(OBJECTS)
	echo "$(INDENT)[LD]" $(OBJECTS) $(LDFLAGS) -o $(OUTPUT)
	$(LD) $(OBJECTS) $(LDFLAGS) -o $(OUTPUT) 

%.o : %.c
	echo "$(INDENT)[CC] " $<
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

%.o : %.S
	echo "$(INDENT)[AS] " $<
	$(AS) $(INCLUDE) -c $< -o $@

clean: $(CLEANDIRS)
	echo "$(INDENT)[RM]" $(OBJECTS) $(OUTPUT)
	rm -f $(OBJECTS) $(OUTPUT)

$(BUILDDIRS):
	echo "$(INDENT)[===] $(@:build-%=%) [===]"
	$(MAKE) -C $(@:build-%=%) INDENT+="$(INDENT_STEP)" curr-dir=$(curr-dir)/$(@:build-%=%)

$(CLEANDIRS):
	echo "$(INDENT)[===] $(@:clean-%=%) [===]"
	$(MAKE) clean -C $(@:clean-%=%) INDENT+="$(INDENT_STEP)" curr-dir=$(curr-dir)/$(@:build-%=%)
