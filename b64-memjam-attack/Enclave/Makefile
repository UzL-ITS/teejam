include $(SGX_SDK)/buildenv.mk

CC		  = gcc
AR		  = ar
LD		  = gcc
EDGER		  = sgx_edger8r
SIGNER		  = sgx_sign
INCLUDE       = -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I./include
T_CFLAGS	  = $(CFLAGS) -nostdinc -fvisibility=hidden -fpie \
					-fstack-protector -Os -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type  \
					-Waddress -Wsequence-point -Wformat-security -Wmissing-include-dirs \
					-Wfloat-equal -Wundef -Wshadow -Wcast-align -Wcast-qual -Wconversion \
					-Wredundant-decls
U_CFLAGS	  = $(CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector -Os -Wall \
					-Wextra -Winit-self -Wpointer-arith -Wreturn-type -Waddress -Wsequence-point \
					-Wformat-security -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
					-Wcast-align -Wcast-qual -Wconversion -Wredundant-decls
AR_FLAGS	  = rcs
OBJECTS		  = encl.o
A_OBJECTS	  = mem_read.s.o
LIB_SGX_TRTS      = -lsgx_trts
LIB_SGX_TSERVICE  = -lsgx_tservice
SGXSSL_Library_Name := sgx_tsgxssl
OpenSSL_Crypto_Library_Name := sgx_tsgxssl_crypto

LIB_SUFX  = 64

# Added to build with SgxSSL libraries
TSETJMP_LIB := -lsgx_tsetjmp
# OPENSSL_LIBRARY_PATH := $(PACKAGE_LIB)/

ifeq "20" "$(word 1, $(sort 20 $(SGXSDK_INT_VERSION)))"
        TSETJMP_LIB:=
endif


ENCLAVE_LIBS      = $(LIB_SGX_TRTS)
										
# ENCLAVE_LIB_PARTS = -lsgx_tstdc -lsgx_tcrypto $(LIB_SGX_TSERVICE)
ENCLAVE_LIB_PARTS1 = -lsgx_tstdc -lsgx_pthread -lsgx_tcxx -lsgx_tcrypto $(TSETJMP_LIB) $(LIB_SGX_TSERVICE)
SgxSSL_Link_Libraries := -Wl,--whole-archive -l$(SGXSSL_Library_Name) -Wl,--no-whole-archive -l$(OpenSSL_Crypto_Library_Name)

ENCLAVE	          = encl
PRIVATE_KEY       = private_key.pem
PUBLIC_KEY        = public_key.pem
KEY_SIZE          = 3072
ENCLAVE_EDL       = $(ENCLAVE).edl
ENCLAVE_CONFIG    = $(ENCLAVE).config.xml
OUTPUT_T          = $(ENCLAVE).so
OUTPUT_T_UNSIG    = $(ENCLAVE).unsigned.so
OUTPUT_U          = lib$(ENCLAVE)_proxy.a
LIB_DIRS          = -L$(SGX_TRUSTED_LIBRARY_PATH) -L./lib64
LD_FLAGS         += -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	$(SgxSSL_Link_Libraries) \
                    -Wl,--whole-archive $(ENCLAVE_LIBS) \
                    -Wl,--no-whole-archive -Wl,--start-group $(ENCLAVE_LIB_PARTS1) -Wl,--end-group \
                    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
                    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
                    -Wl,--defsym,__ImageBase=0
TRUSTED_OBJECTS   = $(ENCLAVE)_t.o
UNTRUSTED_OBJECTS = $(ENCLAVE)_u.o 
TRUSTED_CODE      = $(ENCLAVE)_t.h $(ENCLAVE)_t.c
UNTRUSTED_CODE    = $(ENCLAVE)_u.h $(ENCLAVE)_u.c

# ASM compiler flags
AA = nasm
AAFLAGS = -f elf64

#.SILENT:
all: $(OUTPUT_T) $(OUTPUT_U)

$(OUTPUT_T) : $(TRUSTED_OBJECTS) $(OBJECTS) $(A_OBJECTS) $(PRIVATE_KEY)
	echo "$(INDENT)[LD]  " $(OBJECTS) $(TRUSTED_OBJECTS) $(LD_FLAGS) $(OUTPUT_T_UNSIG)
	$(LD) $(OBJECTS) $(A_OBJECTS) $(TRUSTED_OBJECTS) $(LD_FLAGS) $(LIB_DIRS) -o $(OUTPUT_T_UNSIG) 
	
	echo "$(INDENT)[SGN]" $(OUTPUT_T_UNSIG)
	$(SIGNER) sign -key $(PRIVATE_KEY) -enclave $(OUTPUT_T_UNSIG) -out $(OUTPUT_T) -config $(ENCLAVE_CONFIG) > /dev/null 2> /dev/null

$(OUTPUT_U) : $(UNTRUSTED_OBJECTS) 
	echo "$(INDENT)[AR]  " $(OUTPUT_U)
	$(AR) $(AR_FLAGS) $(OUTPUT_U) $(UNTRUSTED_OBJECTS) 
	
%_t.o : $(subst .o,.c,$@) edger
	echo "$(INDENT)[CC] " $(subst .o,.c,$@) "(trusted edge)"
	touch $(subst .o,.c,$@)
	$(CC) -c $(INCLUDE) $(T_CFLAGS) $(subst .o,.c,$@)

%_u.o : $(subst .o,.c,$@) edger
	echo "$(INDENT)[CC] " $(subst .o,.c,$@) "(untrusted edge)"
	touch $(subst .o,.c,$@)
	$(CC) -c $(INCLUDE) $(U_CFLAGS) $(subst .o,.c,$@)

%.o : %.c edger
	echo "$(INDENT)[CC] " $< "(core)"
	$(CC) $(INCLUDE) $(T_CFLAGS) -c $<

%.o : %.S
	echo "$(INDENT)[AS] " $< "(core)"
	$(CC) $(INCLUDE) $(T_CFLAGS) -c $< -o $@

%.s.o: %.s
	$(AA) $(AAFLAGS) -o $@ $<

edger: $(ENCLAVE).edl
	echo "$(INDENT)[GEN]" $(EDGER) $(ENCLAVE_EDL)
	$(EDGER) $(ENCLAVE_EDL) --search-path ./include --search-path $(SGX_SDK)/include --search-path $(SGX_SDK)/include/tlibc
	# $(EDGER) $(ENCLAVE_EDL)
	
.PHONY: force_check
force_check:
	true

.PHONY: scrub
scrub: 
	echo "$(INDENT)[RM]  " $(PRIVATE_KEY) $(PUBLIC_KEY)
	$(RM) $(PRIVATE_KEY) $(PUBLIC_KEY)

$(PRIVATE_KEY):
	echo "$(INDENT)[GEN] $(PRIVATE_KEY) ($(KEY_SIZE) bits)"

	# generate 3072 bit private RSA key
	openssl genrsa -out $(PRIVATE_KEY) -3 $(KEY_SIZE)
	
	echo "$(INDENT)[EXT] $(PUBLIC_KEY)"
	# extract public key
	openssl rsa -in $(PRIVATE_KEY) -pubout -out $(PUBLIC_KEY) 
	
	# sign enclave
	#sgx_sign sign -key private_key.pem -enclave Enclave/encl.so -out encl.signed.so
	
.PHONY: clean
clean:
	echo "$(INDENT)[RM]" $(OBJECTS) $(OUTPUT_T_UNSIG) $(OUTPUT_T) $(OUTPUT_U)
	$(RM) $(OBJECTS) $(OUTPUT_T_UNSIG) $(OUTPUT_T) $(OUTPUT_U)
	echo "$(INDENT)[RM]" $(TRUSTED_OBJECTS) $(UNTRUSTED_OBJECTS) $(TRUSTED_CODE) $(UNTRUSTED_CODE)
	$(RM) $(TRUSTED_OBJECTS) $(UNTRUSTED_OBJECTS) $(TRUSTED_CODE) $(UNTRUSTED_CODE)
	$(RM) asm_nop.S
