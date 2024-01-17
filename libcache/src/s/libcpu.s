%include "libcpu_nasm_makros.s"

; Warm up loop
; Parameters:
; - RDI: (uint64_t) Number of iterations
[global cpu_warm_up]
cpu_warm_up:
	dec rdi
	jnz cpu_warm_up
	ret

; Flush cacheline
; Parameters:
; - RDI: (void *) Address to be flushed
[global cpu_clflush]
cpu_clflush:
	clflush [rdi]
	ret

; Read timestamp counter
; Return:
; - (uint64_t) Timestamp counter value
[global cpu_rdtsc]
cpu_rdtsc:
	m_rdtsc
	ret

; Read timestamp counter
; Return:
; - (uint64_t) Timestamp counter value
[global cpu_rdtscp]
cpu_rdtscp:
	m_rdtscp
	ret

; Memory access
; Accesses only 1 byte
; Parameters:
; - RDI: (void *) Address to be accessed
[global cpu_maccess]
cpu_maccess:
	mov dil, [rdi]
	ret

; Time memory access
; Accesses only 1 byte
; Parameters:
; - RDI: (void *) Address to access
; Return:
; - (uint64_t) Access time in clock cycles
[global cpu_maccess_time]
cpu_maccess_time:
	m_rdtsc rsi
	mov dil, [rdi]
	m_rdtsc
	sub rax, rsi
	ret

; Prime cache set by Pointer Chasing
; Parameters:
; - RDI: (void *) Start of the linked list
; - RSI: (size_t) Length of the linked list
[global cpu_prime_pointer_chasing_n]
cpu_prime_pointer_chasing_n:
	mov rdi, [rdi]
	dec rsi
	jne cpu_prime_pointer_chasing_n
	ret

; Prime cache set by Pointer Chasing
; Parameters:
; - RDI: (void *) Start of the linked list
[global cpu_prime_pointer_chasing]
cpu_prime_pointer_chasing:
	mov rdi, [rdi]
	test rdi, rdi
	jne cpu_prime_pointer_chasing
	ret

; Prime cache set by array accesses
; Parameters:
; - RDI: (void **) Start of array
; - RSI: (size_t) Lenght of array
[global cpu_prime_array]
cpu_prime_array:
	xor rdx, rdx
cpu_prime_array_loop:
	mov rax, [rdi+8*rdx] ; get address from array
	mov rax, [rcx]       ; access address
	inc rdx
	cmp rsi, rdx
	jne cpu_prime_array_loop
	ret

; Probe cache set by Pointer Chasing
; Parameters:
; - RDI: (void *) Start of the linked list
; - RSI: (size_t) Length of the linked list
; Return:
; - (uint64_t) Probe time in clock cycles
[global cpu_probe_pointer_chasing_n]
cpu_probe_pointer_chasing_n:
	; get timestamp
	m_rdtsc rcx
	; probe
cpu_probe_pointer_chasing_n_loop:
	mov rdi, [rdi]
	dec rsi
	jne cpu_probe_pointer_chasing_n_loop
	; get timestamp
	m_rdtsc
	sub rax, rcx
	ret

; Probe cache set by Pointer Chasing
; Parameters:
; - RDI: (void *) Start of the linked list
; Return:
; - (uint64_t) Probe time in clock cycles
[global cpu_probe_pointer_chasing]
cpu_probe_pointer_chasing:
	; get timestamp
	m_rdtsc rcx
	; probe
cpu_probe_pointer_chasing_loop:
	mov rdi, [rdi]
	test rdi, rdi
	jne cpu_probe_pointer_chasing_loop
	; get timestamp
	m_rdtsc
	sub rax, rcx
	ret

; Probe cache set by Pointer Chasing
; Parameters:
; - RDI: (void *) Start of the linked list
; - RSI: (void *) Storage location for measurement
; Return:
; - (uint64_t) Probe time in clock cycles
[global cpu_probe_pointer_chasing_store]
cpu_probe_pointer_chasing_store:
    ; get timestamp
    m_rdtsc rcx
    ; probe
cpu_probe_pointer_chasing_loop_store:
    mov rdi, [rdi]
    test rdi, rdi
    jne cpu_probe_pointer_chasing_loop_store
    ; get timestamp
    m_rdtsc
    sub rax, rcx
    mov [rsi], rax
    ret

; Probe cache set by array accesses
; Parameters:
; - RDI: (void **) Start of array
; - RSI: (size_t) Length of array
; Return:
; - (uint64_t) Probe time in clock cycles
[global cpu_probe_array]
cpu_probe_array:
	; get timestamp
	m_rdtsc rcx
	; probe
	xor rdx, rdx
cpu_probe_array_loop:
	mov rax, [rdi+8*rdx]
	mov rax, [rax]
	inc rdx
	cmp rsi, rdx
	jne cpu_probe_array_loop
	; get timestamp
	m_rdtsc
	sub rax, rcx
	ret
