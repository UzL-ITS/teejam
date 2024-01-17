[global mem_read]
mem_read:
    %rep 100
        mov rax, qword [rdi]
        mov rax, qword [rsi]
    %endrep
