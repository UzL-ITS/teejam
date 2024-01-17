[global mem_read]
mem_read:
    %rep 100
        mov eax, dword [rdi]
        mov eax, dword [rsi]
    %endrep
