%include "attack_macro.s"

[global write_conflict]
write_conflict:
    mov rax, 0
write_conflict_loop:
    add rax, 1
    m_conflict rdi
    cmp rax, 10000
    jnz write_conflict_loop
    ret
