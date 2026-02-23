section .data
    msg: db "CW:ALIVE", 10
    len: equ $ - msg
section .text
    global _start
_start:
    mov rax, 1
    mov rdi, 1
    lea rsi, [msg]
    mov rdx, len
    syscall
    mov rax, 60
    xor rdi, rdi
    syscall
