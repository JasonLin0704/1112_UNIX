    push rbp
    mov rbp, rsp
    
    mov rcx, 0
L1: 
    cmp rcx, rsi
    jge END
    
    mov r8, rcx    
    mov rdx, rcx
    inc rdx
L2:    
    cmp rdx, rsi
    jge L22 

    mov rax, [rdi + rdx * 8]
    mov rbx, [rdi + r8 * 8]
    cmp rax, rbx
    jge L21
    mov r8, rdx
L21:
    inc rdx
    jmp L2
L22:
    mov rax, [rdi + rcx * 8]
    mov rbx, [rdi + r8 * 8]
    mov [rdi + rcx * 8], rbx
    mov [rdi + r8 * 8], rax

    inc rcx
    jmp L1
END:
    pop rbp
    ret