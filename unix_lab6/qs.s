START:
    push rbp
    mov rbp, rsp

    xor r8, r8
    mov r9, rsi
    dec r9

    call QUICK_SORT

END:
    leave
    ret

QUICK_SORT:
    push rbp
    mov rbp, rsp
    sub rsp, 16

    cmp r8, r9
    jge END

    mov r12, [rdi + r8 * 8]
    lea rcx, [r8]
    lea rdx, [r9 + 1]

DO_i:
    inc rcx
    cmp rcx, r9
    jg DO_j
    
    mov rax, [rdi + rcx * 8]
    cmp rax, r12
    jge  DO_j

    jmp DO_i

DO_j:
    dec rdx
    cmp rdx, r8
    jl IF_i_j
    
    mov rax, [rdi + rdx * 8]
    cmp rax, r12
    jle  IF_i_j

    jmp DO_j

IF_i_j:
    cmp rcx, rdx
    jge SWAP_j_l

    mov rax, [rdi + rcx * 8]
    xchg [rdi + rdx * 8], rax
    mov [rdi + rcx * 8], rax
    jmp DO_i

SWAP_j_l:
    mov rax, [rdi + rdx * 8]
    xchg [rdi + r8 * 8], rax
    mov [rdi + rdx * 8], rax

RECURSIVE:
    mov [rbp - 8], r9
    mov [rbp - 16], rdx

LEFT:
    mov r9, [rbp - 16]
    dec r9
    mov rax, r9
    sub rax, r8
    cmp rax, 45
    jle IS1
QS1:
    call QUICK_SORT
    jmp RIGHT
IS1:    
    call INSERTION_SORT

RIGHT:
    mov r8, [rbp - 16]
    inc r8
    mov r9, [rbp - 8]
    mov rax, r9
    sub rax, r8
    cmp rax, 45
    jle IS2
QS2:
    call QUICK_SORT
    leave
    ret
IS2:    
    call INSERTION_SORT
    leave
    ret

INSERTION_SORT:
OUTER_LOOP:
    inc r8
    cmp r8, r9
    jg END_INSERTION
    mov r13, [rdi + r8 * 8]
    mov r14, r8

INNER_LOOP:
    cmp r14, 0
    jle K

    lea rax, [r14 - 1]
    cmp [rdi + rax * 8], r13
    jle K

    mov rbx, [rdi + rax * 8]
    mov [rdi + r14 * 8], rbx
    dec r14
    jmp INNER_LOOP

K:
    mov [rdi + r14 * 8], r13
    jmp OUTER_LOOP

END_INSERTION:
    ret    