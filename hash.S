.intel_syntax noprefix

#ifdef _WIN32
.text
.globl asm_hash_block
.globl asm_transform
.globl asm_checksum

.align 16
asm_hash_block:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    
    test r13, r13
    jz .hash_done
    
    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    
.hash_loop:
    cmp rcx, r13
    jge .hash_done
    
    movzx r15, byte ptr [r12 + rcx]
    
    rol r14, 13
    xor r14, r15
    
    imul r14, r14, 0x5bd1e995
    
    mov r15, r14
    shr r15, 15
    xor r14, r15
    
    add rax, r14
    
    inc rcx
    jmp .hash_loop
    
.hash_done:
    mov rax, r14
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

.align 16
asm_transform:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    
    mov r12, rcx
    mov r13, rdx
    
    test r13, r13
    jz .transform_done
    
    xor rcx, rcx
    mov rbx, 0x9e3779b97f4a7c15
    
.transform_loop:
    cmp rcx, r13
    jge .transform_done
    
    movzx rax, byte ptr [r12 + rcx]
    
    xor rax, rbx
    rol rax, 5
    
    mov byte ptr [r12 + rcx], al
    
    rol rbx, 7
    xor rbx, rcx
    
    inc rcx
    jmp .transform_loop
    
.transform_done:
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

.align 16
asm_checksum:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    
    mov r12, rcx
    mov ecx, edx
    
    test ecx, ecx
    jz .checksum_done
    
    xor rax, rax
    xor rbx, rbx
    
.checksum_loop:
    cmp ebx, ecx
    jge .checksum_done
    
    mov rdx, qword ptr [r12 + rbx * 8]
    xor rax, rdx
    
    rol rax, 1
    
    inc ebx
    jmp .checksum_loop
    
.checksum_done:
    pop r12
    pop rbx
    pop rbp
    ret

#else

.text
.globl asm_hash_block
.globl asm_transform
.globl asm_checksum

.align 16
asm_hash_block:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    
    test r13, r13
    jz .hash_done
    
    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    
.hash_loop:
    cmp rcx, r13
    jge .hash_done
    
    movzx r15, byte ptr [r12 + rcx]
    
    rol r14, 13
    xor r14, r15
    
    imul r14, r14, 0x5bd1e995
    
    mov r15, r14
    shr r15, 15
    xor r14, r15
    
    add rax, r14
    
    inc rcx
    jmp .hash_loop
    
.hash_done:
    mov rax, r14
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

.align 16
asm_transform:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    
    mov r12, rdi
    mov r13, rsi
    
    test r13, r13
    jz .transform_done
    
    xor rcx, rcx
    mov rbx, 0x9e3779b97f4a7c15
    
.transform_loop:
    cmp rcx, r13
    jge .transform_done
    
    movzx rax, byte ptr [r12 + rcx]
    
    xor rax, rbx
    rol rax, 5
    
    mov byte ptr [r12 + rcx], al
    
    rol rbx, 7
    xor rbx, rcx
    
    inc rcx
    jmp .transform_loop
    
.transform_done:
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

.align 16
asm_checksum:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    
    mov r12, rdi
    mov ecx, esi
    
    test ecx, ecx
    jz .checksum_done
    
    xor rax, rax
    xor rbx, rbx
    
.checksum_loop:
    cmp ebx, ecx
    jge .checksum_done
    
    mov rdx, qword ptr [r12 + rbx * 8]
    xor rax, rdx
    
    rol rax, 1
    
    inc ebx
    jmp .checksum_loop
    
.checksum_done:
    pop r12
    pop rbx
    pop rbp
    ret

.section .note.GNU-stack,"",@progbits

#endif