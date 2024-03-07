# 0 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_tomont_p384.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_tomont_p384.S"
# 15 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_tomont_p384.S"
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/include/_internal_s2n_bignum.h" 1
# 16 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_tomont_p384.S" 2


        .globl bignum_tomont_p384
        .hidden bignum_tomont_p384
        .text
# 87 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_tomont_p384.S"
bignum_tomont_p384:
# 102 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_tomont_p384.S"
        pushq %rbp
        pushq %r12
        pushq %r13
        pushq %r14
        pushq %r15





        movq $0xfffffffe00000001, %rdx
        mulxq (%rsi), %r8, %r9
        mulxq 8(%rsi), %rcx, %r10
        addq %rcx, %r9
        mulxq 16(%rsi), %rcx, %r11
        adcq %rcx, %r10
        mulxq 24(%rsi), %rcx, %r12
        adcq %rcx, %r11
        mulxq 32(%rsi), %rcx, %r13
        adcq %rcx, %r12
        mulxq 40(%rsi), %rcx, %r14
        adcq %rcx, %r13
        adcq $0, %r14



        xorq %r15, %r15
        movq %r8, %rdx 
 shlq $32, %rdx 
 addq %r8, %rdx 
 xorl %ebp, %ebp 
 movq $0xffffffff00000001, %rax 
 mulxq %rax, %rcx, %rax 
 movl $0x00000000ffffffff, %ecx 
 mulxq %rcx, %r8, %rcx 
 adcq %r8, %rax 
 adcq %rdx, %rcx 
 adcl %ebp, %ebp 
 subq %rax, %r9 
 sbbq %rcx, %r10 
 sbbq %rbp, %r11 
 sbbq $0, %r12 
 sbbq $0, %r13 
 sbbq $0, %rdx 
 addq %rdx, %r14 
 adcq $0, %r15



        xorq %rbp, %rbp
        movq $0x0000000200000000, %rdx
        xorq %r8, %r8
        mulxq (%rsi), %rax, %rcx 
 adcxq %rax, %r9 
 adoxq %rcx, %r10
        mulxq 8(%rsi), %rax, %rcx 
 adcxq %rax, %r10 
 adoxq %rcx, %r11
        mulxq 16(%rsi), %rax, %rcx 
 adcxq %rax, %r11 
 adoxq %rcx, %r12
        mulxq 24(%rsi), %rax, %rcx 
 adcxq %rax, %r12 
 adoxq %rcx, %r13
        mulxq 32(%rsi), %rax, %rcx 
 adcxq %rax, %r13 
 adoxq %rcx, %r14
        mulxq 40(%rsi), %rax, %rcx 
 adcxq %rax, %r14 
 adoxq %rcx, %r15
        adcxq %rbp, %r15
        adoxq %rbp, %r8
        adcxq %rbp, %r8



        movq %r9, %rdx 
 shlq $32, %rdx 
 addq %r9, %rdx 
 xorl %ebp, %ebp 
 movq $0xffffffff00000001, %rax 
 mulxq %rax, %rcx, %rax 
 movl $0x00000000ffffffff, %ecx 
 mulxq %rcx, %r9, %rcx 
 adcq %r9, %rax 
 adcq %rdx, %rcx 
 adcl %ebp, %ebp 
 subq %rax, %r10 
 sbbq %rcx, %r11 
 sbbq %rbp, %r12 
 sbbq $0, %r13 
 sbbq $0, %r14 
 sbbq $0, %rdx 
 addq %rdx, %r15 
 adcq $0, %r8



        xorq %rbp, %rbp
        movq $0xfffffffe00000000, %rdx
        xorq %r9, %r9
        mulxq (%rsi), %rax, %rcx 
 adcxq %rax, %r10 
 adoxq %rcx, %r11
        mulxq 8(%rsi), %rax, %rcx 
 adcxq %rax, %r11 
 adoxq %rcx, %r12
        mulxq 16(%rsi), %rax, %rcx 
 adcxq %rax, %r12 
 adoxq %rcx, %r13
        mulxq 24(%rsi), %rax, %rcx 
 adcxq %rax, %r13 
 adoxq %rcx, %r14
        mulxq 32(%rsi), %rax, %rcx 
 adcxq %rax, %r14 
 adoxq %rcx, %r15
        mulxq 40(%rsi), %rax, %rcx 
 adcxq %rax, %r15 
 adoxq %rcx, %r8
        adcxq %rbp, %r8
        adoxq %rbp, %r9
        adcxq %rbp, %r9



        movq %r10, %rdx 
 shlq $32, %rdx 
 addq %r10, %rdx 
 xorl %ebp, %ebp 
 movq $0xffffffff00000001, %rax 
 mulxq %rax, %rcx, %rax 
 movl $0x00000000ffffffff, %ecx 
 mulxq %rcx, %r10, %rcx 
 adcq %r10, %rax 
 adcq %rdx, %rcx 
 adcl %ebp, %ebp 
 subq %rax, %r11 
 sbbq %rcx, %r12 
 sbbq %rbp, %r13 
 sbbq $0, %r14 
 sbbq $0, %r15 
 sbbq $0, %rdx 
 addq %rdx, %r8 
 adcq $0, %r9



        xorq %rbp, %rbp
        movq $0x0000000200000000, %rdx
        xorq %r10, %r10
        mulxq (%rsi), %rax, %rcx 
 adcxq %rax, %r11 
 adoxq %rcx, %r12
        mulxq 8(%rsi), %rax, %rcx 
 adcxq %rax, %r12 
 adoxq %rcx, %r13
        mulxq 16(%rsi), %rax, %rcx 
 adcxq %rax, %r13 
 adoxq %rcx, %r14
        mulxq 24(%rsi), %rax, %rcx 
 adcxq %rax, %r14 
 adoxq %rcx, %r15
        mulxq 32(%rsi), %rax, %rcx 
 adcxq %rax, %r15 
 adoxq %rcx, %r8
        mulxq 40(%rsi), %rax, %rcx 
 adcxq %rax, %r8 
 adoxq %rcx, %r9
        adcxq %rbp, %r9
        adoxq %rbp, %r10
        adcxq %rbp, %r10



        movq %r11, %rdx 
 shlq $32, %rdx 
 addq %r11, %rdx 
 xorl %ebp, %ebp 
 movq $0xffffffff00000001, %rax 
 mulxq %rax, %rcx, %rax 
 movl $0x00000000ffffffff, %ecx 
 mulxq %rcx, %r11, %rcx 
 adcq %r11, %rax 
 adcq %rdx, %rcx 
 adcl %ebp, %ebp 
 subq %rax, %r12 
 sbbq %rcx, %r13 
 sbbq %rbp, %r14 
 sbbq $0, %r15 
 sbbq $0, %r8 
 sbbq $0, %rdx 
 addq %rdx, %r9 
 adcq $0, %r10




        xorq %r11, %r11
        addq (%rsi), %r12
        adcq 8(%rsi), %r13
        adcq 16(%rsi), %r14
        adcq 24(%rsi), %r15
        adcq 32(%rsi), %r8
        adcq 40(%rsi), %r9
        adcq $0, %r10
        adcq $0, %r11



        movq %r12, %rdx 
 shlq $32, %rdx 
 addq %r12, %rdx 
 xorl %ebp, %ebp 
 movq $0xffffffff00000001, %rax 
 mulxq %rax, %rcx, %rax 
 movl $0x00000000ffffffff, %ecx 
 mulxq %rcx, %r12, %rcx 
 adcq %r12, %rax 
 adcq %rdx, %rcx 
 adcl %ebp, %ebp 
 subq %rax, %r13 
 sbbq %rcx, %r14 
 sbbq %rbp, %r15 
 sbbq $0, %r8 
 sbbq $0, %r9 
 sbbq $0, %rdx 
 addq %rdx, %r10 
 adcq $0, %r11




        xorq %r12, %r12



        movq %r13, %rdx 
 shlq $32, %rdx 
 addq %r13, %rdx 
 xorl %ebp, %ebp 
 movq $0xffffffff00000001, %rax 
 mulxq %rax, %rcx, %rax 
 movl $0x00000000ffffffff, %ecx 
 mulxq %rcx, %r13, %rcx 
 adcq %r13, %rax 
 adcq %rdx, %rcx 
 adcl %ebp, %ebp 
 subq %rax, %r14 
 sbbq %rcx, %r15 
 sbbq %rbp, %r8 
 sbbq $0, %r9 
 sbbq $0, %r10 
 sbbq $0, %rdx 
 addq %rdx, %r11 
 adcq $0, %r12
# 223 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_tomont_p384.S"
        movq $0xffffffff00000001, %rdx
        movl $0x00000000ffffffff, %ecx
        movl $0x0000000000000001, %esi




        movq %r14, %rax
        addq %rdx, %rax
        movq %r15, %rax
        adcq %rcx, %rax
        movq %r8, %rax
        adcq %rsi, %rax
        movq %r9, %rax
        adcq $0, %rax
        movq %r10, %rax
        adcq $0, %rax
        movq %r11, %rax
        adcq $0, %rax




        adcq $0, %r12



        negq %r12



        andq %r12, %rdx
        andq %r12, %rcx
        andq %r12, %rsi

        addq %rdx, %r14
        adcq %rcx, %r15
        adcq %rsi, %r8
        adcq $0, %r9
        adcq $0, %r10
        adcq $0, %r11



        movq %r14, (%rdi)
        movq %r15, 8(%rdi)
        movq %r8, 16(%rdi)
        movq %r9, 24(%rdi)
        movq %r10, 32(%rdi)
        movq %r11, 40(%rdi)



        popq %r15
        popq %r14
        popq %r13
        popq %r12
        popq %rbp





        ret


.section .note.GNU-stack,"",%progbits
