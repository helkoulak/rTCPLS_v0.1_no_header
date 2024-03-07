# 0 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_mul_p521.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_mul_p521.S"
# 15 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_mul_p521.S"
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/include/_internal_s2n_bignum.h" 1
# 16 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_mul_p521.S" 2


        .globl bignum_mul_p521
        .hidden bignum_mul_p521
        .text
# 38 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_mul_p521.S"
bignum_mul_p521:
# 50 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_mul_p521.S"
        pushq %rbp
        pushq %rbx
        pushq %r12
        pushq %r13
        pushq %r14
        pushq %r15
        subq $64, %rsp



        movq %rdx, %rcx




        xorl %ebp, %ebp
        movq (%rcx), %rdx
        mulxq (%rsi), %r8, %r9
        movq %r8, (%rsp)
        mulxq 0x8(%rsi), %rbx, %r10
        adcq %rbx, %r9
        mulxq 0x10(%rsi), %rbx, %r11
        adcq %rbx, %r10
        mulxq 0x18(%rsi), %rbx, %r12
        adcq %rbx, %r11
        mulxq 0x20(%rsi), %rbx, %r13
        adcq %rbx, %r12
        mulxq 0x28(%rsi), %rbx, %r14
        adcq %rbx, %r13
        mulxq 0x30(%rsi), %rbx, %r15
        adcq %rbx, %r14
        mulxq 0x38(%rsi), %rbx, %r8
        adcq %rbx, %r15
        adcq %rbp, %r8
        movq 0x8(%rcx), %rdx
        xorl %ebp, %ebp
        mulxq (%rsi), %rax, %rbx
        adcxq %rax, %r9
        adoxq %rbx, %r10
        movq %r9, 0x8(%rsp)
        mulxq 0x8(%rsi), %rax, %rbx
        adcxq %rax, %r10
        adoxq %rbx, %r11
        mulxq 0x10(%rsi), %rax, %rbx
        adcxq %rax, %r11
        adoxq %rbx, %r12
        mulxq 0x18(%rsi), %rax, %rbx
        adcxq %rax, %r12
        adoxq %rbx, %r13
        mulxq 0x20(%rsi), %rax, %rbx
        adcxq %rax, %r13
        adoxq %rbx, %r14
        mulxq 0x28(%rsi), %rax, %rbx
        adcxq %rax, %r14
        adoxq %rbx, %r15
        mulxq 0x30(%rsi), %rax, %rbx
        adcxq %rax, %r15
        adoxq %rbx, %r8
        mulxq 0x38(%rsi), %rax, %r9
        adcxq %rax, %r8
        adoxq %rbp, %r9
        adcq %rbp, %r9
        movq 0x10(%rcx), %rdx
        xorl %ebp, %ebp
        mulxq (%rsi), %rax, %rbx
        adcxq %rax, %r10
        adoxq %rbx, %r11
        movq %r10, 0x10(%rsp)
        mulxq 0x8(%rsi), %rax, %rbx
        adcxq %rax, %r11
        adoxq %rbx, %r12
        mulxq 0x10(%rsi), %rax, %rbx
        adcxq %rax, %r12
        adoxq %rbx, %r13
        mulxq 0x18(%rsi), %rax, %rbx
        adcxq %rax, %r13
        adoxq %rbx, %r14
        mulxq 0x20(%rsi), %rax, %rbx
        adcxq %rax, %r14
        adoxq %rbx, %r15
        mulxq 0x28(%rsi), %rax, %rbx
        adcxq %rax, %r15
        adoxq %rbx, %r8
        mulxq 0x30(%rsi), %rax, %rbx
        adcxq %rax, %r8
        adoxq %rbx, %r9
        mulxq 0x38(%rsi), %rax, %r10
        adcxq %rax, %r9
        adoxq %rbp, %r10
        adcq %rbp, %r10
        movq 0x18(%rcx), %rdx
        xorl %ebp, %ebp
        mulxq (%rsi), %rax, %rbx
        adcxq %rax, %r11
        adoxq %rbx, %r12
        movq %r11, 0x18(%rsp)
        mulxq 0x8(%rsi), %rax, %rbx
        adcxq %rax, %r12
        adoxq %rbx, %r13
        mulxq 0x10(%rsi), %rax, %rbx
        adcxq %rax, %r13
        adoxq %rbx, %r14
        mulxq 0x18(%rsi), %rax, %rbx
        adcxq %rax, %r14
        adoxq %rbx, %r15
        mulxq 0x20(%rsi), %rax, %rbx
        adcxq %rax, %r15
        adoxq %rbx, %r8
        mulxq 0x28(%rsi), %rax, %rbx
        adcxq %rax, %r8
        adoxq %rbx, %r9
        mulxq 0x30(%rsi), %rax, %rbx
        adcxq %rax, %r9
        adoxq %rbx, %r10
        mulxq 0x38(%rsi), %rax, %r11
        adcxq %rax, %r10
        adoxq %rbp, %r11
        adcq %rbp, %r11
        movq 0x20(%rcx), %rdx
        xorl %ebp, %ebp
        mulxq (%rsi), %rax, %rbx
        adcxq %rax, %r12
        adoxq %rbx, %r13
        movq %r12, 0x20(%rsp)
        mulxq 0x8(%rsi), %rax, %rbx
        adcxq %rax, %r13
        adoxq %rbx, %r14
        mulxq 0x10(%rsi), %rax, %rbx
        adcxq %rax, %r14
        adoxq %rbx, %r15
        mulxq 0x18(%rsi), %rax, %rbx
        adcxq %rax, %r15
        adoxq %rbx, %r8
        mulxq 0x20(%rsi), %rax, %rbx
        adcxq %rax, %r8
        adoxq %rbx, %r9
        mulxq 0x28(%rsi), %rax, %rbx
        adcxq %rax, %r9
        adoxq %rbx, %r10
        mulxq 0x30(%rsi), %rax, %rbx
        adcxq %rax, %r10
        adoxq %rbx, %r11
        mulxq 0x38(%rsi), %rax, %r12
        adcxq %rax, %r11
        adoxq %rbp, %r12
        adcq %rbp, %r12
        movq 0x28(%rcx), %rdx
        xorl %ebp, %ebp
        mulxq (%rsi), %rax, %rbx
        adcxq %rax, %r13
        adoxq %rbx, %r14
        movq %r13, 0x28(%rsp)
        mulxq 0x8(%rsi), %rax, %rbx
        adcxq %rax, %r14
        adoxq %rbx, %r15
        mulxq 0x10(%rsi), %rax, %rbx
        adcxq %rax, %r15
        adoxq %rbx, %r8
        mulxq 0x18(%rsi), %rax, %rbx
        adcxq %rax, %r8
        adoxq %rbx, %r9
        mulxq 0x20(%rsi), %rax, %rbx
        adcxq %rax, %r9
        adoxq %rbx, %r10
        mulxq 0x28(%rsi), %rax, %rbx
        adcxq %rax, %r10
        adoxq %rbx, %r11
        mulxq 0x30(%rsi), %rax, %rbx
        adcxq %rax, %r11
        adoxq %rbx, %r12
        mulxq 0x38(%rsi), %rax, %r13
        adcxq %rax, %r12
        adoxq %rbp, %r13
        adcq %rbp, %r13
        movq 0x30(%rcx), %rdx
        xorl %ebp, %ebp
        mulxq (%rsi), %rax, %rbx
        adcxq %rax, %r14
        adoxq %rbx, %r15
        movq %r14, 0x30(%rsp)
        mulxq 0x8(%rsi), %rax, %rbx
        adcxq %rax, %r15
        adoxq %rbx, %r8
        mulxq 0x10(%rsi), %rax, %rbx
        adcxq %rax, %r8
        adoxq %rbx, %r9
        mulxq 0x18(%rsi), %rax, %rbx
        adcxq %rax, %r9
        adoxq %rbx, %r10
        mulxq 0x20(%rsi), %rax, %rbx
        adcxq %rax, %r10
        adoxq %rbx, %r11
        mulxq 0x28(%rsi), %rax, %rbx
        adcxq %rax, %r11
        adoxq %rbx, %r12
        mulxq 0x30(%rsi), %rax, %rbx
        adcxq %rax, %r12
        adoxq %rbx, %r13
        mulxq 0x38(%rsi), %rax, %r14
        adcxq %rax, %r13
        adoxq %rbp, %r14
        adcq %rbp, %r14
        movq 0x38(%rcx), %rdx
        xorl %ebp, %ebp
        mulxq (%rsi), %rax, %rbx
        adcxq %rax, %r15
        adoxq %rbx, %r8
        movq %r15, 0x38(%rsp)
        mulxq 0x8(%rsi), %rax, %rbx
        adcxq %rax, %r8
        adoxq %rbx, %r9
        mulxq 0x10(%rsi), %rax, %rbx
        adcxq %rax, %r9
        adoxq %rbx, %r10
        mulxq 0x18(%rsi), %rax, %rbx
        adcxq %rax, %r10
        adoxq %rbx, %r11
        mulxq 0x20(%rsi), %rax, %rbx
        adcxq %rax, %r11
        adoxq %rbx, %r12
        mulxq 0x28(%rsi), %rax, %rbx
        adcxq %rax, %r12
        adoxq %rbx, %r13
        mulxq 0x30(%rsi), %rax, %rbx
        adcxq %rax, %r13
        adoxq %rbx, %r14
        mulxq 0x38(%rsi), %rax, %r15
        adcxq %rax, %r14
        adoxq %rbp, %r15
        adcq %rbp, %r15



        movq 64(%rsi), %rdx
        xorl %ebp, %ebp
        mulxq (%rcx), %rax, %rbx 
 adcxq %rax, %r8 
 adoxq %rbx, %r9
        mulxq 8(%rcx), %rax, %rbx 
 adcxq %rax, %r9 
 adoxq %rbx, %r10
        mulxq 16(%rcx), %rax, %rbx 
 adcxq %rax, %r10 
 adoxq %rbx, %r11
        mulxq 24(%rcx), %rax, %rbx 
 adcxq %rax, %r11 
 adoxq %rbx, %r12
        mulxq 32(%rcx), %rax, %rbx 
 adcxq %rax, %r12 
 adoxq %rbx, %r13
        mulxq 40(%rcx), %rax, %rbx 
 adcxq %rax, %r13 
 adoxq %rbx, %r14
        mulxq 48(%rcx), %rax, %rbx 
 adcxq %rax, %r14 
 adoxq %rbx, %r15
        mulxq 56(%rcx), %rax, %rbx
        adcxq %rax, %r15
        adoxq %rbp, %rbx
        adcq %rbx, %rbp



        movq 64(%rcx), %rdx
        xorl %eax, %eax
        mulxq (%rsi), %rax, %rbx 
 adcxq %rax, %r8 
 adoxq %rbx, %r9
        mulxq 8(%rsi), %rax, %rbx 
 adcxq %rax, %r9 
 adoxq %rbx, %r10
        mulxq 16(%rsi), %rax, %rbx 
 adcxq %rax, %r10 
 adoxq %rbx, %r11
        mulxq 24(%rsi), %rax, %rbx 
 adcxq %rax, %r11 
 adoxq %rbx, %r12
        mulxq 32(%rsi), %rax, %rbx 
 adcxq %rax, %r12 
 adoxq %rbx, %r13
        mulxq 40(%rsi), %rax, %rbx 
 adcxq %rax, %r13 
 adoxq %rbx, %r14
        mulxq 48(%rsi), %rax, %rbx 
 adcxq %rax, %r14 
 adoxq %rbx, %r15
        mulxq 56(%rsi), %rax, %rbx
        adcxq %rax, %r15
        adoxq %rbx, %rbp
        mulxq 64(%rsi), %rax, %rbx
        adcq %rax, %rbp




        movq %r8, %rax
        andq $0x1FF, %rax
        shrdq $9, %r9, %r8
        shrdq $9, %r10, %r9
        shrdq $9, %r11, %r10
        shrdq $9, %r12, %r11
        shrdq $9, %r13, %r12
        shrdq $9, %r14, %r13
        shrdq $9, %r15, %r14
        shrdq $9, %rbp, %r15
        shrq $9, %rbp
        addq %rax, %rbp




        stc
        adcq (%rsp), %r8
        adcq 8(%rsp), %r9
        adcq 16(%rsp), %r10
        adcq 24(%rsp), %r11
        adcq 32(%rsp), %r12
        adcq 40(%rsp), %r13
        adcq 48(%rsp), %r14
        adcq 56(%rsp), %r15
        adcq $~0x1FF, %rbp







        cmc
        sbbq $0, %r8
        movq %r8, (%rdi)
        sbbq $0, %r9
        movq %r9, 8(%rdi)
        sbbq $0, %r10
        movq %r10, 16(%rdi)
        sbbq $0, %r11
        movq %r11, 24(%rdi)
        sbbq $0, %r12
        movq %r12, 32(%rdi)
        sbbq $0, %r13
        movq %r13, 40(%rdi)
        sbbq $0, %r14
        movq %r14, 48(%rdi)
        sbbq $0, %r15
        movq %r15, 56(%rdi)
        sbbq $0, %rbp
        andq $0x1FF, %rbp
        movq %rbp, 64(%rdi)



        addq $64, %rsp
        popq %r15
        popq %r14
        popq %r13
        popq %r12
        popq %rbx
        popq %rbp





        ret


.section .note.GNU-stack,"",%progbits
