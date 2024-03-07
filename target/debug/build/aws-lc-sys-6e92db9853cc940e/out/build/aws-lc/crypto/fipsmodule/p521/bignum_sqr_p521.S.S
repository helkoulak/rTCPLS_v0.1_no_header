# 0 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_sqr_p521.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_sqr_p521.S"
# 14 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_sqr_p521.S"
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/include/_internal_s2n_bignum.h" 1
# 15 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_sqr_p521.S" 2


        .globl bignum_sqr_p521
        .hidden bignum_sqr_p521
        .text
# 48 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_sqr_p521.S"
bignum_sqr_p521:
# 59 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_sqr_p521.S"
        pushq %rbp
        pushq %r12
        pushq %r13
        pushq %r14
        pushq %r15
        subq $64, %rsp





        xorl %ebp, %ebp

        movq (%rsi), %rdx
        mulxq 8(%rsi), %r9, %rax
        movq %r9, 8(%rsp)
        mulxq 16(%rsi), %r10, %rcx
        adcxq %rax, %r10
        movq %r10, 16(%rsp)
        mulxq 24(%rsi), %r11, %rax
        adcxq %rcx, %r11
        mulxq 32(%rsi), %r12, %rcx
        adcxq %rax, %r12
        mulxq 40(%rsi), %r13, %rax
        adcxq %rcx, %r13
        mulxq 48(%rsi), %r14, %rcx
        adcxq %rax, %r14
        mulxq 56(%rsi), %r15, %r8
        adcxq %rcx, %r15
        adcxq %rbp, %r8

        xorl %ebp, %ebp
        movq 8(%rsi), %rdx
        mulxq 16(%rsi), %rax, %rcx 
 adcxq %rax, %r11 
 adoxq %rcx, %r12
        movq %r11, 24(%rsp)
        mulxq 24(%rsi), %rax, %rcx 
 adcxq %rax, %r12 
 adoxq %rcx, %r13
        movq %r12, 32(%rsp)
        mulxq 32(%rsi), %rax, %rcx 
 adcxq %rax, %r13 
 adoxq %rcx, %r14
        mulxq 40(%rsi), %rax, %rcx 
 adcxq %rax, %r14 
 adoxq %rcx, %r15
        mulxq 48(%rsi), %rax, %rcx 
 adcxq %rax, %r15 
 adoxq %rcx, %r8
        mulxq 56(%rsi), %rax, %r9 
 adcxq %rax, %r8 
 adoxq %rbp, %r9
        movq 32(%rsi), %rdx
        mulxq 40(%rsi), %rax, %r10 
 adcxq %rax, %r9 
 adoxq %rbp, %r10
        adcxq %rbp, %r10

        xorl %ebp, %ebp
        movq 16(%rsi), %rdx
        mulxq 24(%rsi), %rax, %rcx 
 adcxq %rax, %r13 
 adoxq %rcx, %r14
        movq %r13, 40(%rsp)
        mulxq 32(%rsi), %rax, %rcx 
 adcxq %rax, %r14 
 adoxq %rcx, %r15
        movq %r14, 48(%rsp)
        mulxq 40(%rsi), %rax, %rcx 
 adcxq %rax, %r15 
 adoxq %rcx, %r8
        mulxq 48(%rsi), %rax, %rcx 
 adcxq %rax, %r8 
 adoxq %rcx, %r9
        mulxq 56(%rsi), %rax, %rcx 
 adcxq %rax, %r9 
 adoxq %rcx, %r10
        movq 48(%rsi), %rdx
        mulxq 32(%rsi), %rax, %r11 
 adcxq %rax, %r10 
 adoxq %rbp, %r11
        mulxq 40(%rsi), %rax, %r12 
 adcxq %rax, %r11 
 adoxq %rbp, %r12
        adcxq %rbp, %r12

        xorl %ebp, %ebp
        movq 24(%rsi), %rdx
        mulxq 32(%rsi), %rax, %rcx 
 adcxq %rax, %r15 
 adoxq %rcx, %r8
        movq %r15, 56(%rsp)
        mulxq 40(%rsi), %rax, %rcx 
 adcxq %rax, %r8 
 adoxq %rcx, %r9
        mulxq 48(%rsi), %rax, %rcx 
 adcxq %rax, %r9 
 adoxq %rcx, %r10
        mulxq 56(%rsi), %rax, %rcx 
 adcxq %rax, %r10 
 adoxq %rcx, %r11
        movq 56(%rsi), %rdx
        mulxq 32(%rsi), %rax, %rcx 
 adcxq %rax, %r11 
 adoxq %rcx, %r12
        mulxq 40(%rsi), %rax, %r13 
 adcxq %rax, %r12 
 adoxq %rbp, %r13
        mulxq 48(%rsi), %rax, %r14 
 adcxq %rax, %r13 
 adoxq %rbp, %r14
        adcxq %rbp, %r14

        xorl %ebp, %ebp
        movq (%rsi), %rdx
        mulxq %rdx, %rax, %rcx
        movq %rax, (%rsp)
        movq 8(%rsp), %rax
        adcxq %rax, %rax
        adoxq %rcx, %rax
        movq %rax, 8(%rsp)

        movq 16(%rsp), %rax
        movq 8(%rsi), %rdx
        mulxq %rdx, %rdx, %rcx
        adcxq %rax, %rax
        adoxq %rdx, %rax
        movq %rax, 16(%rsp)
        movq 24(%rsp), %rax
        adcxq %rax, %rax
        adoxq %rcx, %rax
        movq %rax, 24(%rsp)

        movq 32(%rsp), %rax
        movq 16(%rsi), %rdx
        mulxq %rdx, %rdx, %rcx
        adcxq %rax, %rax
        adoxq %rdx, %rax
        movq %rax, 32(%rsp)
        movq 40(%rsp), %rax
        adcxq %rax, %rax
        adoxq %rcx, %rax
        movq %rax, 40(%rsp)

        movq 48(%rsp), %rax
        movq 24(%rsi), %rdx
        mulxq %rdx, %rdx, %rcx
        adcxq %rax, %rax
        adoxq %rdx, %rax
        movq %rax, 48(%rsp)
        movq 56(%rsp), %rax
        adcxq %rax, %rax
        adoxq %rcx, %rax
        movq %rax, 56(%rsp)

        movq 32(%rsi), %rdx
        mulxq %rdx, %rdx, %rcx
        adcxq %r8, %r8
        adoxq %rdx, %r8
        adcxq %r9, %r9
        adoxq %rcx, %r9

        movq 40(%rsi), %rdx
        mulxq %rdx, %rdx, %rcx
        adcxq %r10, %r10
        adoxq %rdx, %r10
        adcxq %r11, %r11
        adoxq %rcx, %r11

        movq 48(%rsi), %rdx
        mulxq %rdx, %rdx, %rcx
        adcxq %r12, %r12
        adoxq %rdx, %r12
        adcxq %r13, %r13
        adoxq %rcx, %r13

        movq 56(%rsi), %rdx
        mulxq %rdx, %rdx, %r15
        adcxq %r14, %r14
        adoxq %rdx, %r14
        adcxq %rbp, %r15
        adoxq %rbp, %r15







        movq 64(%rsi), %rdx
        movq %rdx, %rbp
        imulq %rbp, %rbp
        addq %rdx, %rdx
        mulxq 0(%rsi), %rax, %rcx 
 adcxq %rax, %r8 
 adoxq %rcx, %r9
        mulxq 8(%rsi), %rax, %rcx 
 adcxq %rax, %r9 
 adoxq %rcx, %r10
        mulxq 16(%rsi), %rax, %rcx 
 adcxq %rax, %r10 
 adoxq %rcx, %r11
        mulxq 24(%rsi), %rax, %rcx 
 adcxq %rax, %r11 
 adoxq %rcx, %r12
        mulxq 32(%rsi), %rax, %rcx 
 adcxq %rax, %r12 
 adoxq %rcx, %r13
        mulxq 40(%rsi), %rax, %rcx 
 adcxq %rax, %r13 
 adoxq %rcx, %r14
        mulxq 48(%rsi), %rax, %rcx 
 adcxq %rax, %r14 
 adoxq %rcx, %r15
        mulxq 56(%rsi), %rax, %rcx
        adcxq %rax, %r15
        adoxq %rcx, %rbp
        adcq $0, %rbp




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
        popq %rbp





        ret


.section .note.GNU-stack,"",%progbits
