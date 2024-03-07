# 0 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_sqr_p521_alt.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_sqr_p521_alt.S"
# 14 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_sqr_p521_alt.S"
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/include/_internal_s2n_bignum.h" 1
# 15 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_sqr_p521_alt.S" 2


        .globl bignum_sqr_p521_alt
        .hidden bignum_sqr_p521_alt
        .text
# 83 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_sqr_p521_alt.S"
bignum_sqr_p521_alt:
# 94 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_sqr_p521_alt.S"
        pushq %rbx
        pushq %r12
        pushq %r13
        pushq %r14
        pushq %r15
        subq $72, %rsp





        movq (%rsi), %rax
        mulq %rax

        movq %rax, (%rsp)
        movq %rdx, %r9
        xorq %r10, %r10



        xorq %r11, %r11
        movq (%rsi), %rax 
 mulq 8(%rsi)
 addq %rax, %rax 
 adcq %rdx, %rdx 
 adcq $0, %r11 
 addq %rax, %r9 
 adcq %rdx, %r10 
 adcq $0, %r11
        movq %r9, 8(%rsp)



        xorq %r12, %r12
        movq 8(%rsi), %rax 
 mulq %rax
 addq %rax, %r10 
 adcq %rdx, %r11 
 adcq $0, %r12
        movq (%rsi), %rax 
 mulq 16(%rsi)
 addq %rax, %rax 
 adcq %rdx, %rdx 
 adcq $0, %r12 
 addq %rax, %r10 
 adcq %rdx, %r11 
 adcq $0, %r12
        movq %r10, 16(%rsp)



        movq (%rsi), %rax 
 mulq 24(%rsi)
 xorq %r13, %r13 
 movq %rax, %rbx 
 movq %rdx, %rcx
        movq 8(%rsi), %rax 
 mulq 16(%rsi)
 addq %rax, %rbx 
 adcq %rdx, %rcx 
 adcq $0, %r13
        addq %rbx, %rbx 
 adcq %rcx, %rcx 
 adcq %r13, %r13 
 addq %rbx, %r11 
 adcq %rcx, %r12 
 adcq $0, %r13
        movq %r11, 24(%rsp)



        movq (%rsi), %rax 
 mulq 32(%rsi)
 xorq %r14, %r14 
 movq %rax, %rbx 
 movq %rdx, %rcx
        movq 8(%rsi), %rax 
 mulq 24(%rsi)
 addq %rax, %rbx 
 adcq %rdx, %rcx 
 adcq $0, %r14
        addq %rbx, %rbx 
 adcq %rcx, %rcx 
 adcq %r14, %r14 
 addq %rbx, %r12 
 adcq %rcx, %r13 
 adcq $0, %r14
        movq 16(%rsi), %rax 
 mulq %rax
 addq %rax, %r12 
 adcq %rdx, %r13 
 adcq $0, %r14
        movq %r12, 32(%rsp)



        movq (%rsi), %rax 
 mulq 40(%rsi)
 xorq %r15, %r15 
 movq %rax, %rbx 
 movq %rdx, %rcx
        movq 8(%rsi), %rax 
 mulq 32(%rsi)
 addq %rax, %rbx 
 adcq %rdx, %rcx 
 adcq $0, %r15
        movq 16(%rsi), %rax 
 mulq 24(%rsi)
 addq %rax, %rbx 
 adcq %rdx, %rcx 
 adcq $0, %r15
        addq %rbx, %rbx 
 adcq %rcx, %rcx 
 adcq %r15, %r15 
 addq %rbx, %r13 
 adcq %rcx, %r14 
 adcq $0, %r15
        movq %r13, 40(%rsp)



        movq (%rsi), %rax 
 mulq 48(%rsi)
 xorq %r8, %r8 
 movq %rax, %rbx 
 movq %rdx, %rcx
        movq 8(%rsi), %rax 
 mulq 40(%rsi)
 addq %rax, %rbx 
 adcq %rdx, %rcx 
 adcq $0, %r8
        movq 16(%rsi), %rax 
 mulq 32(%rsi)
 addq %rax, %rbx 
 adcq %rdx, %rcx 
 adcq $0, %r8
        addq %rbx, %rbx 
 adcq %rcx, %rcx 
 adcq %r8, %r8 
 addq %rbx, %r14 
 adcq %rcx, %r15 
 adcq $0, %r8
        movq 24(%rsi), %rax 
 mulq %rax
 addq %rax, %r14 
 adcq %rdx, %r15 
 adcq $0, %r8
        movq %r14, 48(%rsp)



        movq (%rsi), %rax 
 mulq 56(%rsi)
 xorq %r9, %r9 
 movq %rax, %rbx 
 movq %rdx, %rcx
        movq 8(%rsi), %rax 
 mulq 48(%rsi)
 addq %rax, %rbx 
 adcq %rdx, %rcx 
 adcq $0, %r9
        movq 16(%rsi), %rax 
 mulq 40(%rsi)
 addq %rax, %rbx 
 adcq %rdx, %rcx 
 adcq $0, %r9
        movq 24(%rsi), %rax 
 mulq 32(%rsi)
 addq %rax, %rbx 
 adcq %rdx, %rcx 
 adcq $0, %r9
        addq %rbx, %rbx 
 adcq %rcx, %rcx 
 adcq %r9, %r9 
 addq %rbx, %r15 
 adcq %rcx, %r8 
 adcq $0, %r9
        movq %r15, 56(%rsp)



        movq (%rsi), %rax 
 mulq 64(%rsi)
 xorq %r10, %r10 
 movq %rax, %rbx 
 movq %rdx, %rcx
        movq 8(%rsi), %rax 
 mulq 56(%rsi)
 addq %rax, %rbx 
 adcq %rdx, %rcx 
 adcq $0, %r10
        movq 16(%rsi), %rax 
 mulq 48(%rsi)
 addq %rax, %rbx 
 adcq %rdx, %rcx 
 adcq $0, %r10
        movq 24(%rsi), %rax 
 mulq 40(%rsi)
 addq %rax, %rbx 
 adcq %rdx, %rcx 
 adcq $0, %r10
        addq %rbx, %rbx 
 adcq %rcx, %rcx 
 adcq %r10, %r10 
 addq %rbx, %r8 
 adcq %rcx, %r9 
 adcq $0, %r10
        movq 32(%rsi), %rax 
 mulq %rax
 addq %rax, %r8 
 adcq %rdx, %r9 
 adcq $0, %r10
        movq %r8, 64(%rsp)




        movq 8(%rsi), %rax 
 mulq 64(%rsi)
 xorq %r11, %r11 
 movq %rax, %rbx 
 movq %rdx, %rcx
        movq 16(%rsi), %rax 
 mulq 56(%rsi)
 addq %rax, %rbx 
 adcq %rdx, %rcx 
 adcq $0, %r11
        movq 24(%rsi), %rax 
 mulq 48(%rsi)
 addq %rax, %rbx 
 adcq %rdx, %rcx 
 adcq $0, %r11
        movq 32(%rsi), %rax 
 mulq 40(%rsi)
 addq %rax, %rbx 
 adcq %rdx, %rcx 
 adcq $0, %r11
        addq %rbx, %rbx 
 adcq %rcx, %rcx 
 adcq %r11, %r11 
 addq %rbx, %r9 
 adcq %rcx, %r10 
 adcq $0, %r11



        movq 16(%rsi), %rax 
 mulq 64(%rsi)
 xorq %r12, %r12 
 movq %rax, %rbx 
 movq %rdx, %rcx
        movq 24(%rsi), %rax 
 mulq 56(%rsi)
 addq %rax, %rbx 
 adcq %rdx, %rcx 
 adcq $0, %r12
        movq 32(%rsi), %rax 
 mulq 48(%rsi)
 addq %rax, %rbx 
 adcq %rdx, %rcx 
 adcq $0, %r12
        addq %rbx, %rbx 
 adcq %rcx, %rcx 
 adcq %r12, %r12 
 addq %rbx, %r10 
 adcq %rcx, %r11 
 adcq $0, %r12
        movq 40(%rsi), %rax 
 mulq %rax
 addq %rax, %r10 
 adcq %rdx, %r11 
 adcq $0, %r12



        movq 24(%rsi), %rax 
 mulq 64(%rsi)
 xorq %r13, %r13 
 movq %rax, %rbx 
 movq %rdx, %rcx
        movq 32(%rsi), %rax 
 mulq 56(%rsi)
 addq %rax, %rbx 
 adcq %rdx, %rcx 
 adcq $0, %r13
        movq 40(%rsi), %rax 
 mulq 48(%rsi)
 addq %rax, %rbx 
 adcq %rdx, %rcx 
 adcq $0, %r13
        addq %rbx, %rbx 
 adcq %rcx, %rcx 
 adcq %r13, %r13 
 addq %rbx, %r11 
 adcq %rcx, %r12 
 adcq $0, %r13



        movq 32(%rsi), %rax 
 mulq 64(%rsi)
 xorq %r14, %r14 
 movq %rax, %rbx 
 movq %rdx, %rcx
        movq 40(%rsi), %rax 
 mulq 56(%rsi)
 addq %rax, %rbx 
 adcq %rdx, %rcx 
 adcq $0, %r14
        addq %rbx, %rbx 
 adcq %rcx, %rcx 
 adcq %r14, %r14 
 addq %rbx, %r12 
 adcq %rcx, %r13 
 adcq $0, %r14
        movq 48(%rsi), %rax 
 mulq %rax
 addq %rax, %r12 
 adcq %rdx, %r13 
 adcq $0, %r14



        movq 40(%rsi), %rax 
 mulq 64(%rsi)
 xorq %r15, %r15 
 movq %rax, %rbx 
 movq %rdx, %rcx
        movq 48(%rsi), %rax 
 mulq 56(%rsi)
 addq %rax, %rbx 
 adcq %rdx, %rcx 
 adcq $0, %r15
        addq %rbx, %rbx 
 adcq %rcx, %rcx 
 adcq %r15, %r15 
 addq %rbx, %r13 
 adcq %rcx, %r14 
 adcq $0, %r15




        xorq %r8, %r8
        movq 56(%rsi), %rax 
 mulq %rax
 addq %rax, %r14 
 adcq %rdx, %r15 
 adcq $0, %r8
        movq 48(%rsi), %rax 
 mulq 64(%rsi)
 addq %rax, %rax 
 adcq %rdx, %rdx 
 adcq $0, %r8 
 addq %rax, %r14 
 adcq %rdx, %r15 
 adcq $0, %r8



        movq 56(%rsi), %rax
        mulq 64(%rsi)
        addq %rax, %rax
        adcq %rdx, %rdx
        addq %rax, %r15
        adcq %rdx, %r8



        movq 64(%rsi), %rax
        imulq %rax, %rax
        addq %r8, %rax





        movq 64(%rsp), %r8
        movq %r8, %rdx
        andq $0x1FF, %rdx
        shrdq $9, %r9, %r8
        shrdq $9, %r10, %r9
        shrdq $9, %r11, %r10
        shrdq $9, %r12, %r11
        shrdq $9, %r13, %r12
        shrdq $9, %r14, %r13
        shrdq $9, %r15, %r14
        shrdq $9, %rax, %r15
        shrq $9, %rax
        addq %rax, %rdx




        stc
        adcq (%rsp), %r8
        adcq 8(%rsp), %r9
        adcq 16(%rsp), %r10
        adcq 24(%rsp), %r11
        adcq 32(%rsp), %r12
        adcq 40(%rsp), %r13
        adcq 48(%rsp), %r14
        adcq 56(%rsp), %r15
        adcq $~0x1FF, %rdx







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
        sbbq $0, %rdx
        andq $0x1FF, %rdx
        movq %rdx, 64(%rdi)



        addq $72, %rsp
        popq %r15
        popq %r14
        popq %r13
        popq %r12
        popq %rbx




        ret


.section .note.GNU-stack,"",%progbits
