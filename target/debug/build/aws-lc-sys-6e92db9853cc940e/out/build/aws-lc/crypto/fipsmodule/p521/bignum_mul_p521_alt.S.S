# 0 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_mul_p521_alt.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_mul_p521_alt.S"
# 15 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_mul_p521_alt.S"
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/include/_internal_s2n_bignum.h" 1
# 16 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_mul_p521_alt.S" 2


        .globl bignum_mul_p521_alt
        .hidden bignum_mul_p521_alt
        .text
# 55 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_mul_p521_alt.S"
bignum_mul_p521_alt:
# 67 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_mul_p521_alt.S"
        pushq %r12
        pushq %r13
        pushq %r14
        pushq %r15
        subq $72, %rsp



        movq %rdx, %rcx



        mov %rdx, %rcx





        movq (%rsi), %rax
        mulq (%rcx)

        movq %rax, (%rsp)
        movq %rdx, %r9
        xorq %r10, %r10



        xorq %r11, %r11
        movq (%rsi), %rax 
 mulq 8(%rcx)
 addq %rax, %r9 
 adcq %rdx, %r10
        movq 8(%rsi), %rax 
 mulq (%rcx)
 addq %rax, %r9 
 adcq %rdx, %r10 
 adcq %r11, %r11
        movq %r9, 8(%rsp)



        xorq %r12, %r12
        movq (%rsi), %rax 
 mulq 16(%rcx)
 addq %rax, %r10 
 adcq %rdx, %r11 
 adcq %r12, %r12
        movq 8(%rsi), %rax 
 mulq 8(%rcx)
 addq %rax, %r10 
 adcq %rdx, %r11 
 adcq $0, %r12
        movq 16(%rsi), %rax 
 mulq (%rcx)
 addq %rax, %r10 
 adcq %rdx, %r11 
 adcq $0, %r12
        movq %r10, 16(%rsp)



        xorq %r13, %r13
        movq (%rsi), %rax 
 mulq 24(%rcx)
 addq %rax, %r11 
 adcq %rdx, %r12 
 adcq %r13, %r13
        movq 8(%rsi), %rax 
 mulq 16(%rcx)
 addq %rax, %r11 
 adcq %rdx, %r12 
 adcq $0, %r13
        movq 16(%rsi), %rax 
 mulq 8(%rcx)
 addq %rax, %r11 
 adcq %rdx, %r12 
 adcq $0, %r13
        movq 24(%rsi), %rax 
 mulq (%rcx)
 addq %rax, %r11 
 adcq %rdx, %r12 
 adcq $0, %r13
        movq %r11, 24(%rsp)



        xorq %r14, %r14
        movq (%rsi), %rax 
 mulq 32(%rcx)
 addq %rax, %r12 
 adcq %rdx, %r13 
 adcq %r14, %r14
        movq 8(%rsi), %rax 
 mulq 24(%rcx)
 addq %rax, %r12 
 adcq %rdx, %r13 
 adcq $0, %r14
        movq 16(%rsi), %rax 
 mulq 16(%rcx)
 addq %rax, %r12 
 adcq %rdx, %r13 
 adcq $0, %r14
        movq 24(%rsi), %rax 
 mulq 8(%rcx)
 addq %rax, %r12 
 adcq %rdx, %r13 
 adcq $0, %r14
        movq 32(%rsi), %rax 
 mulq (%rcx)
 addq %rax, %r12 
 adcq %rdx, %r13 
 adcq $0, %r14
        movq %r12, 32(%rsp)



        xorq %r15, %r15
        movq (%rsi), %rax 
 mulq 40(%rcx)
 addq %rax, %r13 
 adcq %rdx, %r14 
 adcq %r15, %r15
        movq 8(%rsi), %rax 
 mulq 32(%rcx)
 addq %rax, %r13 
 adcq %rdx, %r14 
 adcq $0, %r15
        movq 16(%rsi), %rax 
 mulq 24(%rcx)
 addq %rax, %r13 
 adcq %rdx, %r14 
 adcq $0, %r15
        movq 24(%rsi), %rax 
 mulq 16(%rcx)
 addq %rax, %r13 
 adcq %rdx, %r14 
 adcq $0, %r15
        movq 32(%rsi), %rax 
 mulq 8(%rcx)
 addq %rax, %r13 
 adcq %rdx, %r14 
 adcq $0, %r15
        movq 40(%rsi), %rax 
 mulq (%rcx)
 addq %rax, %r13 
 adcq %rdx, %r14 
 adcq $0, %r15
        movq %r13, 40(%rsp)



        xorq %r8, %r8
        movq (%rsi), %rax 
 mulq 48(%rcx)
 addq %rax, %r14 
 adcq %rdx, %r15 
 adcq %r8, %r8
        movq 8(%rsi), %rax 
 mulq 40(%rcx)
 addq %rax, %r14 
 adcq %rdx, %r15 
 adcq $0, %r8
        movq 16(%rsi), %rax 
 mulq 32(%rcx)
 addq %rax, %r14 
 adcq %rdx, %r15 
 adcq $0, %r8
        movq 24(%rsi), %rax 
 mulq 24(%rcx)
 addq %rax, %r14 
 adcq %rdx, %r15 
 adcq $0, %r8
        movq 32(%rsi), %rax 
 mulq 16(%rcx)
 addq %rax, %r14 
 adcq %rdx, %r15 
 adcq $0, %r8
        movq 40(%rsi), %rax 
 mulq 8(%rcx)
 addq %rax, %r14 
 adcq %rdx, %r15 
 adcq $0, %r8
        movq 48(%rsi), %rax 
 mulq (%rcx)
 addq %rax, %r14 
 adcq %rdx, %r15 
 adcq $0, %r8
        movq %r14, 48(%rsp)



        xorq %r9, %r9
        movq (%rsi), %rax 
 mulq 56(%rcx)
 addq %rax, %r15 
 adcq %rdx, %r8 
 adcq %r9, %r9
        movq 8(%rsi), %rax 
 mulq 48(%rcx)
 addq %rax, %r15 
 adcq %rdx, %r8 
 adcq $0, %r9
        movq 16(%rsi), %rax 
 mulq 40(%rcx)
 addq %rax, %r15 
 adcq %rdx, %r8 
 adcq $0, %r9
        movq 24(%rsi), %rax 
 mulq 32(%rcx)
 addq %rax, %r15 
 adcq %rdx, %r8 
 adcq $0, %r9
        movq 32(%rsi), %rax 
 mulq 24(%rcx)
 addq %rax, %r15 
 adcq %rdx, %r8 
 adcq $0, %r9
        movq 40(%rsi), %rax 
 mulq 16(%rcx)
 addq %rax, %r15 
 adcq %rdx, %r8 
 adcq $0, %r9
        movq 48(%rsi), %rax 
 mulq 8(%rcx)
 addq %rax, %r15 
 adcq %rdx, %r8 
 adcq $0, %r9
        movq 56(%rsi), %rax 
 mulq (%rcx)
 addq %rax, %r15 
 adcq %rdx, %r8 
 adcq $0, %r9
        movq %r15, 56(%rsp)



        xorq %r10, %r10
        movq (%rsi), %rax 
 mulq 64(%rcx)
 addq %rax, %r8 
 adcq %rdx, %r9 
 adcq %r10, %r10
        movq 8(%rsi), %rax 
 mulq 56(%rcx)
 addq %rax, %r8 
 adcq %rdx, %r9 
 adcq $0, %r10
        movq 16(%rsi), %rax 
 mulq 48(%rcx)
 addq %rax, %r8 
 adcq %rdx, %r9 
 adcq $0, %r10
        movq 24(%rsi), %rax 
 mulq 40(%rcx)
 addq %rax, %r8 
 adcq %rdx, %r9 
 adcq $0, %r10
        movq 32(%rsi), %rax 
 mulq 32(%rcx)
 addq %rax, %r8 
 adcq %rdx, %r9 
 adcq $0, %r10
        movq 40(%rsi), %rax 
 mulq 24(%rcx)
 addq %rax, %r8 
 adcq %rdx, %r9 
 adcq $0, %r10
        movq 48(%rsi), %rax 
 mulq 16(%rcx)
 addq %rax, %r8 
 adcq %rdx, %r9 
 adcq $0, %r10
        movq 56(%rsi), %rax 
 mulq 8(%rcx)
 addq %rax, %r8 
 adcq %rdx, %r9 
 adcq $0, %r10
        movq 64(%rsi), %rax 
 mulq (%rcx)
 addq %rax, %r8 
 adcq %rdx, %r9 
 adcq $0, %r10
        movq %r8, 64(%rsp)




        xorq %r11, %r11
        movq 8(%rsi), %rax 
 mulq 64(%rcx)
 addq %rax, %r9 
 adcq %rdx, %r10 
 adcq %r11, %r11
        movq 16(%rsi), %rax 
 mulq 56(%rcx)
 addq %rax, %r9 
 adcq %rdx, %r10 
 adcq $0, %r11
        movq 24(%rsi), %rax 
 mulq 48(%rcx)
 addq %rax, %r9 
 adcq %rdx, %r10 
 adcq $0, %r11
        movq 32(%rsi), %rax 
 mulq 40(%rcx)
 addq %rax, %r9 
 adcq %rdx, %r10 
 adcq $0, %r11
        movq 40(%rsi), %rax 
 mulq 32(%rcx)
 addq %rax, %r9 
 adcq %rdx, %r10 
 adcq $0, %r11
        movq 48(%rsi), %rax 
 mulq 24(%rcx)
 addq %rax, %r9 
 adcq %rdx, %r10 
 adcq $0, %r11
        movq 56(%rsi), %rax 
 mulq 16(%rcx)
 addq %rax, %r9 
 adcq %rdx, %r10 
 adcq $0, %r11
        movq 64(%rsi), %rax 
 mulq 8(%rcx)
 addq %rax, %r9 
 adcq %rdx, %r10 
 adcq $0, %r11



        xorq %r12, %r12
        movq 16(%rsi), %rax 
 mulq 64(%rcx)
 addq %rax, %r10 
 adcq %rdx, %r11 
 adcq %r12, %r12
        movq 24(%rsi), %rax 
 mulq 56(%rcx)
 addq %rax, %r10 
 adcq %rdx, %r11 
 adcq $0, %r12
        movq 32(%rsi), %rax 
 mulq 48(%rcx)
 addq %rax, %r10 
 adcq %rdx, %r11 
 adcq $0, %r12
        movq 40(%rsi), %rax 
 mulq 40(%rcx)
 addq %rax, %r10 
 adcq %rdx, %r11 
 adcq $0, %r12
        movq 48(%rsi), %rax 
 mulq 32(%rcx)
 addq %rax, %r10 
 adcq %rdx, %r11 
 adcq $0, %r12
        movq 56(%rsi), %rax 
 mulq 24(%rcx)
 addq %rax, %r10 
 adcq %rdx, %r11 
 adcq $0, %r12
        movq 64(%rsi), %rax 
 mulq 16(%rcx)
 addq %rax, %r10 
 adcq %rdx, %r11 
 adcq $0, %r12



        xorq %r13, %r13
        movq 24(%rsi), %rax 
 mulq 64(%rcx)
 addq %rax, %r11 
 adcq %rdx, %r12 
 adcq %r13, %r13
        movq 32(%rsi), %rax 
 mulq 56(%rcx)
 addq %rax, %r11 
 adcq %rdx, %r12 
 adcq $0, %r13
        movq 40(%rsi), %rax 
 mulq 48(%rcx)
 addq %rax, %r11 
 adcq %rdx, %r12 
 adcq $0, %r13
        movq 48(%rsi), %rax 
 mulq 40(%rcx)
 addq %rax, %r11 
 adcq %rdx, %r12 
 adcq $0, %r13
        movq 56(%rsi), %rax 
 mulq 32(%rcx)
 addq %rax, %r11 
 adcq %rdx, %r12 
 adcq $0, %r13
        movq 64(%rsi), %rax 
 mulq 24(%rcx)
 addq %rax, %r11 
 adcq %rdx, %r12 
 adcq $0, %r13



        xorq %r14, %r14
        movq 32(%rsi), %rax 
 mulq 64(%rcx)
 addq %rax, %r12 
 adcq %rdx, %r13 
 adcq %r14, %r14
        movq 40(%rsi), %rax 
 mulq 56(%rcx)
 addq %rax, %r12 
 adcq %rdx, %r13 
 adcq $0, %r14
        movq 48(%rsi), %rax 
 mulq 48(%rcx)
 addq %rax, %r12 
 adcq %rdx, %r13 
 adcq $0, %r14
        movq 56(%rsi), %rax 
 mulq 40(%rcx)
 addq %rax, %r12 
 adcq %rdx, %r13 
 adcq $0, %r14
        movq 64(%rsi), %rax 
 mulq 32(%rcx)
 addq %rax, %r12 
 adcq %rdx, %r13 
 adcq $0, %r14



        xorq %r15, %r15
        movq 40(%rsi), %rax 
 mulq 64(%rcx)
 addq %rax, %r13 
 adcq %rdx, %r14 
 adcq %r15, %r15
        movq 48(%rsi), %rax 
 mulq 56(%rcx)
 addq %rax, %r13 
 adcq %rdx, %r14 
 adcq $0, %r15
        movq 56(%rsi), %rax 
 mulq 48(%rcx)
 addq %rax, %r13 
 adcq %rdx, %r14 
 adcq $0, %r15
        movq 64(%rsi), %rax 
 mulq 40(%rcx)
 addq %rax, %r13 
 adcq %rdx, %r14 
 adcq $0, %r15



        xorq %r8, %r8
        movq 48(%rsi), %rax 
 mulq 64(%rcx)
 addq %rax, %r14 
 adcq %rdx, %r15 
 adcq %r8, %r8
        movq 56(%rsi), %rax 
 mulq 56(%rcx)
 addq %rax, %r14 
 adcq %rdx, %r15 
 adcq $0, %r8
        movq 64(%rsi), %rax 
 mulq 48(%rcx)
 addq %rax, %r14 
 adcq %rdx, %r15 
 adcq $0, %r8



        movq 56(%rsi), %rax 
 mulq 64(%rcx)
 addq %rax, %r15 
 adcq %rdx, %r8
        movq 64(%rsi), %rax 
 mulq 56(%rcx)
 addq %rax, %r15 
 adcq %rdx, %r8



        movq 64(%rsi), %rax
        imulq 64(%rcx), %rax
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




        ret


.section .note.GNU-stack,"",%progbits
