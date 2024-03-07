# 0 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_madd_n25519_alt.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_madd_n25519_alt.S"
# 21 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_madd_n25519_alt.S"
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/include/_internal_s2n_bignum.h" 1
# 22 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_madd_n25519_alt.S" 2


        .globl bignum_madd_n25519_alt
        .hidden bignum_madd_n25519_alt
        .text
# 97 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_madd_n25519_alt.S"
bignum_madd_n25519_alt:
# 110 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_madd_n25519_alt.S"
        pushq %rbx
        pushq %rbp
        pushq %r12
        pushq %r13
        pushq %r14
        pushq %r15





        movq %rdx, %rbp
        movq (%rsi), %rax
        mulq (%rbp)
        addq (%rcx), %rax
        adcq $0, %rdx
        movq %rax, %r8
        movq %rdx, %r9
        xorq %r10, %r10
        xorq %r11, %r11
        movq (%rsi), %rax
        mulq 0x8(%rbp)
        addq 8(%rcx), %rax
        adcq $0, %rdx
        addq %rax, %r9
        adcq %rdx, %r10
        movq 0x8(%rsi), %rax
        mulq (%rbp)
        addq %rax, %r9
        adcq %rdx, %r10
        adcq $0x0, %r11
        xorq %r12, %r12
        movq (%rsi), %rax
        mulq 0x10(%rbp)
        addq 16(%rcx), %rax
        adcq $0, %rdx
        addq %rax, %r10
        adcq %rdx, %r11
        adcq %r12, %r12
        movq 0x8(%rsi), %rax
        mulq 0x8(%rbp)
        addq %rax, %r10
        adcq %rdx, %r11
        adcq $0x0, %r12
        movq 0x10(%rsi), %rax
        mulq (%rbp)
        addq %rax, %r10
        adcq %rdx, %r11
        adcq $0x0, %r12
        xorq %r13, %r13
        movq (%rsi), %rax
        mulq 0x18(%rbp)
        addq 24(%rcx), %rax
        adcq $0, %rdx
        addq %rax, %r11
        adcq %rdx, %r12
        adcq %r13, %r13
        movq 0x8(%rsi), %rax
        mulq 0x10(%rbp)
        addq %rax, %r11
        adcq %rdx, %r12
        adcq $0x0, %r13
        movq 0x10(%rsi), %rax
        mulq 0x8(%rbp)
        addq %rax, %r11
        adcq %rdx, %r12
        adcq $0x0, %r13
        movq 0x18(%rsi), %rax
        mulq (%rbp)
        addq %rax, %r11
        adcq %rdx, %r12
        adcq $0x0, %r13
        xorq %r14, %r14
        movq 0x8(%rsi), %rax
        mulq 0x18(%rbp)
        addq %rax, %r12
        adcq %rdx, %r13
        adcq %r14, %r14
        movq 0x10(%rsi), %rax
        mulq 0x10(%rbp)
        addq %rax, %r12
        adcq %rdx, %r13
        adcq $0x0, %r14
        movq 0x18(%rsi), %rax
        mulq 0x8(%rbp)
        addq %rax, %r12
        adcq %rdx, %r13
        adcq $0x0, %r14
        xorq %r15, %r15
        movq 0x10(%rsi), %rax
        mulq 0x18(%rbp)
        addq %rax, %r13
        adcq %rdx, %r14
        adcq %r15, %r15
        movq 0x18(%rsi), %rax
        mulq 0x10(%rbp)
        addq %rax, %r13
        adcq %rdx, %r14
        adcq $0x0, %r15
        movq 0x18(%rsi), %rax
        mulq 0x18(%rbp)
        addq %rax, %r14
        adcq %rdx, %r15




        movq %r15, %rbx 
 shrq $60, %rbx 
 shlq $4, %r15 
 shrq $4, %r15 
 movabsq $0x5812631a5cf5d3ed, %rax 
 mulq %rbx
 movq %rax, %rbp 
 movq %rdx, %rcx 
 movabsq $0x14def9dea2f79cd6, %rax 
 mulq %rbx
 addq %rax, %rcx 
 adcq $0x0, %rdx 
 subq %rbp, %r12 
 sbbq %rcx, %r13 
 sbbq %rdx, %r14 
 sbbq $0x0, %r15 
 sbbq %rbx, %rbx 
 movabsq $0x5812631a5cf5d3ed, %rax 
 andq %rbx, %rax 
 movabsq $0x14def9dea2f79cd6, %rdx 
 andq %rbx, %rdx 
 movabsq $0x1000000000000000, %rbx 
 andq %rax, %rbx 
 addq %rax, %r12 
 adcq %rdx, %r13 
 adcq $0x0, %r14 
 adcq %rbx, %r15
        movq %r15, %rbx 
 shldq $0x4, %r14, %rbx 
 shrq $0x3c, %r15 
 subq %r15, %rbx 
 shlq $0x4, %r14 
 shrdq $0x4, %r15, %r14 
 movabsq $0x5812631a5cf5d3ed, %rax 
 mulq %rbx
 movq %rax, %rbp 
 movq %rdx, %rcx 
 movabsq $0x14def9dea2f79cd6, %rax 
 mulq %rbx
 addq %rax, %rcx 
 adcq $0x0, %rdx 
 subq %rbp, %r11 
 sbbq %rcx, %r12 
 sbbq %rdx, %r13 
 sbbq $0x0, %r14 
 sbbq %rbx, %rbx 
 movabsq $0x5812631a5cf5d3ed, %rax 
 andq %rbx, %rax 
 movabsq $0x14def9dea2f79cd6, %rdx 
 andq %rbx, %rdx 
 movabsq $0x1000000000000000, %rbx 
 andq %rax, %rbx 
 addq %rax, %r11 
 adcq %rdx, %r12 
 adcq $0x0, %r13 
 adcq %rbx, %r14
        movq %r14, %rbx 
 shldq $0x4, %r13, %rbx 
 shrq $0x3c, %r14 
 subq %r14, %rbx 
 shlq $0x4, %r13 
 shrdq $0x4, %r14, %r13 
 movabsq $0x5812631a5cf5d3ed, %rax 
 mulq %rbx
 movq %rax, %rbp 
 movq %rdx, %rcx 
 movabsq $0x14def9dea2f79cd6, %rax 
 mulq %rbx
 addq %rax, %rcx 
 adcq $0x0, %rdx 
 subq %rbp, %r10 
 sbbq %rcx, %r11 
 sbbq %rdx, %r12 
 sbbq $0x0, %r13 
 sbbq %rbx, %rbx 
 movabsq $0x5812631a5cf5d3ed, %rax 
 andq %rbx, %rax 
 movabsq $0x14def9dea2f79cd6, %rdx 
 andq %rbx, %rdx 
 movabsq $0x1000000000000000, %rbx 
 andq %rax, %rbx 
 addq %rax, %r10 
 adcq %rdx, %r11 
 adcq $0x0, %r12 
 adcq %rbx, %r13
        movq %r13, %rbx 
 shldq $0x4, %r12, %rbx 
 shrq $0x3c, %r13 
 subq %r13, %rbx 
 shlq $0x4, %r12 
 shrdq $0x4, %r13, %r12 
 movabsq $0x5812631a5cf5d3ed, %rax 
 mulq %rbx
 movq %rax, %rbp 
 movq %rdx, %rcx 
 movabsq $0x14def9dea2f79cd6, %rax 
 mulq %rbx
 addq %rax, %rcx 
 adcq $0x0, %rdx 
 subq %rbp, %r9 
 sbbq %rcx, %r10 
 sbbq %rdx, %r11 
 sbbq $0x0, %r12 
 sbbq %rbx, %rbx 
 movabsq $0x5812631a5cf5d3ed, %rax 
 andq %rbx, %rax 
 movabsq $0x14def9dea2f79cd6, %rdx 
 andq %rbx, %rdx 
 movabsq $0x1000000000000000, %rbx 
 andq %rax, %rbx 
 addq %rax, %r9 
 adcq %rdx, %r10 
 adcq $0x0, %r11 
 adcq %rbx, %r12
        movq %r12, %rbx 
 shldq $0x4, %r11, %rbx 
 shrq $0x3c, %r12 
 subq %r12, %rbx 
 shlq $0x4, %r11 
 shrdq $0x4, %r12, %r11 
 movabsq $0x5812631a5cf5d3ed, %rax 
 mulq %rbx
 movq %rax, %rbp 
 movq %rdx, %rcx 
 movabsq $0x14def9dea2f79cd6, %rax 
 mulq %rbx
 addq %rax, %rcx 
 adcq $0x0, %rdx 
 subq %rbp, %r8 
 sbbq %rcx, %r9 
 sbbq %rdx, %r10 
 sbbq $0x0, %r11 
 sbbq %rbx, %rbx 
 movabsq $0x5812631a5cf5d3ed, %rax 
 andq %rbx, %rax 
 movabsq $0x14def9dea2f79cd6, %rdx 
 andq %rbx, %rdx 
 movabsq $0x1000000000000000, %rbx 
 andq %rax, %rbx 
 addq %rax, %r8 
 adcq %rdx, %r9 
 adcq $0x0, %r10 
 adcq %rbx, %r11

        movq %r8, (%rdi)
        movq %r9, 8(%rdi)
        movq %r10, 16(%rdi)
        movq %r11, 24(%rdi)



        popq %r15
        popq %r14
        popq %r13
        popq %r12
        popq %rbp
        popq %rbx





        ret


.section .note.GNU-stack,"",%progbits
