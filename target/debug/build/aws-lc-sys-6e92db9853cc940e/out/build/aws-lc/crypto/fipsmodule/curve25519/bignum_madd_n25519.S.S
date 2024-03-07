# 0 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_madd_n25519.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_madd_n25519.S"
# 21 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_madd_n25519.S"
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/include/_internal_s2n_bignum.h" 1
# 22 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_madd_n25519.S" 2


        .globl bignum_madd_n25519
        .hidden bignum_madd_n25519
        .text
# 97 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_madd_n25519.S"
bignum_madd_n25519:
# 110 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_madd_n25519.S"
        pushq %rbx
        pushq %rbp
        pushq %r12
        pushq %r13
        pushq %r14
        pushq %r15







        movq (%rcx), %r8
        movq 8(%rcx), %r9
        movq 16(%rcx), %r10
        movq 24(%rcx), %r11
        movq %rdx, %rcx
        xorl %ebp, %ebp
        movq (%rcx), %rdx
        mulxq (%rsi), %rax, %rbx
        adcxq %rax, %r8
        adoxq %rbx, %r9
        mulxq 0x8(%rsi), %rax, %rbx
        adcxq %rax, %r9
        adoxq %rbx, %r10
        mulxq 0x10(%rsi), %rax, %rbx
        adcxq %rax, %r10
        adoxq %rbx, %r11
        mulxq 0x18(%rsi), %rax, %r12
        adcxq %rax, %r11
        adoxq %rbp, %r12
        adcxq %rbp, %r12
        xorl %ebp, %ebp
        movq 0x8(%rcx), %rdx
        mulxq (%rsi), %rax, %rbx
        adcxq %rax, %r9
        adoxq %rbx, %r10
        mulxq 0x8(%rsi), %rax, %rbx
        adcxq %rax, %r10
        adoxq %rbx, %r11
        mulxq 0x10(%rsi), %rax, %rbx
        adcxq %rax, %r11
        adoxq %rbx, %r12
        mulxq 0x18(%rsi), %rax, %r13
        adcxq %rax, %r12
        adoxq %rbp, %r13
        adcxq %rbp, %r13
        xorl %ebp, %ebp
        movq 0x10(%rcx), %rdx
        mulxq (%rsi), %rax, %rbx
        adcxq %rax, %r10
        adoxq %rbx, %r11
        mulxq 0x8(%rsi), %rax, %rbx
        adcxq %rax, %r11
        adoxq %rbx, %r12
        mulxq 0x10(%rsi), %rax, %rbx
        adcxq %rax, %r12
        adoxq %rbx, %r13
        mulxq 0x18(%rsi), %rax, %r14
        adcxq %rax, %r13
        adoxq %rbp, %r14
        adcxq %rbp, %r14
        xorl %ebp, %ebp
        movq 0x18(%rcx), %rdx
        mulxq (%rsi), %rax, %rbx
        adcxq %rax, %r11
        adoxq %rbx, %r12
        mulxq 0x8(%rsi), %rax, %rbx
        adcxq %rax, %r12
        adoxq %rbx, %r13
        mulxq 0x10(%rsi), %rax, %rbx
        adcxq %rax, %r13
        adoxq %rbx, %r14
        mulxq 0x18(%rsi), %rax, %r15
        adcxq %rax, %r14
        adoxq %rbp, %r15
        adcxq %rbp, %r15



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
