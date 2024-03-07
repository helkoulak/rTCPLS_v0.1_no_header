# 0 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_neg_p521.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_neg_p521.S"
# 14 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_neg_p521.S"
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/include/_internal_s2n_bignum.h" 1
# 15 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_neg_p521.S" 2


        .globl bignum_neg_p521
        .hidden bignum_neg_p521
        .text
# 32 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_neg_p521.S"
bignum_neg_p521:
# 43 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_neg_p521.S"
        movq (%rsi), %rcx
        movq %rcx, %rax
        movq 8(%rsi), %rdx
        orq %rdx, %rax
        movq 16(%rsi), %r8
        orq %r8, %rax
        movq 24(%rsi), %r9
        orq %r9, %rax
        movq 32(%rsi), %r10
        orq %r10, %rax
        movq 40(%rsi), %r11
        orq %r11, %rax
        orq 48(%rsi), %rax
        orq 56(%rsi), %rax
        orq 64(%rsi), %rax




        negq %rax
        sbbq %rax, %rax




        xorq %rax, %rcx
        movq %rcx, (%rdi)
        xorq %rax, %rdx
        movq %rdx, 8(%rdi)
        xorq %rax, %r8
        movq %r8, 16(%rdi)
        xorq %rax, %r9
        movq %r9, 24(%rdi)
        xorq %rax, %r10
        movq %r10, 32(%rdi)
        xorq %rax, %r11
        movq %r11, 40(%rdi)
        movq 48(%rsi), %rcx
        xorq %rax, %rcx
        movq %rcx, 48(%rdi)
        movq 56(%rsi), %rdx
        xorq %rax, %rdx
        movq %rdx, 56(%rdi)
        movq 64(%rsi), %r8
        andq $0x1FF, %rax
        xorq %rax, %r8
        movq %r8, 64(%rdi)







        ret


.section .note.GNU-stack,"",%progbits
