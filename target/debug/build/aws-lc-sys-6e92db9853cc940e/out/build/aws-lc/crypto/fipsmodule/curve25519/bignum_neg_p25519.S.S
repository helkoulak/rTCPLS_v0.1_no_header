# 0 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_neg_p25519.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_neg_p25519.S"
# 15 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_neg_p25519.S"
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/include/_internal_s2n_bignum.h" 1
# 16 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_neg_p25519.S" 2


        .globl bignum_neg_p25519
        .hidden bignum_neg_p25519
        .text
# 35 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_neg_p25519.S"
bignum_neg_p25519:
# 46 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_neg_p25519.S"
        movq (%rsi), %rax
        movq %rax, %rdx
        movq 8(%rsi), %rcx
        orq %rcx, %rdx
        movq 16(%rsi), %r8
        orq %r8, %rdx
        movq 24(%rsi), %r9
        orq %r9, %rdx




        negq %rdx
        sbbq %rdx, %rdx
        movq $-19, %r10
        andq %rdx, %r10




        subq %rax, %r10
        movq %r10, (%rdi)
        movq %rdx, %r10
        sbbq %rcx, %r10
        movq %r10, 8(%rdi)
        movq %rdx, %r10
        sbbq %r8, %r10
        movq %r10, 16(%rdi)
        sbbq %r9, %rdx
        btr $63, %rdx
        movq %rdx, 24(%rdi)





        ret


.section .note.GNU-stack,"",%progbits
