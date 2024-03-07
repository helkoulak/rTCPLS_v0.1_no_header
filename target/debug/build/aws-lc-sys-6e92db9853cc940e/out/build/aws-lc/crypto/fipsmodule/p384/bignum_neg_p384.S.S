# 0 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_neg_p384.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_neg_p384.S"
# 14 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_neg_p384.S"
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/include/_internal_s2n_bignum.h" 1
# 15 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_neg_p384.S" 2


        .globl bignum_neg_p384
        .hidden bignum_neg_p384
        .text
# 33 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_neg_p384.S"
bignum_neg_p384:
# 45 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_neg_p384.S"
        movq (%rsi), %rax
        orq 8(%rsi), %rax
        movq 16(%rsi), %rcx
        orq 24(%rsi), %rcx
        movq 32(%rsi), %rdx
        orq 40(%rsi), %rdx
        orq %rcx, %rax
        orq %rdx, %rax
        negq %rax
        sbbq %r10, %r10



        movl $0x00000000ffffffff, %eax
        andq %r10, %rax
        movq $0xffffffff00000000, %rcx
        andq %r10, %rcx
        movq $0xfffffffffffffffe, %rdx
        andq %r10, %rdx
        movq %r10, %r8
        movq %r10, %r9



        subq (%rsi), %rax
        sbbq 8(%rsi), %rcx
        sbbq 16(%rsi), %rdx
        sbbq 24(%rsi), %r8
        sbbq 32(%rsi), %r9
        sbbq 40(%rsi), %r10



        movq %rax, (%rdi)
        movq %rcx, 8(%rdi)
        movq %rdx, 16(%rdi)
        movq %r8, 24(%rdi)
        movq %r9, 32(%rdi)
        movq %r10, 40(%rdi)





        ret


.section .note.GNU-stack,"",%progbits
