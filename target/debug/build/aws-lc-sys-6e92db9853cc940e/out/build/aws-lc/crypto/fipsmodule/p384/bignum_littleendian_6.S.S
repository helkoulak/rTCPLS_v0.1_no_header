# 0 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_littleendian_6.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_littleendian_6.S"
# 26 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_littleendian_6.S"
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/include/_internal_s2n_bignum.h" 1
# 27 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_littleendian_6.S" 2


        .globl bignum_littleendian_6
        .hidden bignum_littleendian_6
        .globl bignum_fromlebytes_6
        .hidden bignum_fromlebytes_6
        .globl bignum_tolebytes_6
        .hidden bignum_tolebytes_6

        .text





bignum_littleendian_6:
bignum_fromlebytes_6:
bignum_tolebytes_6:
# 53 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_littleendian_6.S"
        movq (%rsi), %rax
        movq %rax, (%rdi)

        movq 8(%rsi), %rax
        movq %rax, 8(%rdi)

        movq 16(%rsi), %rax
        movq %rax, 16(%rdi)

        movq 24(%rsi), %rax
        movq %rax, 24(%rdi)

        movq 32(%rsi), %rax
        movq %rax, 32(%rdi)

        movq 40(%rsi), %rax
        movq %rax, 40(%rdi)





        ret


.section .note.GNU-stack,"",%progbits
