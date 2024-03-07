# 0 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/edwards25519_encode.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/edwards25519_encode.S"
# 28 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/edwards25519_encode.S"
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/include/_internal_s2n_bignum.h" 1
# 29 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/edwards25519_encode.S" 2


        .globl edwards25519_encode
        .hidden edwards25519_encode
        .text
# 43 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/edwards25519_encode.S"
edwards25519_encode:
# 54 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/edwards25519_encode.S"
        movq (%rsi), %r9
        movq 32(%rsi), %rax
        movq 40(%rsi), %rcx
        movq 48(%rsi), %rdx
        movq 56(%rsi), %r8



        btr $63, %r8
        shlq $63, %r9
        orq %r9, %r8



        movq %rax, (%rdi)
        movq %rcx, 8(%rdi)
        movq %rdx, 16(%rdi)
        movq %r8, 24(%rdi)





        ret


.section .note.GNU-stack,"",%progbits
