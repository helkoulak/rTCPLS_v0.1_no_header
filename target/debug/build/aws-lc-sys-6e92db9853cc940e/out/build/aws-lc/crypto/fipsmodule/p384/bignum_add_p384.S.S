# 0 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_add_p384.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_add_p384.S"
# 15 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_add_p384.S"
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/include/_internal_s2n_bignum.h" 1
# 16 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_add_p384.S" 2


        .globl bignum_add_p384
        .hidden bignum_add_p384
        .text
# 43 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_add_p384.S"
bignum_add_p384:
# 56 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_add_p384.S"
        movq (%rsi), %rax
        addq (%rdx), %rax
        movq 8(%rsi), %rcx
        adcq 8(%rdx), %rcx
        movq 16(%rsi), %r8
        adcq 16(%rdx), %r8
        movq 24(%rsi), %r9
        adcq 24(%rdx), %r9
        movq 32(%rsi), %r10
        adcq 32(%rdx), %r10
        movq 40(%rsi), %r11
        adcq 40(%rdx), %r11
        movl $0, %edx
        adcq %rdx, %rdx





        movq $0xffffffff00000001, %rsi
        addq %rsi, %rax
        movl $0x00000000ffffffff, %esi
        adcq %rsi, %rcx
        adcq $1, %r8
        adcq $0, %r9
        adcq $0, %r10
        adcq $0, %r11
        adcq $-1, %rdx







        andq %rsi, %rdx
        xorq %rsi, %rsi
        subq %rdx, %rsi



        subq %rsi, %rax
        movq %rax, (%rdi)
        sbbq %rdx, %rcx
        movq %rcx, 8(%rdi)




        sbbq %rax, %rax
        andq %rsi, %rdx
        negq %rax



        sbbq %rdx, %r8
        movq %r8, 16(%rdi)
        sbbq $0, %r9
        movq %r9, 24(%rdi)
        sbbq $0, %r10
        movq %r10, 32(%rdi)
        sbbq $0, %r11
        movq %r11, 40(%rdi)





        ret


.section .note.GNU-stack,"",%progbits
