# 0 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_sub_p521.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_sub_p521.S"
# 15 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_sub_p521.S"
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/include/_internal_s2n_bignum.h" 1
# 16 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_sub_p521.S" 2


        .globl bignum_sub_p521
        .hidden bignum_sub_p521
        .text
# 41 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_sub_p521.S"
bignum_sub_p521:
# 53 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p521/bignum_sub_p521.S"
        pushq %rbx
        pushq %r12



        movq (%rsi), %rax
        subq (%rdx), %rax
        movq 8(%rsi), %rcx
        sbbq 8(%rdx), %rcx
        movq 16(%rsi), %r8
        sbbq 16(%rdx), %r8
        movq 24(%rsi), %r9
        sbbq 24(%rdx), %r9
        movq 32(%rsi), %r10
        sbbq 32(%rdx), %r10
        movq 40(%rsi), %r11
        sbbq 40(%rdx), %r11
        movq 48(%rsi), %r12
        sbbq 48(%rdx), %r12
        movq 56(%rsi), %rbx
        sbbq 56(%rdx), %rbx
        movq 64(%rsi), %rsi
        sbbq 64(%rdx), %rsi






        sbbq $0, %rax
        movq %rax, (%rdi)
        sbbq $0, %rcx
        movq %rcx, 8(%rdi)
        sbbq $0, %r8
        movq %r8, 16(%rdi)
        sbbq $0, %r9
        movq %r9, 24(%rdi)
        sbbq $0, %r10
        movq %r10, 32(%rdi)
        sbbq $0, %r11
        movq %r11, 40(%rdi)
        sbbq $0, %r12
        movq %r12, 48(%rdi)
        sbbq $0, %rbx
        movq %rbx, 56(%rdi)
        sbbq $0, %rsi
        andq $0x1FF, %rsi
        movq %rsi, 64(%rdi)



        popq %r12
        popq %rbx





        ret


.section .note.GNU-stack,"",%progbits
