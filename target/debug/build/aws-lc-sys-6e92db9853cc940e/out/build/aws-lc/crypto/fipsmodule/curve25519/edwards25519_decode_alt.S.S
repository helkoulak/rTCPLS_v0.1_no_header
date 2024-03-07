# 0 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/edwards25519_decode_alt.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/edwards25519_decode_alt.S"
# 29 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/edwards25519_decode_alt.S"
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/include/_internal_s2n_bignum.h" 1
# 30 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/edwards25519_decode_alt.S" 2


        .globl edwards25519_decode_alt
        .hidden edwards25519_decode_alt
        .text
# 71 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/edwards25519_decode_alt.S"
edwards25519_decode_alt:
# 91 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/edwards25519_decode_alt.S"
        pushq %rbx
        pushq %rbp
        pushq %r12
        pushq %r13
        pushq %r14
        pushq %r15

        subq $(32*8), %rsp



        movq %rdi, (28*8)(%rsp)





        movq (%rsi), %rax
        movq %rax, 0(%rsp)
        movq 8(%rsi), %rbx
        movq %rbx, 0 +8(%rsp)
        xorl %ebp, %ebp
        movq 16(%rsi), %rcx
        movq %rcx, 0 +16(%rsp)
        movq 24(%rsi), %rdx
        btr $63, %rdx
        movq %rdx, 0 +24(%rsp)
        adcq %rbp, %rbp
        movq %rbp, (29*8)(%rsp)

        addq $19, %rax
        adcq $0, %rbx
        adcq $0, %rcx
        adcq $0, %rdx
        shrq $63, %rdx
        movq %rdx, (30*8)(%rsp)





        leaq (16*8)(%rsp), %rdi
        movq $1, %rsi
        leaq 0(%rsp), %rdx
        callq edwards25519_decode_alt_nsqr_p25519
        movq (16*8)(%rsp), %rax
        subq $20, %rax
        movq (16*8)+8(%rsp), %rbx
        sbbq $0, %rbx
        movq (16*8)+16(%rsp), %rcx
        sbbq $0, %rcx
        movq (16*8)+24(%rsp), %rdx
        sbbq $0, %rdx
        btc $63, %rdx
        movq %rax, (12*8)(%rsp)
        movq %rbx, (12*8)+8(%rsp)
        movq %rcx, (12*8)+16(%rsp)
        movq %rdx, (12*8)+24(%rsp)

        movq $0x75eb4dca135978a3, %rax
        movq %rax, (20*8)(%rsp)
        movq $0x00700a4d4141d8ab, %rax
        movq %rax, (20*8)+8(%rsp)
        movq $0x8cc740797779e898, %rax
        movq %rax, (20*8)+16(%rsp)
        movq $0x52036cee2b6ffe73, %rax
        movq %rax, (20*8)+24(%rsp)
        leaq (16*8)(%rsp), %rdi
        leaq (20*8)(%rsp), %rsi
        leaq (16*8)(%rsp), %rdx
        callq edwards25519_decode_alt_mul_p25519
        movq (16*8)(%rsp), %rax
        addq $1, %rax
        movq (16*8)+8(%rsp), %rbx
        adcq $0, %rbx
        movq (16*8)+16(%rsp), %rcx
        adcq $0, %rcx
        movq (16*8)+24(%rsp), %rdx
        adcq $0, %rdx
        movq %rax, (16*8)(%rsp)
        movq %rbx, (16*8)+8(%rsp)
        movq %rcx, (16*8)+16(%rsp)
        movq %rdx, (16*8)+24(%rsp)

        leaq (20*8)(%rsp), %rdi
        leaq (12*8)(%rsp), %rsi
        leaq (16*8)(%rsp), %rdx
        callq edwards25519_decode_alt_mul_p25519




        leaq (8*8)(%rsp), %rdi
        movq $1, %rsi
        leaq (20*8)(%rsp), %rdx
        callq edwards25519_decode_alt_nsqr_p25519

        leaq (8*8)(%rsp), %rdi
        leaq (8*8)(%rsp), %rsi
        leaq (20*8)(%rsp), %rdx
        callq edwards25519_decode_alt_mul_p25519

        leaq (4*8)(%rsp), %rdi
        movq $2, %rsi
        leaq (8*8)(%rsp), %rdx
        callq edwards25519_decode_alt_nsqr_p25519

        leaq (8*8)(%rsp), %rdi
        leaq (4*8)(%rsp), %rsi
        leaq (8*8)(%rsp), %rdx
        callq edwards25519_decode_alt_mul_p25519

        leaq (4*8)(%rsp), %rdi
        movq $1, %rsi
        leaq (8*8)(%rsp), %rdx
        callq edwards25519_decode_alt_nsqr_p25519

        leaq (16*8)(%rsp), %rdi
        leaq (4*8)(%rsp), %rsi
        leaq (20*8)(%rsp), %rdx
        callq edwards25519_decode_alt_mul_p25519

        leaq (4*8)(%rsp), %rdi
        movq $5, %rsi
        leaq (16*8)(%rsp), %rdx
        callq edwards25519_decode_alt_nsqr_p25519

        leaq (8*8)(%rsp), %rdi
        leaq (4*8)(%rsp), %rsi
        leaq (16*8)(%rsp), %rdx
        callq edwards25519_decode_alt_mul_p25519

        leaq (4*8)(%rsp), %rdi
        movq $10, %rsi
        leaq (8*8)(%rsp), %rdx
        callq edwards25519_decode_alt_nsqr_p25519

        leaq (8*8)(%rsp), %rdi
        leaq (4*8)(%rsp), %rsi
        leaq (8*8)(%rsp), %rdx
        callq edwards25519_decode_alt_mul_p25519

        leaq (4*8)(%rsp), %rdi
        movq $5, %rsi
        leaq (8*8)(%rsp), %rdx
        callq edwards25519_decode_alt_nsqr_p25519

        leaq (16*8)(%rsp), %rdi
        leaq (4*8)(%rsp), %rsi
        leaq (16*8)(%rsp), %rdx
        callq edwards25519_decode_alt_mul_p25519

        leaq (4*8)(%rsp), %rdi
        movq $25, %rsi
        leaq (16*8)(%rsp), %rdx
        callq edwards25519_decode_alt_nsqr_p25519

        leaq (8*8)(%rsp), %rdi
        leaq (4*8)(%rsp), %rsi
        leaq (16*8)(%rsp), %rdx
        callq edwards25519_decode_alt_mul_p25519

        leaq (4*8)(%rsp), %rdi
        movq $50, %rsi
        leaq (8*8)(%rsp), %rdx
        callq edwards25519_decode_alt_nsqr_p25519

        leaq (8*8)(%rsp), %rdi
        leaq (4*8)(%rsp), %rsi
        leaq (8*8)(%rsp), %rdx
        callq edwards25519_decode_alt_mul_p25519

        leaq (4*8)(%rsp), %rdi
        movq $25, %rsi
        leaq (8*8)(%rsp), %rdx
        callq edwards25519_decode_alt_nsqr_p25519

        leaq (16*8)(%rsp), %rdi
        leaq (4*8)(%rsp), %rsi
        leaq (16*8)(%rsp), %rdx
        callq edwards25519_decode_alt_mul_p25519

        leaq (4*8)(%rsp), %rdi
        movq $125, %rsi
        leaq (16*8)(%rsp), %rdx
        callq edwards25519_decode_alt_nsqr_p25519

        leaq (16*8)(%rsp), %rdi
        leaq (4*8)(%rsp), %rsi
        leaq (16*8)(%rsp), %rdx
        callq edwards25519_decode_alt_mul_p25519

        leaq (4*8)(%rsp), %rdi
        movq $2, %rsi
        leaq (16*8)(%rsp), %rdx
        callq edwards25519_decode_alt_nsqr_p25519

        leaq (4*8)(%rsp), %rdi
        leaq (4*8)(%rsp), %rsi
        leaq (20*8)(%rsp), %rdx
        callq edwards25519_decode_alt_mul_p25519




        leaq (16*8)(%rsp), %rdi
        movq $1, %rsi
        leaq (4*8)(%rsp), %rdx
        callq edwards25519_decode_alt_nsqr_p25519

        leaq (16*8)(%rsp), %rdi
        leaq (16*8)(%rsp), %rsi
        leaq (20*8)(%rsp), %rdx
        callq edwards25519_decode_alt_mul_p25519




        leaq (4*8)(%rsp), %rdi
        leaq (12*8)(%rsp), %rsi
        leaq (4*8)(%rsp), %rdx
        callq edwards25519_decode_alt_mul_p25519
        movq $0xc4ee1b274a0ea0b0, %rax
        movq %rax, (8*8)(%rsp)
        movq $0x2f431806ad2fe478, %rax
        movq %rax, (8*8)+8(%rsp)
        movq $0x2b4d00993dfbd7a7, %rax
        movq %rax, (8*8)+16(%rsp)
        movq $0x2b8324804fc1df0b, %rax
        movq %rax, (8*8)+24(%rsp)
        leaq (8*8)(%rsp), %rdi
        leaq (4*8)(%rsp), %rsi
        leaq (8*8)(%rsp), %rdx
        callq edwards25519_decode_alt_mul_p25519



        movq (16*8)(%rsp), %r8
        movq (16*8)+8(%rsp), %r9
        movq (16*8)+16(%rsp), %r10
        movq (16*8)+24(%rsp), %r11
        movl $1, %eax
        notq %rax
        andq %r8, %rax
        orq %r9, %rax
        orq %r10, %rax
        orq %r11, %rax



        addq $20, %r8
        notq %r9
        notq %r10
        bts $63, %r11
        addq $1, %r11
        orq %r9, %r8
        orq %r11, %r10
        orq %r10, %r8



        testq %rax, %rax

        movq (4*8)(%rsp), %r12
        movq (8*8)(%rsp), %rbx
        cmovnzq %rbx, %r12
        movq (4*8)+8(%rsp), %r13
        movq (8*8)+8(%rsp), %rbx
        cmovnzq %rbx, %r13
        movq (4*8)+16(%rsp), %r14
        movq (8*8)+16(%rsp), %rbx
        cmovnzq %rbx, %r14
        movq (4*8)+24(%rsp), %r15
        movq (8*8)+24(%rsp), %rbx
        cmovnzq %rbx, %r15
        movq %r12, (4*8)(%rsp)
        movq %r13, (4*8)+8(%rsp)
        movq %r14, (4*8)+16(%rsp)
        movq %r15, (4*8)+24(%rsp)



        cmovzq %rax, %r8
        negq %r8
        sbbq %r8, %r8
        negq %r8
        orq %r8, (30*8)(%rsp)



        movq (4*8)(%rsp), %r8
        movq $-19, %r12
        subq %r8, %r12
        movq (4*8)+8(%rsp), %r9
        movq $-1, %r13
        sbbq %r9, %r13
        movq (4*8)+16(%rsp), %r10
        movq $-1, %r14
        sbbq %r10, %r14
        movq (4*8)+24(%rsp), %r11
        movq $0x7FFFFFFFFFFFFFFF, %r15
        sbbq %r11, %r15






        movl $1, %ecx
        andq %r8, %rcx
        xorq (29*8)(%rsp), %rcx
        movq (30*8)(%rsp), %rdx
        movq %rdx, %rsi
        orq %rcx, %rdx
        xorl %ebp, %ebp
        movq %r8, %rax
        movq %r9, %rbx
        orq %r10, %rax
        orq %r11, %rbx
        orq %rbx, %rax
        cmovzq %rbp, %rcx
        cmovnzq %rsi, %rdx



        testq %rcx, %rcx

        cmovnzq %r12, %r8
        cmovnzq %r13, %r9
        cmovnzq %r14, %r10
        cmovnzq %r15, %r11

        movq (28*8)(%rsp), %rdi
        movq %r8, (%rdi)
        movq %r9, 8(%rdi)
        movq %r10, 16(%rdi)
        movq %r11, 24(%rdi)
        movq 0(%rsp), %rcx
        movq %rcx, 32(%rdi)
        movq 0 +8(%rsp), %rcx
        movq %rcx, 40(%rdi)
        movq 0 +16(%rsp), %rcx
        movq %rcx, 48(%rdi)
        movq 0 +24(%rsp), %rcx
        movq %rcx, 56(%rdi)

        movq %rdx, %rax



        addq $(32*8), %rsp

        popq %r15
        popq %r14
        popq %r13
        popq %r12
        popq %rbp
        popq %rbx
        ret





edwards25519_decode_alt_mul_p25519:
        movq %rdx, %rcx
        movq (%rsi), %rax
        mulq (%rcx)
        movq %rax, %r8
        movq %rdx, %r9
        xorq %r10, %r10
        xorq %r11, %r11
        movq (%rsi), %rax
        mulq 0x8(%rcx)
        addq %rax, %r9
        adcq %rdx, %r10
        movq 0x8(%rsi), %rax
        mulq (%rcx)
        addq %rax, %r9
        adcq %rdx, %r10
        adcq $0x0, %r11
        xorq %r12, %r12
        movq (%rsi), %rax
        mulq 0x10(%rcx)
        addq %rax, %r10
        adcq %rdx, %r11
        adcq %r12, %r12
        movq 0x8(%rsi), %rax
        mulq 0x8(%rcx)
        addq %rax, %r10
        adcq %rdx, %r11
        adcq $0x0, %r12
        movq 0x10(%rsi), %rax
        mulq (%rcx)
        addq %rax, %r10
        adcq %rdx, %r11
        adcq $0x0, %r12
        xorq %r13, %r13
        movq (%rsi), %rax
        mulq 0x18(%rcx)
        addq %rax, %r11
        adcq %rdx, %r12
        adcq %r13, %r13
        movq 0x8(%rsi), %rax
        mulq 0x10(%rcx)
        addq %rax, %r11
        adcq %rdx, %r12
        adcq $0x0, %r13
        movq 0x10(%rsi), %rax
        mulq 0x8(%rcx)
        addq %rax, %r11
        adcq %rdx, %r12
        adcq $0x0, %r13
        movq 0x18(%rsi), %rax
        mulq (%rcx)
        addq %rax, %r11
        adcq %rdx, %r12
        adcq $0x0, %r13
        xorq %r14, %r14
        movq 0x8(%rsi), %rax
        mulq 0x18(%rcx)
        addq %rax, %r12
        adcq %rdx, %r13
        adcq %r14, %r14
        movq 0x10(%rsi), %rax
        mulq 0x10(%rcx)
        addq %rax, %r12
        adcq %rdx, %r13
        adcq $0x0, %r14
        movq 0x18(%rsi), %rax
        mulq 0x8(%rcx)
        addq %rax, %r12
        adcq %rdx, %r13
        adcq $0x0, %r14
        xorq %r15, %r15
        movq 0x10(%rsi), %rax
        mulq 0x18(%rcx)
        addq %rax, %r13
        adcq %rdx, %r14
        adcq %r15, %r15
        movq 0x18(%rsi), %rax
        mulq 0x10(%rcx)
        addq %rax, %r13
        adcq %rdx, %r14
        adcq $0x0, %r15
        movq 0x18(%rsi), %rax
        mulq 0x18(%rcx)
        addq %rax, %r14
        adcq %rdx, %r15
        movl $0x26, %esi
        movq %r12, %rax
        mulq %rsi
        addq %rax, %r8
        adcq %rdx, %r9
        sbbq %rcx, %rcx
        movq %r13, %rax
        mulq %rsi
        subq %rcx, %rdx
        addq %rax, %r9
        adcq %rdx, %r10
        sbbq %rcx, %rcx
        movq %r14, %rax
        mulq %rsi
        subq %rcx, %rdx
        addq %rax, %r10
        adcq %rdx, %r11
        sbbq %rcx, %rcx
        movq %r15, %rax
        mulq %rsi
        subq %rcx, %rdx
        xorq %rcx, %rcx
        addq %rax, %r11
        movq %rdx, %r12
        adcq %rcx, %r12
        shldq $0x1, %r11, %r12
        leaq 0x1(%r12), %rax
        movl $0x13, %esi
        bts $0x3f, %r11
        imulq %rsi, %rax
        addq %rax, %r8
        adcq %rcx, %r9
        adcq %rcx, %r10
        adcq %rcx, %r11
        sbbq %rax, %rax
        notq %rax
        andq %rsi, %rax
        subq %rax, %r8
        sbbq %rcx, %r9
        sbbq %rcx, %r10
        sbbq %rcx, %r11
        btr $0x3f, %r11
        movq %r8, (%rdi)
        movq %r9, 0x8(%rdi)
        movq %r10, 0x10(%rdi)
        movq %r11, 0x18(%rdi)
        ret





edwards25519_decode_alt_nsqr_p25519:



        movq (%rdx), %rax
        movq 8(%rdx), %rbx
        movq 16(%rdx), %rcx
        movq 24(%rdx), %rdx
        movq %rax, (25*8)(%rsp)
        movq %rbx, (25*8)+8(%rsp)
        movq %rcx, (25*8)+16(%rsp)
        movq %rdx, (25*8)+24(%rsp)




edwards25519_decode_alt_loop:
        movq (25*8)(%rsp), %rax
        mulq %rax
        movq %rax, %r8
        movq %rdx, %r9
        xorq %r10, %r10
        xorq %r11, %r11
        movq (25*8)(%rsp), %rax
        mulq (25*8)+0x8(%rsp)
        addq %rax, %rax
        adcq %rdx, %rdx
        adcq $0x0, %r11
        addq %rax, %r9
        adcq %rdx, %r10
        adcq $0x0, %r11
        xorq %r12, %r12
        movq (25*8)+0x8(%rsp), %rax
        mulq %rax
        addq %rax, %r10
        adcq %rdx, %r11
        adcq $0x0, %r12
        movq (25*8)(%rsp), %rax
        mulq (25*8)+0x10(%rsp)
        addq %rax, %rax
        adcq %rdx, %rdx
        adcq $0x0, %r12
        addq %rax, %r10
        adcq %rdx, %r11
        adcq $0x0, %r12
        xorq %r13, %r13
        movq (25*8)(%rsp), %rax
        mulq (25*8)+0x18(%rsp)
        addq %rax, %rax
        adcq %rdx, %rdx
        adcq $0x0, %r13
        addq %rax, %r11
        adcq %rdx, %r12
        adcq $0x0, %r13
        movq (25*8)+0x8(%rsp), %rax
        mulq (25*8)+0x10(%rsp)
        addq %rax, %rax
        adcq %rdx, %rdx
        adcq $0x0, %r13
        addq %rax, %r11
        adcq %rdx, %r12
        adcq $0x0, %r13
        xorq %r14, %r14
        movq (25*8)+0x8(%rsp), %rax
        mulq (25*8)+0x18(%rsp)
        addq %rax, %rax
        adcq %rdx, %rdx
        adcq $0x0, %r14
        addq %rax, %r12
        adcq %rdx, %r13
        adcq $0x0, %r14
        movq (25*8)+0x10(%rsp), %rax
        mulq %rax
        addq %rax, %r12
        adcq %rdx, %r13
        adcq $0x0, %r14
        xorq %r15, %r15
        movq (25*8)+0x10(%rsp), %rax
        mulq (25*8)+0x18(%rsp)
        addq %rax, %rax
        adcq %rdx, %rdx
        adcq $0x0, %r15
        addq %rax, %r13
        adcq %rdx, %r14
        adcq $0x0, %r15
        movq (25*8)+0x18(%rsp), %rax
        mulq %rax
        addq %rax, %r14
        adcq %rdx, %r15
        movl $0x26, %ebx
        movq %r12, %rax
        mulq %rbx
        addq %rax, %r8
        adcq %rdx, %r9
        sbbq %rcx, %rcx
        movq %r13, %rax
        mulq %rbx
        subq %rcx, %rdx
        addq %rax, %r9
        adcq %rdx, %r10
        sbbq %rcx, %rcx
        movq %r14, %rax
        mulq %rbx
        subq %rcx, %rdx
        addq %rax, %r10
        adcq %rdx, %r11
        sbbq %rcx, %rcx
        movq %r15, %rax
        mulq %rbx
        subq %rcx, %rdx
        xorq %rcx, %rcx
        addq %rax, %r11
        movq %rdx, %r12
        adcq %rcx, %r12
        shldq $0x1, %r11, %r12
        btr $0x3f, %r11
        movl $0x13, %edx
        imulq %r12, %rdx
        addq %rdx, %r8
        adcq %rcx, %r9
        adcq %rcx, %r10
        adcq %rcx, %r11
        movq %r8, (25*8)(%rsp)
        movq %r9, (25*8)+0x8(%rsp)
        movq %r10, (25*8)+0x10(%rsp)
        movq %r11, (25*8)+0x18(%rsp)



        decq %rsi
        jnz edwards25519_decode_alt_loop






        movl $19, %eax
        xorl %ebx, %ebx
        xorl %ecx, %ecx
        xorl %edx, %edx
        addq %r8, %rax
        adcq %r9, %rbx
        adcq %r10, %rcx
        adcq %r11, %rdx

        cmovns %r8, %rax
        cmovns %r9, %rbx
        cmovns %r10, %rcx
        cmovns %r11, %rdx
        btr $63, %rdx
        movq %rax, (%rdi)
        movq %rbx, 8(%rdi)
        movq %rcx, 16(%rdi)
        movq %rdx, 24(%rdi)
        ret


.section .note.GNU-stack, "", %progbits
