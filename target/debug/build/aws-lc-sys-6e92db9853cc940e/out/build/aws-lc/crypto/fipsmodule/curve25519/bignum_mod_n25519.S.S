# 0 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_mod_n25519.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_mod_n25519.S"
# 18 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_mod_n25519.S"
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/include/_internal_s2n_bignum.h" 1
# 19 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_mod_n25519.S" 2


        .globl bignum_mod_n25519
        .hidden bignum_mod_n25519
        .text
# 37 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_mod_n25519.S"
bignum_mod_n25519:
# 49 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/curve25519/bignum_mod_n25519.S"
        pushq %rbx
        pushq %rbp
        pushq %r12



        cmpq $4, %rsi
        jc shortinput




        subq $4, %rsi
        movq 24(%rdx,%rsi,8), %r11
        movq 16(%rdx,%rsi,8), %r10
        movq 8(%rdx,%rsi,8), %r9
        movq (%rdx,%rsi,8), %r8



        movq %rdx, %rcx




        movq %r11, %rbx
        shrq $60, %rbx

        shlq $4, %r11
        shrq $4, %r11



        movq $0x5812631a5cf5d3ed, %rax
        mulq %rbx
        movq %rax, %rbp
        movq %rdx, %r12

        movq $0x14def9dea2f79cd6, %rax
        mulq %rbx
        addq %rax, %r12
        adcq $0, %rdx



        subq %rbp, %r8
        sbbq %r12, %r9
        sbbq %rdx, %r10
        sbbq $0, %r11





        sbbq %rbx, %rbx

        movq $0x5812631a5cf5d3ed, %rax
        andq %rbx, %rax
        movq $0x14def9dea2f79cd6, %rdx
        andq %rbx, %rdx
        movq $0x1000000000000000, %rbx
        andq %rax, %rbx

        addq %rax, %r8
        adcq %rdx, %r9
        adcq $0, %r10
        adcq %rbx, %r11





        testq %rsi, %rsi
        jz writeback

loop:





        movq %r11, %rbx
        shldq $4, %r10, %rbx
        shrq $60, %r11
        subq %r11, %rbx
        shlq $4, %r10
        shrdq $4, %r11, %r10



        movq $0x5812631a5cf5d3ed, %rax
        mulq %rbx
        movq %rax, %rbp
        movq %rdx, %r11

        movq $0x14def9dea2f79cd6, %rax
        mulq %rbx
        addq %rax, %r11
        adcq $0, %rdx



        movq -8(%rcx,%rsi,8), %r12



        subq %rbp, %r12
        sbbq %r11, %r8
        sbbq %rdx, %r9
        sbbq $0, %r10





        sbbq %rbx, %rbx

        movq $0x5812631a5cf5d3ed, %rax
        andq %rbx, %rax
        movq $0x14def9dea2f79cd6, %rdx
        andq %rbx, %rdx
        movq $0x1000000000000000, %rbx
        andq %rax, %rbx

        addq %rax, %r12
        adcq %rdx, %r8
        adcq $0, %r9
        adcq %rbx, %r10



        movq %r10, %r11
        movq %r9, %r10
        movq %r8, %r9
        movq %r12, %r8

        decq %rsi
        jnz loop



writeback:

        movq %r8, (%rdi)
        movq %r9, 8(%rdi)
        movq %r10, 16(%rdi)
        movq %r11, 24(%rdi)



        popq %r12
        popq %rbp
        popq %rbx




        ret

shortinput:

        xorq %r8, %r8
        xorq %r9, %r9
        xorq %r10, %r10
        xorq %r11, %r11

        testq %rsi, %rsi
        jz writeback
        movq (%rdx), %r8
        decq %rsi
        jz writeback
        movq 8(%rdx), %r9
        decq %rsi
        jz writeback
        movq 16(%rdx), %r10
        jmp writeback


.section .note.GNU-stack,"",%progbits
