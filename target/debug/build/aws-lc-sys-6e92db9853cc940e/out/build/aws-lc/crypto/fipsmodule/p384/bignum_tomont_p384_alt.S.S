# 0 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_tomont_p384_alt.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_tomont_p384_alt.S"
# 15 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_tomont_p384_alt.S"
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/include/_internal_s2n_bignum.h" 1
# 16 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_tomont_p384_alt.S" 2


        .globl bignum_tomont_p384_alt
        .hidden bignum_tomont_p384_alt
        .text
# 105 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_tomont_p384_alt.S"
bignum_tomont_p384_alt:
# 120 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_tomont_p384_alt.S"
        pushq %rbx
        pushq %r12
        pushq %r13
        pushq %r14
        pushq %r15





        movq $0xfffffffe00000001, %rbx
        movq (%rsi), %rax
        mulq %rbx
        movq %rax, %r8
        movq %rdx, %r9

        movq 8(%rsi), %rax
        mulq %rbx
        xorl %r10d, %r10d
        addq %rax, %r9
        adcq %rdx, %r10

        movq 16(%rsi), %rax
        mulq %rbx
        xorl %r11d, %r11d
        addq %rax, %r10
        adcq %rdx, %r11

        movq 24(%rsi), %rax
        mulq %rbx
        xorl %r12d, %r12d
        addq %rax, %r11
        adcq %rdx, %r12

        movq 32(%rsi), %rax
        mulq %rbx
        xorl %r13d, %r13d
        addq %rax, %r12
        adcq %rdx, %r13

        movq 40(%rsi), %rax
        mulq %rbx
        xorl %r14d, %r14d
        addq %rax, %r13
        adcq %rdx, %r14

        xorl %r15d, %r15d



        movq %r8, %rbx 
 shlq $32, %rbx 
 addq %r8, %rbx 
 xorl %ecx, %ecx 
 movq $0xffffffff00000001, %rax 
 mulq %rbx
 movq %rdx, %r8 
 movq $0x00000000ffffffff, %rax 
 mulq %rbx
 addq %r8, %rax 
 adcq %rbx, %rdx 
 adcl %ecx, %ecx 
 subq %rax, %r9 
 sbbq %rdx, %r10 
 sbbq %rcx, %r11 
 sbbq $0, %r12 
 sbbq $0, %r13 
 sbbq $0, %rbx 
 addq %rbx, %r14 
 adcq $0, %r15



        movq $0x0000000200000000, %rbx
        movq (%rsi), %rax 
 mulq %rbx
 addq %rax, %r9 
 adcq %rdx, %r10 
 sbbq %r8, %r8
        movq 8(%rsi), %rax 
 mulq %rbx
 subq %r8, %rdx 
 addq %rax, %r10 
 adcq %rdx, %r11 
 sbbq %r8, %r8
        movq 16(%rsi), %rax 
 mulq %rbx
 subq %r8, %rdx 
 addq %rax, %r11 
 adcq %rdx, %r12 
 sbbq %r8, %r8
        movq 24(%rsi), %rax 
 mulq %rbx
 subq %r8, %rdx 
 addq %rax, %r12 
 adcq %rdx, %r13 
 sbbq %r8, %r8
        movq 32(%rsi), %rax 
 mulq %rbx
 subq %r8, %rdx 
 addq %rax, %r13 
 adcq %rdx, %r14 
 sbbq %r8, %r8
        movq 40(%rsi), %rax 
 mulq %rbx
 subq %r8, %rdx 
 addq %rax, %r14 
 adcq %rdx, %r15 
 sbbq %r8, %r8
        negq %r8



        movq %r9, %rbx 
 shlq $32, %rbx 
 addq %r9, %rbx 
 xorl %ecx, %ecx 
 movq $0xffffffff00000001, %rax 
 mulq %rbx
 movq %rdx, %r9 
 movq $0x00000000ffffffff, %rax 
 mulq %rbx
 addq %r9, %rax 
 adcq %rbx, %rdx 
 adcl %ecx, %ecx 
 subq %rax, %r10 
 sbbq %rdx, %r11 
 sbbq %rcx, %r12 
 sbbq $0, %r13 
 sbbq $0, %r14 
 sbbq $0, %rbx 
 addq %rbx, %r15 
 adcq $0, %r8



        movq $0xfffffffe00000000, %rbx
        movq (%rsi), %rax 
 mulq %rbx
 addq %rax, %r10 
 adcq %rdx, %r11 
 sbbq %r9, %r9
        movq 8(%rsi), %rax 
 mulq %rbx
 subq %r9, %rdx 
 addq %rax, %r11 
 adcq %rdx, %r12 
 sbbq %r9, %r9
        movq 16(%rsi), %rax 
 mulq %rbx
 subq %r9, %rdx 
 addq %rax, %r12 
 adcq %rdx, %r13 
 sbbq %r9, %r9
        movq 24(%rsi), %rax 
 mulq %rbx
 subq %r9, %rdx 
 addq %rax, %r13 
 adcq %rdx, %r14 
 sbbq %r9, %r9
        movq 32(%rsi), %rax 
 mulq %rbx
 subq %r9, %rdx 
 addq %rax, %r14 
 adcq %rdx, %r15 
 sbbq %r9, %r9
        movq 40(%rsi), %rax 
 mulq %rbx
 subq %r9, %rdx 
 addq %rax, %r15 
 adcq %rdx, %r8 
 sbbq %r9, %r9
        negq %r9



        movq %r10, %rbx 
 shlq $32, %rbx 
 addq %r10, %rbx 
 xorl %ecx, %ecx 
 movq $0xffffffff00000001, %rax 
 mulq %rbx
 movq %rdx, %r10 
 movq $0x00000000ffffffff, %rax 
 mulq %rbx
 addq %r10, %rax 
 adcq %rbx, %rdx 
 adcl %ecx, %ecx 
 subq %rax, %r11 
 sbbq %rdx, %r12 
 sbbq %rcx, %r13 
 sbbq $0, %r14 
 sbbq $0, %r15 
 sbbq $0, %rbx 
 addq %rbx, %r8 
 adcq $0, %r9



        movq $0x0000000200000000, %rbx
        movq (%rsi), %rax 
 mulq %rbx
 addq %rax, %r11 
 adcq %rdx, %r12 
 sbbq %r10, %r10
        movq 8(%rsi), %rax 
 mulq %rbx
 subq %r10, %rdx 
 addq %rax, %r12 
 adcq %rdx, %r13 
 sbbq %r10, %r10
        movq 16(%rsi), %rax 
 mulq %rbx
 subq %r10, %rdx 
 addq %rax, %r13 
 adcq %rdx, %r14 
 sbbq %r10, %r10
        movq 24(%rsi), %rax 
 mulq %rbx
 subq %r10, %rdx 
 addq %rax, %r14 
 adcq %rdx, %r15 
 sbbq %r10, %r10
        movq 32(%rsi), %rax 
 mulq %rbx
 subq %r10, %rdx 
 addq %rax, %r15 
 adcq %rdx, %r8 
 sbbq %r10, %r10
        movq 40(%rsi), %rax 
 mulq %rbx
 subq %r10, %rdx 
 addq %rax, %r8 
 adcq %rdx, %r9 
 sbbq %r10, %r10
        negq %r10



        movq %r11, %rbx 
 shlq $32, %rbx 
 addq %r11, %rbx 
 xorl %ecx, %ecx 
 movq $0xffffffff00000001, %rax 
 mulq %rbx
 movq %rdx, %r11 
 movq $0x00000000ffffffff, %rax 
 mulq %rbx
 addq %r11, %rax 
 adcq %rbx, %rdx 
 adcl %ecx, %ecx 
 subq %rax, %r12 
 sbbq %rdx, %r13 
 sbbq %rcx, %r14 
 sbbq $0, %r15 
 sbbq $0, %r8 
 sbbq $0, %rbx 
 addq %rbx, %r9 
 adcq $0, %r10




        xorq %r11, %r11
        addq (%rsi), %r12
        adcq 8(%rsi), %r13
        adcq 16(%rsi), %r14
        adcq 24(%rsi), %r15
        adcq 32(%rsi), %r8
        adcq 40(%rsi), %r9
        adcq %r11, %r10
        adcq %r11, %r11



        movq %r12, %rbx 
 shlq $32, %rbx 
 addq %r12, %rbx 
 xorl %ecx, %ecx 
 movq $0xffffffff00000001, %rax 
 mulq %rbx
 movq %rdx, %r12 
 movq $0x00000000ffffffff, %rax 
 mulq %rbx
 addq %r12, %rax 
 adcq %rbx, %rdx 
 adcl %ecx, %ecx 
 subq %rax, %r13 
 sbbq %rdx, %r14 
 sbbq %rcx, %r15 
 sbbq $0, %r8 
 sbbq $0, %r9 
 sbbq $0, %rbx 
 addq %rbx, %r10 
 adcq $0, %r11




        xorq %r12, %r12



        movq %r13, %rbx 
 shlq $32, %rbx 
 addq %r13, %rbx 
 xorl %ecx, %ecx 
 movq $0xffffffff00000001, %rax 
 mulq %rbx
 movq %rdx, %r13 
 movq $0x00000000ffffffff, %rax 
 mulq %rbx
 addq %r13, %rax 
 adcq %rbx, %rdx 
 adcl %ecx, %ecx 
 subq %rax, %r14 
 sbbq %rdx, %r15 
 sbbq %rcx, %r8 
 sbbq $0, %r9 
 sbbq $0, %r10 
 sbbq $0, %rbx 
 addq %rbx, %r11 
 adcq $0, %r12
# 252 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_tomont_p384_alt.S"
        movq $0xffffffff00000001, %rdx
        movl $0x00000000ffffffff, %ecx
        movl $0x0000000000000001, %esi




        movq %r14, %rax
        addq %rdx, %rax
        movq %r15, %rax
        adcq %rcx, %rax
        movq %r8, %rax
        adcq %rsi, %rax
        movq %r9, %rax
        adcq $0, %rax
        movq %r10, %rax
        adcq $0, %rax
        movq %r11, %rax
        adcq $0, %rax




        adcq $0, %r12



        negq %r12



        andq %r12, %rdx
        andq %r12, %rcx
        andq %r12, %rsi

        addq %rdx, %r14
        adcq %rcx, %r15
        adcq %rsi, %r8
        adcq $0, %r9
        adcq $0, %r10
        adcq $0, %r11



        movq %r14, (%rdi)
        movq %r15, 8(%rdi)
        movq %r8, 16(%rdi)
        movq %r9, 24(%rdi)
        movq %r10, 32(%rdi)
        movq %r11, 40(%rdi)



        popq %r15
        popq %r14
        popq %r13
        popq %r12
        popq %rbx





        ret


.section .note.GNU-stack,"",%progbits
