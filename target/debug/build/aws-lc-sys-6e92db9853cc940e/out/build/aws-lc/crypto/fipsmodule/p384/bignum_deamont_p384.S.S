# 0 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_deamont_p384.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_deamont_p384.S"
# 18 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_deamont_p384.S"
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/include/_internal_s2n_bignum.h" 1
# 19 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_deamont_p384.S" 2


        .globl bignum_deamont_p384
        .hidden bignum_deamont_p384
        .text
# 73 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_deamont_p384.S"
bignum_deamont_p384:
# 84 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_deamont_p384.S"
        pushq %r12
        pushq %r13



        movq (%rsi), %r8
        movq 8(%rsi), %r9
        movq 16(%rsi), %r10
        movq 24(%rsi), %r11
        movq 32(%rsi), %r12
        movq 40(%rsi), %r13



        movq %r8, %rdx 
 shlq $32, %rdx 
 addq %r8, %rdx 
 xorq %rsi, %rsi 
 movq $0xffffffff00000001, %rax 
 mulxq %rax, %rcx, %rax 
 movl $0x00000000ffffffff, %ecx 
 mulxq %rcx, %r8, %rcx 
 adcq %r8, %rax 
 adcq %rdx, %rcx 
 adcq $0, %rsi 
 subq %rax, %r9 
 sbbq %rcx, %r10 
 sbbq %rsi, %r11 
 sbbq $0, %r12 
 sbbq $0, %r13 
 movq %rdx, %r8 
 sbbq $0, %r8



        movq %r9, %rdx 
 shlq $32, %rdx 
 addq %r9, %rdx 
 xorq %rsi, %rsi 
 movq $0xffffffff00000001, %rax 
 mulxq %rax, %rcx, %rax 
 movl $0x00000000ffffffff, %ecx 
 mulxq %rcx, %r9, %rcx 
 adcq %r9, %rax 
 adcq %rdx, %rcx 
 adcq $0, %rsi 
 subq %rax, %r10 
 sbbq %rcx, %r11 
 sbbq %rsi, %r12 
 sbbq $0, %r13 
 sbbq $0, %r8 
 movq %rdx, %r9 
 sbbq $0, %r9



        movq %r10, %rdx 
 shlq $32, %rdx 
 addq %r10, %rdx 
 xorq %rsi, %rsi 
 movq $0xffffffff00000001, %rax 
 mulxq %rax, %rcx, %rax 
 movl $0x00000000ffffffff, %ecx 
 mulxq %rcx, %r10, %rcx 
 adcq %r10, %rax 
 adcq %rdx, %rcx 
 adcq $0, %rsi 
 subq %rax, %r11 
 sbbq %rcx, %r12 
 sbbq %rsi, %r13 
 sbbq $0, %r8 
 sbbq $0, %r9 
 movq %rdx, %r10 
 sbbq $0, %r10



        movq %r11, %rdx 
 shlq $32, %rdx 
 addq %r11, %rdx 
 xorq %rsi, %rsi 
 movq $0xffffffff00000001, %rax 
 mulxq %rax, %rcx, %rax 
 movl $0x00000000ffffffff, %ecx 
 mulxq %rcx, %r11, %rcx 
 adcq %r11, %rax 
 adcq %rdx, %rcx 
 adcq $0, %rsi 
 subq %rax, %r12 
 sbbq %rcx, %r13 
 sbbq %rsi, %r8 
 sbbq $0, %r9 
 sbbq $0, %r10 
 movq %rdx, %r11 
 sbbq $0, %r11



        movq %r12, %rdx 
 shlq $32, %rdx 
 addq %r12, %rdx 
 xorq %rsi, %rsi 
 movq $0xffffffff00000001, %rax 
 mulxq %rax, %rcx, %rax 
 movl $0x00000000ffffffff, %ecx 
 mulxq %rcx, %r12, %rcx 
 adcq %r12, %rax 
 adcq %rdx, %rcx 
 adcq $0, %rsi 
 subq %rax, %r13 
 sbbq %rcx, %r8 
 sbbq %rsi, %r9 
 sbbq $0, %r10 
 sbbq $0, %r11 
 movq %rdx, %r12 
 sbbq $0, %r12



        movq %r13, %rdx 
 shlq $32, %rdx 
 addq %r13, %rdx 
 xorq %rsi, %rsi 
 movq $0xffffffff00000001, %rax 
 mulxq %rax, %rcx, %rax 
 movl $0x00000000ffffffff, %ecx 
 mulxq %rcx, %r13, %rcx 
 adcq %r13, %rax 
 adcq %rdx, %rcx 
 adcq $0, %rsi 
 subq %rax, %r8 
 sbbq %rcx, %r9 
 sbbq %rsi, %r10 
 sbbq $0, %r11 
 sbbq $0, %r12 
 movq %rdx, %r13 
 sbbq $0, %r13





        movq $0xffffffff00000001, %rax
        movl $0x00000000ffffffff, %ecx

        movq %r8, %rdx
        addq %rax, %rdx
        movq %r9, %rdx
        adcq %rcx, %rdx
        movq %r10, %rdx
        adcq $1, %rdx
        movq %r11, %rdx
        adcq $0, %rdx
        movq %r12, %rdx
        adcq $0, %rdx
        movq %r13, %rdx
        adcq $0, %rdx



        sbbq %rdx, %rdx



        andq %rdx, %rax
        andq %rdx, %rcx
        andq $1, %rdx

        addq %rax, %r8
        adcq %rcx, %r9
        adcq %rdx, %r10
        adcq $0, %r11
        adcq $0, %r12
        adcq $0, %r13



        movq %r8, (%rdi)
        movq %r9, 8(%rdi)
        movq %r10, 16(%rdi)
        movq %r11, 24(%rdi)
        movq %r12, 32(%rdi)
        movq %r13, 40(%rdi)



        popq %r13
        popq %r12





        ret


.section .note.GNU-stack,"",%progbits
