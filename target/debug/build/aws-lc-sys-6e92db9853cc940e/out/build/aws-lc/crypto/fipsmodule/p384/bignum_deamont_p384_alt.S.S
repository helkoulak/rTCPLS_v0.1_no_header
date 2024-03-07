# 0 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_deamont_p384_alt.S"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_deamont_p384_alt.S"
# 18 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_deamont_p384_alt.S"
# 1 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/include/_internal_s2n_bignum.h" 1
# 19 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_deamont_p384_alt.S" 2


        .globl bignum_deamont_p384_alt
        .hidden bignum_deamont_p384_alt
        .text
# 73 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_deamont_p384_alt.S"
bignum_deamont_p384_alt:
# 84 "/home/helkoulak/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.13.2/aws-lc/third_party/s2n-bignum/x86_att/p384/bignum_deamont_p384_alt.S"
        pushq %r12
        pushq %r13



        movq (%rsi), %r8
        movq 8(%rsi), %r9
        movq 16(%rsi), %r10
        movq 24(%rsi), %r11
        movq 32(%rsi), %r12
        movq 40(%rsi), %r13



        movq %r8, %rcx 
 shlq $32, %rcx 
 addq %r8, %rcx 
 movq $0xffffffff00000001, %rax 
 mulq %rcx
 movq %rdx, %r8 
 movq $0x00000000ffffffff, %rax 
 mulq %rcx
 addq %rax, %r8 
 movl $0, %eax 
 adcq %rcx, %rdx 
 adcl %eax, %eax 
 subq %r8, %r9 
 sbbq %rdx, %r10 
 sbbq %rax, %r11 
 sbbq $0, %r12 
 sbbq $0, %r13 
 movq %rcx, %r8 
 sbbq $0, %r8



        movq %r9, %rcx 
 shlq $32, %rcx 
 addq %r9, %rcx 
 movq $0xffffffff00000001, %rax 
 mulq %rcx
 movq %rdx, %r9 
 movq $0x00000000ffffffff, %rax 
 mulq %rcx
 addq %rax, %r9 
 movl $0, %eax 
 adcq %rcx, %rdx 
 adcl %eax, %eax 
 subq %r9, %r10 
 sbbq %rdx, %r11 
 sbbq %rax, %r12 
 sbbq $0, %r13 
 sbbq $0, %r8 
 movq %rcx, %r9 
 sbbq $0, %r9



        movq %r10, %rcx 
 shlq $32, %rcx 
 addq %r10, %rcx 
 movq $0xffffffff00000001, %rax 
 mulq %rcx
 movq %rdx, %r10 
 movq $0x00000000ffffffff, %rax 
 mulq %rcx
 addq %rax, %r10 
 movl $0, %eax 
 adcq %rcx, %rdx 
 adcl %eax, %eax 
 subq %r10, %r11 
 sbbq %rdx, %r12 
 sbbq %rax, %r13 
 sbbq $0, %r8 
 sbbq $0, %r9 
 movq %rcx, %r10 
 sbbq $0, %r10



        movq %r11, %rcx 
 shlq $32, %rcx 
 addq %r11, %rcx 
 movq $0xffffffff00000001, %rax 
 mulq %rcx
 movq %rdx, %r11 
 movq $0x00000000ffffffff, %rax 
 mulq %rcx
 addq %rax, %r11 
 movl $0, %eax 
 adcq %rcx, %rdx 
 adcl %eax, %eax 
 subq %r11, %r12 
 sbbq %rdx, %r13 
 sbbq %rax, %r8 
 sbbq $0, %r9 
 sbbq $0, %r10 
 movq %rcx, %r11 
 sbbq $0, %r11



        movq %r12, %rcx 
 shlq $32, %rcx 
 addq %r12, %rcx 
 movq $0xffffffff00000001, %rax 
 mulq %rcx
 movq %rdx, %r12 
 movq $0x00000000ffffffff, %rax 
 mulq %rcx
 addq %rax, %r12 
 movl $0, %eax 
 adcq %rcx, %rdx 
 adcl %eax, %eax 
 subq %r12, %r13 
 sbbq %rdx, %r8 
 sbbq %rax, %r9 
 sbbq $0, %r10 
 sbbq $0, %r11 
 movq %rcx, %r12 
 sbbq $0, %r12



        movq %r13, %rcx 
 shlq $32, %rcx 
 addq %r13, %rcx 
 movq $0xffffffff00000001, %rax 
 mulq %rcx
 movq %rdx, %r13 
 movq $0x00000000ffffffff, %rax 
 mulq %rcx
 addq %rax, %r13 
 movl $0, %eax 
 adcq %rcx, %rdx 
 adcl %eax, %eax 
 subq %r13, %r8 
 sbbq %rdx, %r9 
 sbbq %rax, %r10 
 sbbq $0, %r11 
 sbbq $0, %r12 
 movq %rcx, %r13 
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
