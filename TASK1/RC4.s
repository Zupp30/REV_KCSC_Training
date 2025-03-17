	.file	"RC4.c"
	.intel_syntax noprefix
	.text
	.globl	pt
	.bss
	.align 32
pt:
	.space 256
	.globl	key
	.align 32
key:
	.space 256
	.globl	s
	.align 32
s:
	.space 256
	.text
	.globl	swap
	.def	swap;	.scl	2;	.type	32;	.endef
	.seh_proc	swap
swap:
	push	rbp
	.seh_pushreg	rbp
	mov	rbp, rsp
	.seh_setframe	rbp, 0
	sub	rsp, 16
	.seh_stackalloc	16
	.seh_endprologue
	mov	QWORD PTR 16[rbp], rcx
	mov	QWORD PTR 24[rbp], rdx
	mov	rax, QWORD PTR 16[rbp]
	movzx	eax, BYTE PTR [rax]
	mov	BYTE PTR -1[rbp], al
	mov	rax, QWORD PTR 24[rbp]
	movzx	edx, BYTE PTR [rax]
	mov	rax, QWORD PTR 16[rbp]
	mov	BYTE PTR [rax], dl
	mov	rax, QWORD PTR 24[rbp]
	movzx	edx, BYTE PTR -1[rbp]
	mov	BYTE PTR [rax], dl
	nop
	add	rsp, 16
	pop	rbp
	ret
	.seh_endproc
	.section .rdata,"dr"
.LC0:
	.ascii "Plaintext: \0"
.LC1:
	.ascii "Key: \0"
	.text
	.globl	getInput
	.def	getInput;	.scl	2;	.type	32;	.endef
	.seh_proc	getInput
getInput:
	push	rbp
	.seh_pushreg	rbp
	mov	rbp, rsp
	.seh_setframe	rbp, 0
	sub	rsp, 48
	.seh_stackalloc	48
	.seh_endprologue
	mov	QWORD PTR 16[rbp], rcx
	mov	QWORD PTR 24[rbp], rdx
	lea	rax, .LC0[rip]
	mov	rcx, rax
	call	__mingw_printf
	mov	ecx, 0
	mov	rax, QWORD PTR __imp___acrt_iob_func[rip]
	call	rax
	mov	rdx, rax
	mov	rax, QWORD PTR 16[rbp]
	mov	r8, rdx
	mov	edx, 256
	mov	rcx, rax
	call	fgets
	mov	rax, QWORD PTR 16[rbp]
	mov	rcx, rax
	call	strlen
	mov	DWORD PTR -4[rbp], eax
	cmp	DWORD PTR -4[rbp], 0
	jle	.L3
	mov	eax, DWORD PTR -4[rbp]
	cdqe
	lea	rdx, -1[rax]
	mov	rax, QWORD PTR 16[rbp]
	add	rax, rdx
	movzx	eax, BYTE PTR [rax]
	cmp	al, 10
	jne	.L3
	mov	eax, DWORD PTR -4[rbp]
	cdqe
	lea	rdx, -1[rax]
	mov	rax, QWORD PTR 16[rbp]
	add	rax, rdx
	mov	BYTE PTR [rax], 0
.L3:
	lea	rax, .LC1[rip]
	mov	rcx, rax
	call	__mingw_printf
	mov	ecx, 0
	mov	rax, QWORD PTR __imp___acrt_iob_func[rip]
	call	rax
	mov	rdx, rax
	mov	rax, QWORD PTR 24[rbp]
	mov	r8, rdx
	mov	edx, 256
	mov	rcx, rax
	call	fgets
	mov	rax, QWORD PTR 24[rbp]
	mov	rcx, rax
	call	strlen
	mov	DWORD PTR -4[rbp], eax
	cmp	DWORD PTR -4[rbp], 0
	jle	.L5
	mov	eax, DWORD PTR -4[rbp]
	cdqe
	lea	rdx, -1[rax]
	mov	rax, QWORD PTR 24[rbp]
	add	rax, rdx
	movzx	eax, BYTE PTR [rax]
	cmp	al, 10
	jne	.L5
	mov	eax, DWORD PTR -4[rbp]
	cdqe
	lea	rdx, -1[rax]
	mov	rax, QWORD PTR 24[rbp]
	add	rax, rdx
	mov	BYTE PTR [rax], 0
.L5:
	nop
	add	rsp, 48
	pop	rbp
	ret
	.seh_endproc
	.globl	KSA
	.def	KSA;	.scl	2;	.type	32;	.endef
	.seh_proc	KSA
KSA:
	push	rbp
	.seh_pushreg	rbp
	mov	rbp, rsp
	.seh_setframe	rbp, 0
	sub	rsp, 48
	.seh_stackalloc	48
	.seh_endprologue
	mov	QWORD PTR 16[rbp], rcx
	mov	DWORD PTR 24[rbp], edx
	mov	DWORD PTR -4[rbp], 0
	jmp	.L7
.L8:
	mov	eax, DWORD PTR -4[rbp]
	mov	ecx, eax
	mov	eax, DWORD PTR -4[rbp]
	cdqe
	lea	rdx, s[rip]
	mov	BYTE PTR [rax+rdx], cl
	add	DWORD PTR -4[rbp], 1
.L7:
	cmp	DWORD PTR -4[rbp], 255
	jle	.L8
	mov	DWORD PTR -8[rbp], 0
	mov	DWORD PTR -12[rbp], 0
	jmp	.L9
.L10:
	mov	eax, DWORD PTR -12[rbp]
	cdqe
	lea	rdx, s[rip]
	movzx	eax, BYTE PTR [rax+rdx]
	movzx	edx, al
	mov	eax, DWORD PTR -8[rbp]
	lea	ecx, [rdx+rax]
	mov	eax, DWORD PTR -12[rbp]
	cdq
	idiv	DWORD PTR 24[rbp]
	mov	eax, edx
	movsx	rdx, eax
	mov	rax, QWORD PTR 16[rbp]
	add	rax, rdx
	movzx	eax, BYTE PTR [rax]
	movzx	eax, al
	lea	edx, [rcx+rax]
	mov	eax, edx
	sar	eax, 31
	shr	eax, 24
	add	edx, eax
	movzx	edx, dl
	sub	edx, eax
	mov	DWORD PTR -8[rbp], edx
	mov	eax, DWORD PTR -8[rbp]
	cdqe
	lea	rdx, s[rip]
	add	rdx, rax
	mov	eax, DWORD PTR -12[rbp]
	cdqe
	lea	rcx, s[rip]
	add	rax, rcx
	mov	rcx, rax
	call	swap
	add	DWORD PTR -12[rbp], 1
.L9:
	cmp	DWORD PTR -12[rbp], 255
	jle	.L10
	nop
	nop
	add	rsp, 48
	pop	rbp
	ret
	.seh_endproc
	.globl	PRGA
	.def	PRGA;	.scl	2;	.type	32;	.endef
	.seh_proc	PRGA
PRGA:
	push	rbp
	.seh_pushreg	rbp
	mov	rbp, rsp
	.seh_setframe	rbp, 0
	sub	rsp, 48
	.seh_stackalloc	48
	.seh_endprologue
	mov	QWORD PTR 16[rbp], rcx
	mov	DWORD PTR 24[rbp], edx
	mov	QWORD PTR 32[rbp], r8
	mov	DWORD PTR -4[rbp], 0
	mov	DWORD PTR -8[rbp], 0
	mov	DWORD PTR -12[rbp], 0
	jmp	.L12
.L13:
	mov	eax, DWORD PTR -4[rbp]
	lea	edx, 1[rax]
	mov	eax, edx
	sar	eax, 31
	shr	eax, 24
	add	edx, eax
	movzx	edx, dl
	sub	edx, eax
	mov	DWORD PTR -4[rbp], edx
	mov	eax, DWORD PTR -4[rbp]
	cdqe
	lea	rdx, s[rip]
	movzx	eax, BYTE PTR [rax+rdx]
	movzx	edx, al
	mov	eax, DWORD PTR -8[rbp]
	add	edx, eax
	mov	eax, edx
	sar	eax, 31
	shr	eax, 24
	add	edx, eax
	movzx	edx, dl
	sub	edx, eax
	mov	DWORD PTR -8[rbp], edx
	mov	eax, DWORD PTR -8[rbp]
	cdqe
	lea	rdx, s[rip]
	add	rdx, rax
	mov	eax, DWORD PTR -4[rbp]
	cdqe
	lea	rcx, s[rip]
	add	rax, rcx
	mov	rcx, rax
	call	swap
	mov	eax, DWORD PTR -4[rbp]
	cdqe
	lea	rdx, s[rip]
	movzx	ecx, BYTE PTR [rax+rdx]
	mov	eax, DWORD PTR -8[rbp]
	cdqe
	lea	rdx, s[rip]
	movzx	eax, BYTE PTR [rax+rdx]
	add	eax, ecx
	movzx	eax, al
	mov	DWORD PTR -16[rbp], eax
	mov	eax, DWORD PTR -12[rbp]
	movsx	rdx, eax
	mov	rax, QWORD PTR 32[rbp]
	add	rdx, rax
	mov	eax, DWORD PTR -16[rbp]
	cdqe
	lea	rcx, s[rip]
	movzx	eax, BYTE PTR [rax+rcx]
	mov	BYTE PTR [rdx], al
	add	DWORD PTR -12[rbp], 1
.L12:
	mov	eax, DWORD PTR -12[rbp]
	cmp	eax, DWORD PTR 24[rbp]
	jl	.L13
	nop
	nop
	add	rsp, 48
	pop	rbp
	ret
	.seh_endproc
	.globl	xoring
	.def	xoring;	.scl	2;	.type	32;	.endef
	.seh_proc	xoring
xoring:
	push	rbp
	.seh_pushreg	rbp
	mov	rbp, rsp
	.seh_setframe	rbp, 0
	sub	rsp, 16
	.seh_stackalloc	16
	.seh_endprologue
	mov	QWORD PTR 16[rbp], rcx
	mov	DWORD PTR 24[rbp], edx
	mov	QWORD PTR 32[rbp], r8
	mov	QWORD PTR 40[rbp], r9
	mov	DWORD PTR -4[rbp], 0
	jmp	.L15
.L16:
	mov	eax, DWORD PTR -4[rbp]
	movsx	rdx, eax
	mov	rax, QWORD PTR 16[rbp]
	add	rax, rdx
	movzx	r8d, BYTE PTR [rax]
	mov	eax, DWORD PTR -4[rbp]
	movsx	rdx, eax
	mov	rax, QWORD PTR 32[rbp]
	add	rax, rdx
	movzx	ecx, BYTE PTR [rax]
	mov	eax, DWORD PTR -4[rbp]
	movsx	rdx, eax
	mov	rax, QWORD PTR 40[rbp]
	add	rax, rdx
	mov	edx, r8d
	xor	edx, ecx
	mov	BYTE PTR [rax], dl
	add	DWORD PTR -4[rbp], 1
.L15:
	mov	eax, DWORD PTR -4[rbp]
	cmp	eax, DWORD PTR 24[rbp]
	jl	.L16
	nop
	nop
	add	rsp, 16
	pop	rbp
	ret
	.seh_endproc
	.section .rdata,"dr"
.LC2:
	.ascii "Encrypted text: \0"
.LC3:
	.ascii "%02X\0"
	.text
	.globl	main
	.def	main;	.scl	2;	.type	32;	.endef
	.seh_proc	main
main:
	push	rbp
	.seh_pushreg	rbp
	sub	rsp, 560
	.seh_stackalloc	560
	lea	rbp, 128[rsp]
	.seh_setframe	rbp, 128
	.seh_endprologue
	call	__main
	lea	rax, key[rip]
	mov	rdx, rax
	lea	rax, pt[rip]
	mov	rcx, rax
	call	getInput
	lea	rax, pt[rip]
	mov	rcx, rax
	call	strlen
	mov	DWORD PTR 424[rbp], eax
	lea	rax, key[rip]
	mov	rcx, rax
	call	strlen
	mov	DWORD PTR 420[rbp], eax
	mov	eax, DWORD PTR 420[rbp]
	mov	edx, eax
	lea	rax, key[rip]
	mov	rcx, rax
	call	KSA
	lea	rdx, 160[rbp]
	mov	eax, DWORD PTR 424[rbp]
	mov	r8, rdx
	mov	edx, eax
	lea	rax, pt[rip]
	mov	rcx, rax
	call	PRGA
	lea	rcx, -96[rbp]
	lea	rdx, 160[rbp]
	mov	eax, DWORD PTR 424[rbp]
	mov	r9, rcx
	mov	r8, rdx
	mov	edx, eax
	lea	rax, pt[rip]
	mov	rcx, rax
	call	xoring
	lea	rax, .LC2[rip]
	mov	rcx, rax
	call	__mingw_printf
	mov	DWORD PTR 428[rbp], 0
	jmp	.L18
.L19:
	mov	eax, DWORD PTR 428[rbp]
	cdqe
	movzx	eax, BYTE PTR -96[rbp+rax]
	movzx	eax, al
	mov	edx, eax
	lea	rax, .LC3[rip]
	mov	rcx, rax
	call	__mingw_printf
	add	DWORD PTR 428[rbp], 1
.L18:
	mov	eax, DWORD PTR 428[rbp]
	cmp	eax, DWORD PTR 424[rbp]
	jl	.L19
	mov	ecx, 10
	call	putchar
	mov	eax, 0
	add	rsp, 560
	pop	rbp
	ret
	.seh_endproc
	.def	__main;	.scl	2;	.type	32;	.endef
	.ident	"GCC: (Rev2, Built by MSYS2 project) 14.2.0"
	.def	fgets;	.scl	2;	.type	32;	.endef
	.def	strlen;	.scl	2;	.type	32;	.endef
	.def	putchar;	.scl	2;	.type	32;	.endef
