	.section	__TEXT,__text,regular,pure_instructions
	.macosx_version_min 15, 0
	.globl	_foo
	.align	4, 0x90
_foo:                                   ## @foo
	.cfi_startproc
## BB#0:
	movq	_test@GOTPCREL(%rip), %rax
	retq
	.cfi_endproc


.subsections_via_symbols
