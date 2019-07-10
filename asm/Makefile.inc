# -*-Makefile-*-

SUBDIRS += asm 
ASM_OBJS = head.o misc.o kernel-wrapper.o cvc_entry.o
ASM=asm/built-in.a

SURFBOOT_ASM_OBJS = surfboot-head.o misc.o cvc_entry.o
SURFBOOT_ASM=asm/surfboot-built-in.a

# Add extra dependency to the kernel wrapper
kernel_wrapper.o : $(KERNEL)

$(ASM): $(ASM_OBJS:%=asm/%)

$(SURFBOOT_ASM): $(SURFBOOT_ASM_OBJS:%=asm/%)
