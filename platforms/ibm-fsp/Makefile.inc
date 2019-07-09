SUBDIRS += $(PLATDIR)/ibm-fsp

IBM_FSP_OBJS = common.o lxvpd.o hostservices.o fsp-vpd.o \
	       firenze.o firenze-pci.o zz.o
IBM_FSP = $(PLATDIR)/ibm-fsp/built-in.a

include $(SRC)/$(PLATDIR)/ibm-fsp/hw/Makefile.inc

ifeq ($(CONFIG_FSP),1)
$(IBM_FSP): $(IBM_FSP_OBJS:%=$(PLATDIR)/ibm-fsp/%) $(FSP_HW_OBJS)
endif
