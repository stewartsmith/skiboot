PLATDIR = platforms

SUBDIRS += $(PLATDIR)
PLATFORMS = $(PLATDIR)/built-in.a
NO_FSP_PLATFORMS = $(PLATDIR)/nofsp-built-in.a

include $(SRC)/$(PLATDIR)/ibm-fsp/Makefile.inc
include $(SRC)/$(PLATDIR)/rhesus/Makefile.inc
include $(SRC)/$(PLATDIR)/astbmc/Makefile.inc
include $(SRC)/$(PLATDIR)/mambo/Makefile.inc
include $(SRC)/$(PLATDIR)/qemu/Makefile.inc

$(PLATFORMS): $(IBM_FSP) $(RHESUS) $(ASTBMC) $(MAMBO) $(QEMU)

$(NO_FSP_PLATFORMS): $(RHESUS) $(ASTBMC) $(MAMBO) $(QEMU)
