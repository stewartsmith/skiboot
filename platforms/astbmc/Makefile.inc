SUBDIRS += $(PLATDIR)/astbmc

ASTBMC_OBJS = pnor.o common.o slots.o \
	      palmetto.o habanero.o firestone.o \
	      p8dtu.o p8dnu.o \
	      garrison.o barreleye.o \
	      witherspoon.o zaius.o romulus.o p9dsu.o \
	      vesnin.o nicole.o \
	      talos.o

ASTBMC = $(PLATDIR)/astbmc/built-in.a
$(ASTBMC): $(ASTBMC_OBJS:%=$(PLATDIR)/astbmc/%)

ASTBMC_SURFBOOT_OBJS = pnor.o common.o surfboot.o
ASTBMC_SURFBOOT = $(PLATDIR)/astbmc/surfboot-built-in.a

$(ASTBMC_SURFBOOT): $(ASTBMC_SURFBOOT_OBJS:%=$(PLATDIR)/astbmc/%)