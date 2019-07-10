# -*-Makefile-*-
SUBDIRS += hw
HW_OBJS  = xscom.o chiptod.o lpc.o lpc-uart.o psi.o
HW_OBJS += homer.o fsi-master.o centaur.o
HW_OBJS += sfc-ctrl.o fake-rtc.o bt.o p8-i2c.o
HW_OBJS += dts.o lpc-rtc.o xive.o
HW_OBJS += fake-nvram.o lpc-mbox.o
HW_OBJS += phys-map.o sbe-p9.o
HW_OBJS += vas.o sbe-p8.o dio-p9.o
HW_OBJS += lpc-port80h.o
HW=hw/built-in.a

SKIBOOT_HW_OBJS  = slw.o occ.o imc.o
SKIBOOT_HW_OBJS += nx.o nx-rng.o nx-crypto.o nx-compress.o nx-842.o nx-gzip.o
SKIBOOT_HW_OBJS += phb3.o phb4.o prd.o
SKIBOOT_HW_OBJS += npu.o npu-hw-procedures.o
SKIBOOT_HW_OBJS += npu2-common.o npu2.o npu2-opencapi.o npu2-hw-procedures.o
SKIBOOT_HW_OBJS += capp.o occ-sensor.o vas.o

include $(SRC)/hw/ast-bmc/Makefile.inc
include $(SRC)/hw/ipmi/Makefile.inc

$(HW): $(HW_OBJS:%=hw/%) $(EC) $(AST_BMC) $(IPMI)

SKIBOOT_HW=hw/skiboot-built-in.a
SURFBOOT_HW=hw/surfboot-built-in.a

$(SKIBOOT_HW): $(HW_OBJS:%=hw/%) $(SKIBOOT_HW_OBJS:%=hw/%) $(EC) $(AST_BMC) $(IPMI)
$(SURFBOOT_HW): $(HW_OBJS:%=hw/%) $(EC) $(AST_BMC_SURFBOOT) $(IPMI)
