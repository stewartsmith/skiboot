# -*-Makefile-*-

SUBDIRS += core
CORE_OBJS = relocate.o console.o stack.o init.o chip.o mem_region.o
CORE_OBJS += malloc.o lock.o cpu.o utils.o fdt.o interrupts.o timebase.o
CORE_OBJS += device.o exceptions.o affinity.o
CORE_OBJS += vpd.o platform.o nvram.o nvram-format.o hmi.o
CORE_OBJS += console-log.o ipmi.o  ipmi-opal.o time-utils.o
CORE_OBJS += pel.o pool.o errorlog.o
CORE_OBJS += timer.o i2c.o rtc.o flash.o sensor.o
CORE_OBJS += flash-subpartition.o bitmap.o buddy.o
CORE_OBJS += direct-controls.o
CORE_OBJS += opal.o opal-msg.o

SKIBOOT_CORE_OBJS  = mem_map.o trace.o
SKIBOOT_CORE_OBJS += pci.o pci-virt.o pci-slot.o pcie-slot.o
SKIBOOT_CORE_OBJS += pci-opal.o fast-reboot.o
SKIBOOT_CORE_OBJS += pci-quirk.o powercap.o psr.o pci-dt-slot.o
SKIBOOT_CORE_OBJS += flash-firmware-versions.o cpufeatures.o
SKIBOOT_CORE_OBJS += npu-hmi.o npu2-hmi.o capp-hmi.o nx-hmi.o
SKIBOOT_CORE_OBJS += console-section.o

ifeq ($(SKIBOOT_GCOV),1)
CORE_OBJS += gcov-profiling.o
CFLAGS_SKIP_core/gcov-profiling.o = -Wsuggest-attribute=const
endif

CORE=core/built-in.a

CFLAGS_SKIP_core/relocate.o = -pg -fstack-protector-all
CFLAGS_SKIP_core/relocate.o += -fstack-protector -fstack-protector-strong
CFLAGS_SKIP_core/relocate.o += -fprofile-arcs -ftest-coverage

$(CORE): $(CORE_OBJS:%=core/%)

SURFBOOT_CORE_OBJS = surfboot-stubs.o surfboot-mem_map.o surfboot-console-section.o

SURFBOOT_CORE=core/surfboot-built-in.a
SKIBOOT_CORE=core/skiboot-built-in.a

$(SURFBOOT_CORE): $(CORE_OBJS:%=core/%) $(SURFBOOT_CORE_OBJS:%=core/%)
$(SKIBOOT_CORE): $(CORE_OBJS:%=core/%) $(SKIBOOT_CORE_OBJS:%=core/%)
