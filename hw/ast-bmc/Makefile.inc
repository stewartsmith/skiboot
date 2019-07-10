SUBDIRS += hw/ast-bmc

AST_BMC_OBJS  = ast-io.o ast-sf-ctrl.o
AST_BMC = hw/ast-bmc/built-in.a
$(AST_BMC): $(AST_BMC_OBJS:%=hw/ast-bmc/%)

AST_BMC_SURFBOOT_OBJS  = ast-io.o
AST_BMC_SURFBOOT = hw/ast-bmc/surfboot-built-in.a
$(AST_BMC_SURFBOOT): $(AST_BMC_SURFBOOT_OBJS:%=hw/ast-bmc/%)
