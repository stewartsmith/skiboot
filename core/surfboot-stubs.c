/* Copyright 2013-2019 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Casually evil stubs so that we can just link different targets.
 */

#include <stdbool.h>
#include <compiler.h>
#include <device.h>
#include <pci.h>
#include <pci-slot.h>
#include <occ.h>
#include <imc.h>
#include <nx.h>
#include <npu2.h>
#include <hmi.h>
#include <trace.h>
#include <p9_stop_api.H>
#include "ast.h"
#include <skiboot.h>

int last_phb_id = 0;
enum wakeup_engine_states wakeup_engine_state = WAKEUP_ENGINE_NOT_PRESENT;

int __attrconst parse_hdat(bool is_opal)
{
	(void)is_opal;
	return 0;
}

void add_fast_reboot_dt_entries(void)
{
}

void dt_add_cpufeatures(struct dt_node *root)
{
	(void)root;
}

void flash_fw_version_preload(void)
{
}

void flash_dt_add_fw_version(void)
{
}

void pci_init_slots(void)
{
}

struct pci_slot* __attrconst pci_slot_find(uint64_t id)
{
	(void)id;
	return NULL;
}

void disable_fast_reboot(const char *reason)
{
	(void)reason;
}

void fast_reboot(void)
{
}

void imc_catalog_preload(void)
{
}

void imc_init(void)
{
}

void slw_init(void)
{
}

int64_t __attrconst slw_reinit(uint64_t flags)
{
	(void)flags;
	return 0;
}

int __attrconst preload_capp_ucode(void)
{
	return 0;
}

void imc_decompress_catalog(void)
{
}

void nx_init(void)
{
}

void probe_phb3(void)
{
}

void probe_phb4(void)
{
}

void probe_npu(void)
{
}

void probe_npu2(void)
{
}

void prd_register_reserved_memory(void)
{
}

bool __attrconst occ_sensors_init(void)
{
	return true;
}

int __attrconst occ_sensor_group_enable(u32 group_hndl, int token, bool enable)
{
	(void)group_hndl;
	(void)token;
	(void)enable;

	return OPAL_CONSTRAINED;
}

int __attrconst occ_sensor_group_clear(u32 group_hndl, int token)
{
	(void)group_hndl;
	(void)token;

	return OPAL_CONSTRAINED;
}

int __attrconst occ_sensor_read(u32 handle, u64 *data)
{
	(void)handle;
	(void)data;

	return OPAL_CONSTRAINED;
}

void occ_send_dummy_interrupt(void)
{
}

void occ_p8_interrupt(uint32_t chip_id)
{
	(void)chip_id;
}

void occ_p9_interrupt(uint32_t chip_id)
{
	(void)chip_id;
}

void prd_init(void)
{
}

void prd_psi_interrupt(uint32_t proc)
{
	(void)proc;
}

void prd_sbe_passthrough(uint32_t proc)
{
	(void)proc;
}

void occ_pstates_init(void)
{
}

void occ_pnor_set_owner(enum pnor_owner owner)
{
	(void)owner;
}

bool __attrconst occ_get_gpu_presence(struct proc_chip *chip, int gpu_num)
{
	(void)chip;
	(void)gpu_num;
	return false;
}

void prd_occ_reset(uint32_t proc)
{
	(void)proc;
}

void npu2_i2c_presence_detect(struct npu2 *npu)
{
	(void)npu;
}

void find_capp_checkstop_reason(int flat_chip_id,
				struct OpalHMIEvent *hmi_evt,
				uint64_t *out_flags)
{
	(void)flat_chip_id;
	(void)hmi_evt;
	(void)out_flags;
}

void find_nx_checkstop_reason(int flat_chip_id,
			      struct OpalHMIEvent *hmi_evt,
			      uint64_t *out_flags)
{
	(void)flat_chip_id;
	(void)hmi_evt;
	(void)out_flags;
}

void find_npu_checkstop_reason(int flat_chip_id,
			       struct OpalHMIEvent *hmi_evt,
			       uint64_t *out_flags)
{
	(void)flat_chip_id;
	(void)hmi_evt;
	(void)out_flags;
}


void pci_slot_add_loc(struct pci_slot *slot,
                        struct dt_node *np, const char *label)
{
	(void)slot;
	(void)np;
	(void)label;
}

struct phb * __attrconst pci_get_phb(uint64_t phb_id)
{
	(void)phb_id;
	return NULL;
}

struct pci_device* __attrconst pci_walk_dev(struct phb *phb,
					    struct pci_device *pd,
					    int (*cb)(struct phb *,
						      struct pci_device *,
						      void *),
					    void *userdata)
{
	(void)phb;
	(void)pd;
	(void)cb;
	(void)userdata;
	return NULL;
}

struct pci_slot* __attrconst pcie_slot_create_dynamic(struct phb *phb,
						      struct pci_device *pd)
{
	(void)phb;
	(void)pd;

	return NULL;
}

struct pci_slot* __attrconst pcie_slot_create(struct phb *phb, struct pci_device *pd)
{
	(void)phb;
	(void)pd;
	return NULL;
}

struct dt_node* __attrconst map_pci_dev_to_slot(struct phb *phb, struct pci_device *pd)
{
	(void)phb;
	(void)pd;
	return NULL;
}

void init_trace_buffers(void)
{
}

void init_boot_tracebuf(struct cpu_thread *boot_cpu)
{
	(void)boot_cpu;
}

void trace_add(union trace *trace, u8 type, u16 len)
{
	(void)trace;
	(void)type;
	(void)len;
}

StopReturnCode_t __attrconst p9_stop_save_scom( void* const   i_pImage,
                                    const uint32_t i_scomAddress,
                                    const uint64_t i_scomData,
                                    const ScomOperation_t i_operation,
                                    const ScomSection_t i_section )
{
	(void)i_pImage;
	(void)i_scomAddress;
	(void)i_scomData;
	(void)i_operation;
	(void)i_section;

	return STOP_SAVE_SUCCESS;
}

int __attrconst ast_sf_open(uint8_t type, struct spi_flash_ctrl **ctrl)
{
	(void)type;
	(void)ctrl;

	return -ENODEV;
}

void ast_sf_close(struct spi_flash_ctrl *ctrl)
{
	(void)ctrl;
}
