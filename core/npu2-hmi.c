/* Copyright 2013-2018 IBM Corp.
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

#define pr_fmt(fmt)	"NPU2HMI: " fmt

#include <skiboot.h>
#include <opal.h>
#include <opal-msg.h>
#include <processor.h>
#include <chiptod.h>
#include <xscom.h>
#include <xscom-p8-regs.h>
#include <xscom-p9-regs.h>
#include <pci.h>
#include <cpu.h>
#include <chip.h>
#include <npu-regs.h>
#include <npu2-regs.h>
#include <npu2.h>
#include <npu.h>
#include <capp.h>
#include <nvram.h>
#include <cpu.h>
#include <hmi.h>

static bool phb_is_npu2(struct dt_node *dn)
{
	return (dt_node_is_compatible(dn, "ibm,power9-npu-pciex") ||
		dt_node_is_compatible(dn, "ibm,power9-npu-opencapi-pciex"));
}

static void add_npu2_xstop_reason(uint32_t *xstop_reason, uint8_t reason)
{
	int i, reason_count;
	uint8_t *ptr;

	reason_count = sizeof(*xstop_reason) / sizeof(reason);
	ptr = (uint8_t *) xstop_reason;
	for (i = 0; i < reason_count; i++) {
		if (*ptr == 0) {
			*ptr = reason;
			break;
		}
		ptr++;
	}
}

static void encode_npu2_xstop_reason(uint32_t *xstop_reason,
				uint64_t fir, int fir_number)
{
	int bit;
	uint8_t reason;

	/*
	 * There are three 64-bit FIRs but the xstop reason field of
	 * the hmi event is only 32-bit. Encode which FIR bit is set as:
	 * - 2 bits for the FIR number
	 * - 6 bits for the bit number (0 -> 63)
	 *
	 * So we could even encode up to 4 reasons for the HMI, if
	 * that can ever happen
	 */
	while (fir) {
		bit = ilog2(fir);
		reason = fir_number << 6;
		reason |= (63 - bit); // IBM numbering
		add_npu2_xstop_reason(xstop_reason, reason);
		fir ^= 1ULL << bit;
	}
}

void find_npu2_checkstop_reason(int flat_chip_id,
				struct OpalHMIEvent *hmi_evt,
				uint64_t *out_flags)
{
	struct phb *phb;
	int i;
	bool npu2_hmi_verbose = false, found = false;
	uint64_t npu2_fir;
	uint64_t npu2_fir_mask;
	uint64_t npu2_fir_action0;
	uint64_t npu2_fir_action1;
	uint64_t npu2_fir_addr;
	uint64_t npu2_fir_mask_addr;
	uint64_t npu2_fir_action0_addr;
	uint64_t npu2_fir_action1_addr;
	uint64_t fatal_errors;
	uint32_t xstop_reason = 0;
	int total_errors = 0;
	const char *loc;

	/* Find the NPU on the chip associated with the HMI. */
	for_each_phb(phb) {
		/* NOTE: if a chip ever has >1 NPU this will need adjusting */
		if (phb_is_npu2(phb->dt_node) &&
		    (dt_get_chip_id(phb->dt_node) == flat_chip_id)) {
			found = true;
			break;
		}
	}

	/* If we didn't find a NPU on the chip, it's not our checkstop. */
	if (!found)
		return;

	npu2_fir_addr = NPU2_FIR_REGISTER_0;
	npu2_fir_mask_addr = NPU2_FIR_REGISTER_0 + NPU2_FIR_MASK_OFFSET;
	npu2_fir_action0_addr = NPU2_FIR_REGISTER_0 + NPU2_FIR_ACTION0_OFFSET;
	npu2_fir_action1_addr = NPU2_FIR_REGISTER_0 + NPU2_FIR_ACTION1_OFFSET;

	for (i = 0; i < NPU2_TOTAL_FIR_REGISTERS; i++) {
		/* Read all the registers necessary to find a checkstop condition. */
		if (xscom_read(flat_chip_id, npu2_fir_addr, &npu2_fir) ||
			xscom_read(flat_chip_id, npu2_fir_mask_addr, &npu2_fir_mask) ||
			xscom_read(flat_chip_id, npu2_fir_action0_addr, &npu2_fir_action0) ||
			xscom_read(flat_chip_id, npu2_fir_action1_addr, &npu2_fir_action1)) {
			prerror("HMI: Couldn't read NPU FIR register%d with XSCOM\n", i);
			continue;
		}

		fatal_errors = npu2_fir & ~npu2_fir_mask & npu2_fir_action0 & npu2_fir_action1;

		if (fatal_errors) {
			loc = chip_loc_code(flat_chip_id);
			if (!loc)
				loc = "Not Available";
			prlog(PR_ERR, "NPU: [Loc: %s] P:%d FIR#%d FIR 0x%016llx mask 0x%016llx\n",
					loc, flat_chip_id, i, npu2_fir, npu2_fir_mask);
			prlog(PR_ERR, "NPU: [Loc: %s] P:%d ACTION0 0x%016llx, ACTION1 0x%016llx\n",
					loc, flat_chip_id, npu2_fir_action0, npu2_fir_action1);
			total_errors++;

			encode_npu2_xstop_reason(&xstop_reason, fatal_errors, i);
		}

		/* Can't do a fence yet, we are just logging fir information for now */
		npu2_fir_addr += NPU2_FIR_OFFSET;
		npu2_fir_mask_addr += NPU2_FIR_OFFSET;
		npu2_fir_action0_addr += NPU2_FIR_OFFSET;
		npu2_fir_action1_addr += NPU2_FIR_OFFSET;

	}

	if (!total_errors)
		return;

	npu2_hmi_verbose = nvram_query_eq_safe("npu2-hmi-verbose", "true");
	/* Force this for now until we sort out something better */
	npu2_hmi_verbose = true;

	if (npu2_hmi_verbose) {
		npu2_dump_scoms(flat_chip_id);
		prlog(PR_ERR, " _________________________ \n");
		prlog(PR_ERR, "<    It's Debug time!     >\n");
		prlog(PR_ERR, " ------------------------- \n");
		prlog(PR_ERR, "       \\   ,__,            \n");
		prlog(PR_ERR, "        \\  (oo)____        \n");
		prlog(PR_ERR, "           (__)    )\\      \n");
		prlog(PR_ERR, "              ||--|| *     \n");
	}

	/* Set up the HMI event */
	hmi_evt->severity = OpalHMI_SEV_WARNING;
	hmi_evt->type = OpalHMI_ERROR_MALFUNC_ALERT;
	hmi_evt->u.xstop_error.xstop_type = CHECKSTOP_TYPE_NPU;
	hmi_evt->u.xstop_error.xstop_reason = xstop_reason;
	hmi_evt->u.xstop_error.u.chip_id = flat_chip_id;

	/* Marking the event as recoverable so that we don't crash */
	queue_hmi_event(hmi_evt, 1, out_flags);
}
