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

#define pr_fmt(fmt)	"NPUHMI: " fmt

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

void find_npu_checkstop_reason(int flat_chip_id,
			       struct OpalHMIEvent *hmi_evt,
			       uint64_t *out_flags)
{
	struct phb *phb;
	struct npu *p = NULL;

	uint64_t npu_fir;
	uint64_t npu_fir_mask;
	uint64_t npu_fir_action0;
	uint64_t npu_fir_action1;
	uint64_t fatal_errors;

	/* Only check for NPU errors if the chip has a NPU */
	if (PVR_TYPE(mfspr(SPR_PVR)) != PVR_TYPE_P8NVL)
		return find_npu2_checkstop_reason(flat_chip_id, hmi_evt, out_flags);

	/* Find the NPU on the chip associated with the HMI. */
	for_each_phb(phb) {
		/* NOTE: if a chip ever has >1 NPU this will need adjusting */
		if (dt_node_is_compatible(phb->dt_node, "ibm,power8-npu-pciex") &&
		    (dt_get_chip_id(phb->dt_node) == flat_chip_id)) {
			p = phb_to_npu(phb);
			break;
		}
	}

	/* If we didn't find a NPU on the chip, it's not our checkstop. */
	if (p == NULL)
		return;

	/* Read all the registers necessary to find a checkstop condition. */
	if (xscom_read(flat_chip_id,
		       p->at_xscom + NX_FIR, &npu_fir) ||
	    xscom_read(flat_chip_id,
		       p->at_xscom + NX_FIR_MASK, &npu_fir_mask) ||
	    xscom_read(flat_chip_id,
		       p->at_xscom + NX_FIR_ACTION0, &npu_fir_action0) ||
	    xscom_read(flat_chip_id,
		       p->at_xscom + NX_FIR_ACTION1, &npu_fir_action1)) {
		prerror("Couldn't read NPU registers with XSCOM\n");
		return;
	}

	fatal_errors = npu_fir & ~npu_fir_mask & npu_fir_action0 & npu_fir_action1;

	/* If there's no errors, we don't need to do anything. */
	if (!fatal_errors)
		return;

	prlog(PR_DEBUG, "NPU: FIR 0x%016llx mask 0x%016llx\n",
	      npu_fir, npu_fir_mask);
	prlog(PR_DEBUG, "NPU: ACTION0 0x%016llx, ACTION1 0x%016llx\n",
	      npu_fir_action0, npu_fir_action1);

	/* Set the NPU to fenced since it can't recover. */
	npu_set_fence_state(p, true);

	/* Set up the HMI event */
	hmi_evt->severity = OpalHMI_SEV_WARNING;
	hmi_evt->type = OpalHMI_ERROR_MALFUNC_ALERT;
	hmi_evt->u.xstop_error.xstop_type = CHECKSTOP_TYPE_NPU;
	hmi_evt->u.xstop_error.u.chip_id = flat_chip_id;

	/* The HMI is "recoverable" because it shouldn't crash the system */
	queue_hmi_event(hmi_evt, 1, out_flags);
}
