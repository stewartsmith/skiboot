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

#define pr_fmt(fmt)	"CAPPHMI: " fmt

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

void find_capp_checkstop_reason(int flat_chip_id,
				struct OpalHMIEvent *hmi_evt,
				uint64_t *out_flags)
{
	struct capp_info info;
	struct phb *phb;
	uint64_t capp_fir;
	uint64_t capp_fir_mask;
	uint64_t capp_fir_action0;
	uint64_t capp_fir_action1;
	uint64_t reg;
	int64_t rc;

	/* Find the CAPP on the chip associated with the HMI. */
	for_each_phb(phb) {
		/* get the CAPP info */
		rc = capp_get_info(flat_chip_id, phb, &info);
		if (rc == OPAL_PARAMETER)
			continue;

		if (xscom_read(flat_chip_id, info.capp_fir_reg, &capp_fir) ||
		    xscom_read(flat_chip_id, info.capp_fir_mask_reg,
			       &capp_fir_mask) ||
		    xscom_read(flat_chip_id, info.capp_fir_action0_reg,
			       &capp_fir_action0) ||
		    xscom_read(flat_chip_id, info.capp_fir_action1_reg,
			       &capp_fir_action1)) {
			prerror("CAPP: Couldn't read CAPP#%d (PHB:#%x) FIR registers by XSCOM!\n",
				info.capp_index, info.phb_index);
			continue;
		}

		if (!(capp_fir & ~capp_fir_mask))
			continue;

		prlog(PR_DEBUG, "CAPP#%d (PHB:#%x): FIR 0x%016llx mask 0x%016llx\n",
		      info.capp_index, info.phb_index, capp_fir,
		      capp_fir_mask);
		prlog(PR_DEBUG, "CAPP#%d (PHB:#%x): ACTION0 0x%016llx, ACTION1 0x%016llx\n",
		      info.capp_index, info.phb_index, capp_fir_action0,
		      capp_fir_action1);

		/*
		 * If this bit is set (=1) a Recoverable Error has been
		 * detected
		 */
		xscom_read(flat_chip_id, info.capp_err_status_ctrl_reg, &reg);
		if ((reg & PPC_BIT(0)) != 0) {
			phb_lock(phb);
			phb->ops->set_capp_recovery(phb);
			phb_unlock(phb);

			hmi_evt->severity = OpalHMI_SEV_NO_ERROR;
			hmi_evt->type = OpalHMI_ERROR_CAPP_RECOVERY;
			queue_hmi_event(hmi_evt, 1, out_flags);

			return;
		}
	}
}
