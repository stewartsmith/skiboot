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

#define pr_fmt(fmt)	"NXHMI: " fmt

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

static const struct nx_xstop_bit_info {
	uint8_t bit;		/* NX FIR bit number */
	enum OpalHMI_NestAccelXstopReason reason;
} nx_dma_xstop_bits[] = {
	{ 1, NX_CHECKSTOP_SHM_INVAL_STATE_ERR },
	{ 15, NX_CHECKSTOP_DMA_INVAL_STATE_ERR_1 },
	{ 16, NX_CHECKSTOP_DMA_INVAL_STATE_ERR_2 },
	{ 20, NX_CHECKSTOP_DMA_CH0_INVAL_STATE_ERR },
	{ 21, NX_CHECKSTOP_DMA_CH1_INVAL_STATE_ERR },
	{ 22, NX_CHECKSTOP_DMA_CH2_INVAL_STATE_ERR },
	{ 23, NX_CHECKSTOP_DMA_CH3_INVAL_STATE_ERR },
	{ 24, NX_CHECKSTOP_DMA_CH4_INVAL_STATE_ERR },
	{ 25, NX_CHECKSTOP_DMA_CH5_INVAL_STATE_ERR },
	{ 26, NX_CHECKSTOP_DMA_CH6_INVAL_STATE_ERR },
	{ 27, NX_CHECKSTOP_DMA_CH7_INVAL_STATE_ERR },
	{ 31, NX_CHECKSTOP_DMA_CRB_UE },
	{ 32, NX_CHECKSTOP_DMA_CRB_SUE },
};

static const struct nx_xstop_bit_info nx_pbi_xstop_bits[] = {
	{ 12, NX_CHECKSTOP_PBI_ISN_UE },
};

extern uint32_t nx_status_reg;
extern uint32_t nx_dma_engine_fir;
extern uint32_t nx_pbi_fir;

void find_nx_checkstop_reason(int flat_chip_id,
			      struct OpalHMIEvent *hmi_evt,
			      uint64_t *out_flags)
{
	uint64_t nx_status;
	uint64_t nx_dma_fir;
	uint64_t nx_pbi_fir_val;
	int i;

	/* Get NX status register value. */
	if (xscom_read(flat_chip_id, nx_status_reg, &nx_status) != 0) {
		prerror("XSCOM error reading NX_STATUS_REG\n");
		return;
	}

	/* Check if NX has driven an HMI interrupt. */
	if (!(nx_status & NX_HMI_ACTIVE))
		return;

	/* Initialize HMI event */
	hmi_evt->severity = OpalHMI_SEV_FATAL;
	hmi_evt->type = OpalHMI_ERROR_MALFUNC_ALERT;
	hmi_evt->u.xstop_error.xstop_type = CHECKSTOP_TYPE_NX;
	hmi_evt->u.xstop_error.u.chip_id = flat_chip_id;

	/* Get DMA & Engine FIR data register value. */
	if (xscom_read(flat_chip_id, nx_dma_engine_fir, &nx_dma_fir) != 0) {
		prerror("XSCOM error reading NX_DMA_ENGINE_FIR\n");
		return;
	}

	/* Get PowerBus Interface FIR data register value. */
	if (xscom_read(flat_chip_id, nx_pbi_fir, &nx_pbi_fir_val) != 0) {
		prerror("XSCOM error reading NX_PBI_FIR\n");
		return;
	}

	/* Find NX checkstop reason and populate HMI event with error info. */
	for (i = 0; i < ARRAY_SIZE(nx_dma_xstop_bits); i++)
		if (nx_dma_fir & PPC_BIT(nx_dma_xstop_bits[i].bit))
			hmi_evt->u.xstop_error.xstop_reason
						|= nx_dma_xstop_bits[i].reason;

	for (i = 0; i < ARRAY_SIZE(nx_pbi_xstop_bits); i++)
		if (nx_pbi_fir_val & PPC_BIT(nx_pbi_xstop_bits[i].bit))
			hmi_evt->u.xstop_error.xstop_reason
						|= nx_pbi_xstop_bits[i].reason;

	/*
	 * Set NXDMAENGFIR[38] to signal PRD that service action is required.
	 * Without this inject, PRD will not be able to do NX unit checkstop
	 * error analysis. NXDMAENGFIR[38] is a spare bit and used to report
	 * a software initiated attention.
	 *
	 * The behavior of this bit and all FIR bits are documented in
	 * RAS spreadsheet.
	 */
	xscom_write(flat_chip_id, nx_dma_engine_fir, PPC_BIT(38));

	/* Send an HMI event. */
	queue_hmi_event(hmi_evt, 0, out_flags);
}
