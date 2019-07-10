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

#include <skiboot.h>
#include <opal.h>

#ifndef __HMI_H
#define __HMI_H

int queue_hmi_event(struct OpalHMIEvent *hmi_evt, int recover, uint64_t *out_flags);

void find_capp_checkstop_reason(int flat_chip_id,
				struct OpalHMIEvent *hmi_evt,
				uint64_t *out_flags);
void find_nx_checkstop_reason(int flat_chip_id,
			      struct OpalHMIEvent *hmi_evt,
			      uint64_t *out_flags);
void find_npu_checkstop_reason(int flat_chip_id,
			       struct OpalHMIEvent *hmi_evt,
			       uint64_t *out_flags);
void find_npu2_checkstop_reason(int flat_chip_id,
				struct OpalHMIEvent *hmi_evt,
				uint64_t *out_flags);

#endif /* __HMI_H */
