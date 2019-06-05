/* Copyright 2013-2014 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
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
#include <mem_region.h>
#include <lock.h>

static struct mem_region *nvram_region;
static struct lock fake_nvram_lock = LOCK_UNLOCKED;

int fake_nvram_info(uint32_t *total_size)
{
	nvram_region = find_mem_region("ibm,fake-nvram");

	if (!nvram_region)
		return OPAL_HARDWARE;

	*total_size = nvram_region->len;

	return OPAL_SUCCESS;
}

int fake_nvram_start_read(void *dst, uint32_t src, uint32_t len)
{
	void *t;

	if (!nvram_region)
		return -ENODEV;

	t = vm_map(nvram_region->start + src, len, false);
	lock(&fake_nvram_lock);
	memcpy(dst, t, len);
	unlock(&fake_nvram_lock);
	vm_unmap(nvram_region->start + src, len);

	nvram_read_complete(true);

	return 0;
}

int fake_nvram_write(uint32_t offset, void *src, uint32_t size)
{
	void *t;

	if (!nvram_region)
		return OPAL_HARDWARE;

	t = vm_map(nvram_region->start + offset, size, true);
	lock(&fake_nvram_lock);
	memcpy(t, src, size);
	unlock(&fake_nvram_lock);
	vm_unmap(nvram_region->start + offset, size);

	return 0;
}

