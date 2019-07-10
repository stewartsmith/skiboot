/* Copyright 2013-2014 IBM Corp.
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
 * Console IO routine for use by libc
 *
 * fd is the classic posix 0,1,2 (stdin, stdout, stderr)
 */
#include <inttypes.h>
#include <stdbool.h>
#include <compiler.h>
#include <mem-map.h>
#include <console.h>

char *con_buf = (char *)INMEM_CON_START;

/* This is mapped via TCEs so we keep it alone in a page */
struct memcons memcons __section(".data.memcons") = {
	.magic		= MEMCONS_MAGIC,
	.obuf_phys	= INMEM_CON_START,
	.ibuf_phys	= INMEM_CON_START + INMEM_CON_OUT_LEN,
	.obuf_size	= INMEM_CON_OUT_LEN,
	.ibuf_size	= INMEM_CON_IN_LEN,
};

