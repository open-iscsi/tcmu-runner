/*
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
*/

#define _GNU_SOURCE

#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <scsi/scsi.h>

#include "tcmu-runner.h"

#define BLOCKSZ 4096

bool initialized = false;
char hello_buffer[BLOCKSZ];

static int tcmu_hello_open(struct tcmu_device *dev)
{
	const char hello_world[] = "Hello world!";
	const size_t hello_len = sizeof(hello_world);
	int i;

	for (i = 0; i < sizeof(hello_buffer); i++)
		hello_buffer[i] = hello_world[i % hello_len];

	return 0;
}

static int tcmu_hello_close(struct tcmu_device *dev)
{
	return 0;
}

/*
 * Return scsi status or TCMU_NOT_HANDLED
 */
int tcmu_hello_handle_cmd(
	struct tcmu_device *dev,
	struct tcmulib_cmd *tcmulib_cmd)
{
	uint8_t *cdb = tcmulib_cmd->cdb;
	struct iovec *iovec = tcmulib_cmd->iovec;
	size_t iov_cnt = tcmulib_cmd->iov_cnt;
	uint8_t *sense = tcmulib_cmd->sense_buf;
	uint8_t cmd;

	int ret = 0;
	uint32_t length = 0;
	int result = SAM_STAT_GOOD;

	cmd = cdb[0];

	switch (cmd) {
	case INQUIRY:
		return tcmu_emulate_inquiry(dev, cdb, iovec, iov_cnt, sense);
		break;
	case TEST_UNIT_READY:
		return tcmu_emulate_test_unit_ready(cdb, iovec, iov_cnt, sense);
		break;
	case SERVICE_ACTION_IN_16:
		if (cdb[1] == READ_CAPACITY_16) {
			long long size;
			unsigned long long num_lbas;

			size = tcmu_get_device_size(dev);
			if (size == -1) {
				errp("Could not get device size\n");
				return TCMU_NOT_HANDLED;
			}

			num_lbas = size / BLOCKSZ;

			return tcmu_emulate_read_capacity_16(num_lbas, BLOCKSZ,
							     cdb, iovec, iov_cnt, sense);
		} else {
			return TCMU_NOT_HANDLED;
		}
		break;
	case MODE_SENSE:
	case MODE_SENSE_10:
		return tcmu_emulate_mode_sense(cdb, iovec, iov_cnt, sense);
		break;
	case MODE_SELECT:
	case MODE_SELECT_10:
		return tcmu_emulate_mode_select(cdb, iovec, iov_cnt, sense);
		break;
	case COMPARE_AND_WRITE:
		break;
	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16:
		break;
	case WRITE_VERIFY:
	case WRITE_VERIFY_12:
	case WRITE_VERIFY_16:
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		break;

	case WRITE_SAME:
	case WRITE_SAME_16:
		break;
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:

		do {
			ret = tcmu_memcpy_into_iovec(iovec, iov_cnt, hello_buffer, sizeof(hello_buffer));
		} while (ret == sizeof(hello_buffer));
		break;
	case UNMAP:
		/* TODO: implement UNMAP */
		result = tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					     ASC_INVALID_FIELD_IN_CDB, NULL);
		break;
	default:
		result = TCMU_NOT_HANDLED;
		break;
	}

	dbgp("io done %p %x %d %u\n", cdb, cmd, result, length);

	if (result == TCMU_NOT_HANDLED)
		dbgp("io not handled %p %x %x %d %d\n",
		     cdb, result, cmd, ret, length);
	else if (result != SAM_STAT_GOOD) {
		errp("io error %p %x %x %d %d\n",
		     cdb, result, cmd, ret, length);
	}

	return result;
}

static const char hello_cfg_desc[] = "Hello World!";

struct tcmur_handler glfs_handler = {
	.name = "Hello World handler",
	.subtype = "hello",
	.cfg_desc = hello_cfg_desc,

	.open = tcmu_hello_open,
	.close = tcmu_hello_close,
	.handle_cmd = tcmu_hello_handle_cmd,
};

/* Entry point must be named "handler_init". */
void handler_init(void)
{
	tcmur_register_handler(&glfs_handler);
}
