/*
 * Copyright 2017, Red Hat, Inc.
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
#include <scsi/scsi.h>
#include <errno.h>

#include "libtcmu.h"
#include "libtcmu_log.h"
#include "libtcmu_store.h"
#include "tcmu-runner.h"

int call_store(struct tcmu_device *dev,
	       struct tcmulib_cmd *tcmulib_cmd, uint8_t cmd)
{
	int ret = TCMU_NOT_HANDLED;
	struct tcmulib_handler *handler = tcmu_get_dev_handler(dev);
	struct tcmur_handler *store = handler->hm_private;
	uint8_t *cdb = tcmulib_cmd->cdb;
	struct iovec *iovec = tcmulib_cmd->iovec;
	size_t iov_cnt = tcmulib_cmd->iov_cnt;
	uint8_t *sense = tcmulib_cmd->sense_buf;
	uint32_t block_size = tcmu_get_dev_block_size(dev);
	ssize_t ret, l = tcmu_iovec_length(iovec, iov_cnt);
	off_t offset = block_size * tcmu_get_lba(cdb);
	struct iovec iov;
	size_t half = l / 2;
	uint32_t cmp_offset;

	if (store->handle_cmd)
		ret = store->handle_cmd(dev, tcmulib_cmd);
	if (ret != TCMU_NOT_HANDLED)
		return ret;

	switch(cmd) {
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		ret = store->read(dev, iovec, iov_cnt, offset);
		if (ret != l) {
			tcmu_err("Error on read %x, %x\n", ret, l);
			return tcmu_set_sense_data(sense, MEDIUM_ERROR,
						   ASC_READ_ERROR, NULL);
		} else
			return SAM_STAT_GOOD;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		ret = store->write(dev, iovec, iov_cnt, offset);
		if (ret != l) {
			tcmu_err("Error on write %x, %x\n", ret, l);
			return tcmu_set_sense_data(sense, MEDIUM_ERROR,
						   ASC_READ_ERROR, NULL);
		} else
			return SAM_STAT_GOOD;
	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16:
		ret = store->flush(dev);
		if (ret < 0) {
			tcmu_err("Error on flush %x\n", ret);
			return tcmu_set_sense_data(sense, MEDIUM_ERROR,
						   ASC_READ_ERROR, NULL);
		} else
			return SAM_STAT_GOOD;
	case COMPARE_AND_WRITE:
		iov.iov_base = malloc(half);
		if (!iov.iov_base) {
			tcmu_err("out of memory\n");
			return tcmu_set_sense_data(sense, MEDIUM_ERROR,
						   ASC_READ_ERROR, NULL);
		}
		iov.iov_len = half;
		ret = store->read(dev, &iov, 1, offset);
		if (ret != l) {
			tcmu_err("Error on read %x, %x\n", ret, l);
			return tcmu_set_sense_data(sense, MEDIUM_ERROR,
						   ASC_READ_ERROR, NULL);
		}
		cmp_offset = tcmu_compare_with_iovec(iov.iov_base, iovec, half);
		if (cmp_offset != -1) {
			return tcmu_set_sense_data(sense, MISCOMPARE,
					ASC_MISCOMPARE_DURING_VERIFY_OPERATION,
					&cmp_offset);
		}
		free(iov.iov_base);

		tcmu_seek_in_iovec(iovec, half);
		ret = store->write(dev, iovec, iov_cnt, offset);
		if (ret != half) {
			tcmu_err("Error on write %x, %x\n", ret, half);
			return tcmu_set_sense_data(sense, MEDIUM_ERROR,
						   ASC_READ_ERROR, NULL);
		} else
			return SAM_STAT_GOOD;
	case WRITE_VERIFY:
		return tcmu_emulate_write_verify(dev, tcmulib_cmd,
						 store->read,
						 store->write,
						 iovec, iov_cnt, offset);
	default:
		tcmu_err("unknown command %x\n", cdb[0]);
		return TCMU_NOT_HANDLED;
	}
}
