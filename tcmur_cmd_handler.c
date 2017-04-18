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
#include <inttypes.h>

#include "libtcmu.h"
#include "libtcmu_log.h"
#include "libtcmu_priv.h"
#include "tcmur_aio.h"
#include "tcmur_cmd_handler.h"
#include "tcmu-runner.h"

static void aio_command_finish(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			       int rc)
{
	int wakeup;

	track_aio_request_finish(dev, &wakeup);
	tcmulib_command_complete(dev, cmd, rc);
	if (wakeup)
		tcmulib_processing_complete(dev);
}

static int alloc_iovec(struct tcmulib_cmd *cmd, size_t length)
{
	struct iovec *iov;

	assert(!cmd->iovec);

	iov = calloc(1, sizeof(*iov));
	if (!iov)
		goto out;
	iov->iov_base = calloc(1, length);
	if (!iov->iov_base)
		goto free_iov;
	iov->iov_len = length;

	cmd->iovec = iov;
	cmd->iov_cnt = 1;
	return 0;

free_iov:
	free(iov);
out:
	return -ENOMEM;
}

static void free_iovec(struct tcmulib_cmd *cmd)
{
	assert(cmd->iovec);
	assert(cmd->iovec->iov_base);

	free(cmd->iovec->iov_base);
	free(cmd->iovec);

	cmd->iov_cnt = 0;
	cmd->iovec = NULL;
}

static int check_lba_and_length(struct tcmu_device *dev,
				struct tcmulib_cmd *cmd, uint32_t sectors)
{
	uint8_t *cdb = cmd->cdb;
	uint64_t lba = tcmu_get_lba(cdb);
	uint64_t num_lbas = tcmu_get_dev_num_lbas(dev);
	size_t iov_length = tcmu_iovec_length(cmd->iovec, cmd->iov_cnt);

	if (iov_length != sectors * tcmu_get_dev_block_size(dev)) {
		tcmu_err("iov len mismatch: iov len %zu, xfer len %" PRIu32 ", block size %" PRIu32 "\n",
			 iov_length, sectors, tcmu_get_dev_block_size(dev));

		return tcmu_set_sense_data(cmd->sense_buf, HARDWARE_ERROR,
					   ASC_INTERNAL_TARGET_FAILURE, NULL);
	}

	if (lba >= num_lbas || lba + sectors > num_lbas)
		return tcmu_set_sense_data(cmd->sense_buf, ILLEGAL_REQUEST,
					   ASC_LBA_OUT_OF_RANGE, NULL);

	return SAM_STAT_GOOD;
}

static int read_work_fn(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);
	uint32_t block_size = tcmu_get_dev_block_size(dev);

	return rhandler->read(dev, cmd, cmd->iovec, cmd->iov_cnt,
			      tcmu_iovec_length(cmd->iovec, cmd->iov_cnt),
			      block_size * tcmu_get_lba(cmd->cdb));
}

static int write_work_fn(struct tcmu_device *dev,
				struct tcmulib_cmd *cmd)
{
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);
	uint32_t block_size = tcmu_get_dev_block_size(dev);

	return rhandler->write(dev, cmd, cmd->iovec, cmd->iov_cnt,
				tcmu_iovec_length(cmd->iovec, cmd->iov_cnt),
				block_size * tcmu_get_lba(cmd->cdb));
}

/* async write verify */

struct write_verify_state {
	size_t requested;
	struct iovec *w_iovec;
	size_t w_iov_cnt;
	void *read_buf;
	struct tcmulib_cmd *readcmd;
};

static int write_verify_init(struct tcmulib_cmd *origcmd, size_t length)
{
	struct tcmulib_cmd *readcmd;
	struct write_verify_state *state;
	int i;

	readcmd = calloc(1, sizeof(*readcmd));
	if (!readcmd)
		goto out;
	readcmd->cmdstate = origcmd;
	readcmd->cdb = origcmd->cdb;

	if (alloc_iovec(readcmd, length))
		goto free_cmd;

	state = calloc(1, sizeof(*state));
	if (!state)
		goto free_iov;

	/* use @origcmd as writecmd */
	state->read_buf = readcmd->iovec->iov_base;
	state->requested = length;
	state->readcmd = readcmd;

	state->w_iovec = calloc(origcmd->iov_cnt, sizeof(struct iovec));
	if (!state->w_iovec)
		goto free_state;

	state->w_iov_cnt = origcmd->iov_cnt;
	for (i = 0; i < origcmd->iov_cnt; i++) {
		state->w_iovec[i].iov_base = origcmd->iovec[i].iov_base;
		state->w_iovec[i].iov_len = origcmd->iovec[i].iov_len;
	}
	origcmd->cmdstate = state;

	return 0;

free_state:
	free(state);
free_iov:
	free_iovec(readcmd);
free_cmd:
	free(readcmd);
out:
	return -ENOMEM;
}

static void write_verify_free(struct tcmulib_cmd *origcmd)
{
	struct write_verify_state *state = origcmd->cmdstate;
	struct tcmulib_cmd *readcmd = state->readcmd;

	/* some handlers update iov_base */
	readcmd->iovec->iov_base = state->read_buf;
	free_iovec(readcmd);
	free(readcmd);
	free(state->w_iovec);
	free(state);
}

static void handle_write_verify_read_cbk(struct tcmu_device *dev,
					 struct tcmulib_cmd *readcmd, int ret)
{
	uint32_t cmp_offset;
	struct tcmulib_cmd *writecmd = readcmd->cmdstate;
	struct write_verify_state *state = writecmd->cmdstate;
	uint8_t *sense = writecmd->sense_buf;

	/* failed read - bail out */
	if (ret != SAM_STAT_GOOD) {
		memcpy(writecmd->sense_buf, readcmd->sense_buf,
		       sizeof(writecmd->sense_buf));
		goto done;
	}

	ret = SAM_STAT_GOOD;
	cmp_offset = tcmu_compare_with_iovec(state->read_buf, state->w_iovec,
					     state->requested);
	if (cmp_offset != -1) {
		tcmu_err("Verify failed at offset %lu\n", cmp_offset);
		ret =  tcmu_set_sense_data(sense, MISCOMPARE,
					   ASC_MISCOMPARE_DURING_VERIFY_OPERATION,
					   &cmp_offset);
	}

done:
	write_verify_free(writecmd);
	aio_command_finish(dev, writecmd, ret);
}

static void handle_write_verify_write_cbk(struct tcmu_device *dev,
					  struct tcmulib_cmd *writecmd,
					  int ret)
{
	struct write_verify_state *state = writecmd->cmdstate;

	/* write error - bail out */
	if (ret != SAM_STAT_GOOD)
		goto finish_err;

	state->readcmd->done = handle_write_verify_read_cbk;
	ret = async_handle_cmd(dev, state->readcmd, read_work_fn);
	if (ret != TCMU_ASYNC_HANDLED)
		goto finish_err;
	return;

finish_err:
	write_verify_free(writecmd);
	aio_command_finish(dev, writecmd, ret);
}

static int handle_write_verify(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	int ret = SAM_STAT_TASK_SET_FULL;
	uint8_t *cdb = cmd->cdb;
	size_t length = tcmu_get_xfer_length(cdb) * tcmu_get_dev_block_size(dev);

	ret = check_lba_and_length(dev, cmd, tcmu_get_xfer_length(cmd->cdb));
	if (ret)
		return ret;

	if (write_verify_init(cmd, length)) {
		ret = SAM_STAT_TASK_SET_FULL;
		goto out;
	}

	cmd->done = handle_write_verify_write_cbk;

	ret = async_handle_cmd(dev, cmd, write_work_fn);
	if (ret != TCMU_ASYNC_HANDLED)
		goto free_write_verify;

	return TCMU_ASYNC_HANDLED;

free_write_verify:
	write_verify_free(cmd);
out:
	return ret;
}

/* async compare_and_write */

struct caw_state {
	size_t requested;
	void *read_buf;
	struct tcmulib_cmd *origcmd;
};

static struct tcmulib_cmd *
caw_init_readcmd(struct tcmulib_cmd *origcmd, size_t length)
{
	struct tcmulib_cmd *readcmd;
	struct caw_state *state;

	state = calloc(1, sizeof(*state));
	if (!state)
		goto out;
	readcmd = calloc(1, sizeof(*readcmd));
	if (!readcmd)
		goto free_state;
	readcmd->cdb = origcmd->cdb;

	if (alloc_iovec(readcmd, length))
		goto free_cmd;

	/* multi-op state maintainance */
	state->read_buf = readcmd->iovec->iov_base;
	state->requested = length;
	state->origcmd = origcmd;

	readcmd->cmdstate = state;
	return readcmd;

free_cmd:
	free(readcmd);
free_state:
	free(state);
out:
	return NULL;
}

static void caw_free_readcmd(struct tcmulib_cmd *readcmd)
{
	struct caw_state *state = readcmd->cmdstate;

	/* some handlers update iov_base */
	readcmd->iovec->iov_base = state->read_buf;
	free_iovec(readcmd);
	free(state);
	free(readcmd);
}

static void handle_caw_write_cbk(struct tcmu_device *dev,
				 struct tcmulib_cmd *cmd, int ret)
{
	pthread_mutex_unlock(&dev->caw_lock);
	aio_command_finish(dev, cmd, ret);
}

static void handle_caw_read_cbk(struct tcmu_device *dev,
				struct tcmulib_cmd *readcmd, int ret)
{
	uint32_t cmp_offset;
	struct caw_state *state = readcmd->cmdstate;
	struct tcmulib_cmd *origcmd = state->origcmd;
	uint8_t *sense = origcmd->sense_buf;

	/* read failed - bail out */
	if (ret != SAM_STAT_GOOD) {
		memcpy(origcmd->sense_buf, readcmd->sense_buf,
		       sizeof(origcmd->sense_buf));
		goto finish_err;
	}

	cmp_offset = tcmu_compare_with_iovec(state->read_buf, origcmd->iovec,
					     state->requested);
	if (cmp_offset != -1) {
		/* verify failed - bail out */
		ret = tcmu_set_sense_data(sense, MISCOMPARE,
					  ASC_MISCOMPARE_DURING_VERIFY_OPERATION,
					  &cmp_offset);
		goto finish_err;
	}

	/* perform write */
	tcmu_seek_in_iovec(origcmd->iovec, state->requested);
	origcmd->done = handle_caw_write_cbk;

	ret = async_handle_cmd(dev, origcmd, write_work_fn);
	if (ret != TCMU_ASYNC_HANDLED)
		goto finish_err;

	caw_free_readcmd(readcmd);
	return;

finish_err:
	pthread_mutex_unlock(&dev->caw_lock);
	aio_command_finish(dev, origcmd, ret);
	caw_free_readcmd(readcmd);
}

static int handle_caw(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	int ret;
	struct tcmulib_cmd *readcmd;
	size_t half = (tcmu_iovec_length(cmd->iovec, cmd->iov_cnt)) / 2;

	ret = check_lba_and_length(dev, cmd, cmd->cdb[13] * 2);
	if (ret)
		return ret;

	readcmd = caw_init_readcmd(cmd, half);
	if (!readcmd) {
		ret = SAM_STAT_TASK_SET_FULL;
		goto out;
	}

	readcmd->done = handle_caw_read_cbk;

	pthread_mutex_lock(&dev->caw_lock);

	ret = async_handle_cmd(dev, readcmd, read_work_fn);
	if (ret == TCMU_ASYNC_HANDLED)
		return TCMU_ASYNC_HANDLED;

	pthread_mutex_unlock(&dev->caw_lock);
	caw_free_readcmd(readcmd);
out:
	return ret;
}

/* async flush */
static void handle_flush_cbk(struct tcmu_device *dev,
			     struct tcmulib_cmd *cmd, int ret)
{
	aio_command_finish(dev, cmd, ret);
}

static int flush_work_fn(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);

	return rhandler->flush(dev, cmd);
}

static int handle_flush(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	cmd->done = handle_flush_cbk;
	return async_handle_cmd(dev, cmd, flush_work_fn);
}

/* async write */
static void handle_write_cbk(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			     int ret)
{
	aio_command_finish(dev, cmd, ret);
}

static int handle_write(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	int ret;

	ret = check_lba_and_length(dev, cmd, tcmu_get_xfer_length(cmd->cdb));
	if (ret)
		return ret;

	cmd->done = handle_write_cbk;
	return async_handle_cmd(dev, cmd, write_work_fn);
}

/* async read */
static void handle_read_cbk(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			    int ret)
{
	aio_command_finish(dev, cmd, ret);
}

static int handle_read(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	int ret;

	ret = check_lba_and_length(dev, cmd, tcmu_get_xfer_length(cmd->cdb));
	if (ret)
		return ret;

	cmd->done = handle_read_cbk;
	return async_handle_cmd(dev, cmd, read_work_fn);
}

/* command passthrough */
static void
handle_passthrough_cbk(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
		       int ret)
{
	aio_command_finish(dev, cmd, ret);
}

static int passthrough_work_fn(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);

	return rhandler->handle_cmd(dev, cmd);
}

static int handle_passthrough(struct tcmu_device *dev,
			      struct tcmulib_cmd *cmd)
{
	cmd->done = handle_passthrough_cbk;
	return async_handle_cmd(dev, cmd, passthrough_work_fn);
}

bool tcmur_handler_is_passthrough_only(struct tcmur_handler *rhandler)
{
	if (rhandler->write || rhandler->read || rhandler->flush)
		return false;

	return true;
}

int tcmur_cmd_handler(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	int ret = TCMU_NOT_HANDLED;
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);
	uint8_t *cdb = cmd->cdb;
	int wakeup;

	track_aio_request_start(dev);

	if (tcmur_handler_is_passthrough_only(rhandler))
		goto passthrough;

	switch(cdb[0]) {
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		ret = handle_read(dev, cmd);
		goto done;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		ret = handle_write(dev, cmd);
		goto done;
	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16:
		if (!rhandler->flush)
			goto done;
		ret = handle_flush(dev, cmd);
		goto done;
	case COMPARE_AND_WRITE:
		ret = handle_caw(dev, cmd);
		goto done;
	case WRITE_VERIFY:
		ret = handle_write_verify(dev, cmd);
		goto done;
	}

passthrough:
	/*
	 * note that TCMU_NOT_HANDLED is returned when a tcmur handler does not
	 * handle a passthrough command, but since we call ->handle_cmd via
	 * async_handle_cmd(), ->handle_cmd can finish in the callers context
	 * (asynchronous handler) or work queue context (synchronous handlers),
	 * thus we'd need to check if ->handle_cmd handled the passthough
	 * command here as well as in handle_passthrough_cbk().
	 */
	if (rhandler->handle_cmd)
		ret = handle_passthrough(dev, cmd);
done:
	if (ret != TCMU_ASYNC_HANDLED)
		track_aio_request_finish(dev, &wakeup);
	return ret;
}
