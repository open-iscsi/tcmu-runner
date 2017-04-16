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
#include "libtcmu_aio.h"
#include "libtcmu_log.h"
#include "libtcmu_priv.h"
#include "tcmur_cmd_handler.h"
#include "tcmu-runner.h"

static void aio_command_start(struct tcmu_device *dev)
{
	track_aio_request_start(dev);
}

static void aio_command_finish(struct tcmu_device *dev,
			       struct tcmulib_cmd *cmd,
			       int rc, bool complete)
{
	int wakeup;

	track_aio_request_finish(dev, &wakeup);
	if (complete) {
		tcmulib_command_complete(dev, cmd, rc);
		if (wakeup)
			tcmulib_processing_complete(dev);
	}
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

/* async write verify */

struct tcmu_write_verify_state {
	off_t off;
	size_t requested;
	struct iovec *w_iovec;
	size_t w_iov_cnt;
	struct tcmulib_cmd *readcmd;
};

/*
 * read command state just points to the original command which
 * itself is the write command. no special state maintainance
 * is required here as we retrigger the write after a successful
 * verification in read.
 */
static struct tcmulib_cmd *
write_verify_init_readcmd(struct tcmulib_cmd *origcmd)
{
	struct tcmulib_cmd *readcmd;

	readcmd = calloc(1, sizeof(*readcmd));
	if (!readcmd)
		goto out;

	readcmd->iov_cnt = 0;
	readcmd->iovec = NULL;
	readcmd->cmdstate = origcmd;
	return readcmd;

out:
	return NULL;
}

static void write_verify_free_readcmd(struct tcmulib_cmd *readcmd)
{
	/* no state is allocated - just deallocate cmd */
	free(readcmd);
}

static struct tcmulib_cmd *
write_verify_init_writecmd(struct tcmulib_cmd *origcmd,
			   struct tcmulib_cmd *readcmd,
			   off_t off, size_t length)
{
	size_t count = 0;
	struct tcmu_write_verify_state *state;

	state = calloc(1, sizeof(*state));
	if (!state)
		goto out;

	/* use @origcmd as writecmd */
	state->off = off;
	state->requested = length;
	state->readcmd = readcmd;

	state->w_iovec = calloc(origcmd->iov_cnt, sizeof(struct iovec));
	if (!state->w_iovec)
		goto free_state;

	state->w_iov_cnt = origcmd->iov_cnt;
	for (; count < origcmd->iov_cnt; ++count) {
		state->w_iovec[count].iov_base = origcmd->iovec[count].iov_base;
		state->w_iovec[count].iov_len = origcmd->iovec[count].iov_len;
	}

	origcmd->cmdstate = state;
	return origcmd;

free_state:
	free(state);
out:
	return NULL;
}

static void write_verify_free_writecmd(struct tcmulib_cmd *writecmd)
{
	struct tcmu_write_verify_state *state = writecmd->cmdstate;

	/* writecmd is original cmd - just deallocate its state */
	free(state->w_iovec);
	free(state);
}

static void handle_write_verify_read_cbk(struct tcmu_device *dev,
					 struct tcmulib_cmd *readcmd, int ret)
{
	uint32_t cmp_offset;
	struct tcmulib_cmd *writecmd = readcmd->cmdstate;
	struct tcmu_write_verify_state *state = writecmd->cmdstate;
	uint8_t *sense = writecmd->sense_buf;
	size_t count = 0;

	/* failed read - bail out */
	if (ret != SAM_STAT_GOOD)
		goto done;

	readcmd->iovec->iov_base -= state->requested;

	for(; count < state->w_iov_cnt; ++count) {
		if (writecmd->iovec[count].iov_len != state->w_iovec[count].iov_len) {
			writecmd->iovec[count].iov_base = state->w_iovec[count].iov_base;
			writecmd->iovec[count].iov_len = state->w_iovec[count].iov_len -
				writecmd->iovec[count].iov_len;
		}
	}

	/* verify failed - bail out */
	ret = SAM_STAT_GOOD;
	cmp_offset = tcmu_compare_with_iovec(readcmd->iovec->iov_base,
					     writecmd->iovec, state->requested);
	if (cmp_offset != -1) {
		tcmu_err("Verify failed at offset %lu\n", cmp_offset);
		ret =  tcmu_set_sense_data(sense, MISCOMPARE,
					   ASC_MISCOMPARE_DURING_VERIFY_OPERATION,
					   &cmp_offset);
	}

done:
	free_iovec(readcmd);
	write_verify_free_readcmd(readcmd);
	write_verify_free_writecmd(writecmd);
	aio_command_finish(dev, writecmd, ret, true);
}

static int write_verify_do_read(struct tcmu_device *dev,
				struct tcmulib_cmd *readcmd,
				off_t off, size_t length)
{
	int ret;
	struct tcmu_call_stub stub;
	struct tcmulib_cmd *writecmd = readcmd->cmdstate;
	uint8_t *sense = writecmd->sense_buf;
	struct tcmulib_handler *handler = tcmu_get_dev_handler(dev);
	struct tcmur_handler *rhandler = handler->hm_private;

	ret = errno_to_sam_status(-ENOMEM, sense);

	/* do realloc() ? */
	if (alloc_iovec(readcmd, length))
		goto out;

	stub.sop = TCMU_STORE_OP_READ;
	stub.callout_cbk = handle_write_verify_read_cbk;

	stub.u.rw.exec = rhandler->read;
	stub.u.rw.iov = readcmd->iovec;
	stub.u.rw.iov_cnt = 1;
	stub.u.rw.off = off;

	ret = async_call_command(dev, readcmd, &stub);
	if (ret != TCMU_ASYNC_HANDLED)
		goto free_iov;
	return TCMU_ASYNC_HANDLED;

free_iov:
	free_iovec(readcmd);
out:
	return ret;
}

static void handle_write_verify_write_cbk(struct tcmu_device *dev,
					  struct tcmulib_cmd *writecmd,
					  int ret)
{
	struct tcmu_write_verify_state *state = writecmd->cmdstate;

	/* write error - bail out */
	if (ret != SAM_STAT_GOOD)
		goto finish_err;

	/* perform read for verification */
	ret = write_verify_do_read(dev, state->readcmd, state->off, state->requested);
	if (ret != TCMU_ASYNC_HANDLED)
		goto finish_err;
	return;

finish_err:
	write_verify_free_readcmd(state->readcmd);
	write_verify_free_writecmd(writecmd);
	aio_command_finish(dev, writecmd, ret, true);
}

static int write_verify_do_write(struct tcmu_device *dev,
				 struct tcmulib_cmd *writecmd,
				 struct iovec *iovec, size_t iov_cnt, off_t off)
{
	struct tcmu_call_stub stub;
	struct tcmulib_handler *handler = tcmu_get_dev_handler(dev);
	struct tcmur_handler *rhandler= handler->hm_private;

	stub.sop = TCMU_STORE_OP_WRITE;
	stub.callout_cbk = handle_write_verify_write_cbk;

	stub.u.rw.exec = rhandler->write;
	stub.u.rw.iov = iovec;
	stub.u.rw.iov_cnt = iov_cnt;
	stub.u.rw.off = off;

	return async_call_command(dev, writecmd, &stub);
}

static int handle_write_verify(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			       off_t off)
{
	int ret;
	uint8_t *cdb = cmd->cdb;
	struct tcmulib_cmd *readcmd, *writecmd;
	uint8_t *sense = cmd->sense_buf;
	size_t length = tcmu_get_xfer_length(cdb) * tcmu_get_dev_block_size(dev);

	ret = errno_to_sam_status(-ENOMEM, sense);

	readcmd = write_verify_init_readcmd(cmd);
	if (!readcmd)
		goto out;
	writecmd = write_verify_init_writecmd(cmd, readcmd, off, length);
	if (!writecmd)
		goto free_readcmd;

	aio_command_start(dev);
	ret = write_verify_do_write(dev, writecmd,
				    writecmd->iovec, writecmd->iov_cnt, off);
	if (ret != TCMU_ASYNC_HANDLED) {
		aio_command_finish(dev, writecmd, ret, false);
		goto free_writecmd;
	}

	return TCMU_ASYNC_HANDLED;

free_writecmd:
	write_verify_free_writecmd(writecmd);
free_readcmd:
	write_verify_free_readcmd(readcmd);
out:
	return ret;
}

/* async compare_and_write */

struct tcmu_caw_state {
	off_t off;
	ssize_t requested;
	struct tcmulib_cmd *origcmd;
};

static struct tcmulib_cmd *
caw_init_readcmd(struct tcmulib_cmd *origcmd, off_t off, ssize_t length)
{
	struct tcmulib_cmd *readcmd;
	struct tcmu_caw_state *state;

	state = calloc(1, sizeof(*state));
	if (!state)
		goto out;
	readcmd = calloc(1, sizeof(*readcmd));
	if (!readcmd)
		goto free_state;

	if (alloc_iovec(readcmd, length))
		goto free_cmd;

	/* multi-op state maintainance */
	state->off = off;
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
	struct tcmu_caw_state *state = readcmd->cmdstate;

	free_iovec(readcmd);
	free(state);
	free(readcmd);
}

static void handle_caw_write_cbk(struct tcmu_device *dev,
				 struct tcmulib_cmd *cmd, int ret)
{
	pthread_mutex_unlock(&dev->caw_lock);
	aio_command_finish(dev, cmd, ret, true);
}

static void handle_caw_read_cbk(struct tcmu_device *dev,
				struct tcmulib_cmd *readcmd, int ret)
{
	uint32_t cmp_offset;
	struct tcmu_call_stub stub;
	struct tcmu_caw_state *state = readcmd->cmdstate;
	struct tcmulib_cmd *origcmd = state->origcmd;
	uint8_t *sense = origcmd->sense_buf;
	struct tcmulib_handler *handler = tcmu_get_dev_handler(dev);
	struct tcmur_handler *rhandler = handler->hm_private;

	/* read failed - bail out */
	if (ret != SAM_STAT_GOOD)
		goto finish_err;

	readcmd->iovec->iov_base -= state->requested;

	/* verify failed - bail out */
	cmp_offset = tcmu_compare_with_iovec(readcmd->iovec->iov_base,
					     origcmd->iovec, state->requested);
	if (cmp_offset != -1) {
		ret = tcmu_set_sense_data(sense, MISCOMPARE,
					  ASC_MISCOMPARE_DURING_VERIFY_OPERATION,
					  &cmp_offset);
		goto finish_err;
	}

	/* perform write */
	tcmu_seek_in_iovec(origcmd->iovec, state->requested);
	stub.sop = TCMU_STORE_OP_WRITE;
	stub.callout_cbk = handle_caw_write_cbk;

	stub.u.rw.exec = rhandler->write;
	stub.u.rw.iov = origcmd->iovec;
	stub.u.rw.iov_cnt = origcmd->iov_cnt;
	stub.u.rw.off = state->off;

	ret = async_call_command(dev, origcmd, &stub);
	if (ret != TCMU_ASYNC_HANDLED)
		goto finish_err;

	caw_free_readcmd(readcmd);
	return;

finish_err:
	pthread_mutex_unlock(&dev->caw_lock);
	aio_command_finish(dev, origcmd, ret, true);
	caw_free_readcmd(readcmd);
}

static int handle_caw(struct tcmu_device *dev,
		      struct tcmur_handler *rhandler,
		      struct tcmulib_cmd *cmd,
		      struct iovec *iovec, size_t iov_cnt, off_t off)
{
	int ret;
	struct tcmu_call_stub stub;
	struct tcmulib_cmd *readcmd;
	uint8_t *sense = cmd->sense_buf;
	ssize_t half = (tcmu_iovec_length(iovec, iov_cnt)) / 2;

	ret = check_lba_and_length(dev, cmd, cmd->cdb[13] * 2);
	if (ret)
		return ret;

	ret = errno_to_sam_status(-ENOMEM, sense);

	readcmd = caw_init_readcmd(cmd, off, half);
	if (!readcmd)
		goto out;

	stub.sop = TCMU_STORE_OP_READ;
	stub.callout_cbk = handle_caw_read_cbk;

	stub.u.rw.exec = rhandler->read;
	stub.u.rw.iov = readcmd->iovec;
	stub.u.rw.iov_cnt = readcmd->iov_cnt;
	stub.u.rw.off = off;

	aio_command_start(dev);
	pthread_mutex_lock(&dev->caw_lock);

	ret = async_call_command(dev, readcmd, &stub);
	if (ret == TCMU_ASYNC_HANDLED)
		return TCMU_ASYNC_HANDLED;

	pthread_mutex_unlock(&dev->caw_lock);
	aio_command_finish(dev, cmd, ret, false);

	caw_free_readcmd(readcmd);
out:
	return ret;
}

/* async flush */
static void handle_flush_cbk(struct tcmu_device *dev,
			     struct tcmulib_cmd *cmd, int ret)
{
	aio_command_finish(dev, cmd, ret, true);
}

static int handle_flush(struct tcmu_device *dev,
			struct tcmur_handler *rhandler,
			struct tcmulib_cmd *cmd)
{
	int ret;
	struct tcmu_call_stub stub;

	stub.sop = TCMU_STORE_OP_FLUSH;
	stub.callout_cbk = handle_flush_cbk;
	stub.u.flush.exec = rhandler->flush;

	aio_command_start(dev);
	ret = async_call_command(dev, cmd, &stub);
	if (ret != TCMU_ASYNC_HANDLED)
		aio_command_finish(dev, cmd, ret, false);
	return ret;
}

/* async write */
static void handle_write_cbk(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			     int ret)
{
	aio_command_finish(dev, cmd, ret, true);
}

static int handle_write(struct tcmu_device *dev,
			 struct tcmur_handler *rhandler,
			 struct tcmulib_cmd *cmd,
			 struct iovec *iovec, size_t iov_cnt, off_t off)
{
	int ret;
	struct tcmu_call_stub stub;

	ret = check_lba_and_length(dev, cmd, tcmu_get_xfer_length(cmd->cdb));
	if (ret)
		return ret;

	stub.sop = TCMU_STORE_OP_WRITE;
	stub.callout_cbk = handle_write_cbk;

	stub.u.rw.exec = rhandler->write;
	stub.u.rw.iov = iovec;
	stub.u.rw.iov_cnt = iov_cnt;
	stub.u.rw.off = off;

	aio_command_start(dev);
	ret = async_call_command(dev, cmd, &stub);
	if (ret != TCMU_ASYNC_HANDLED)
		aio_command_finish(dev, cmd, ret, false);
	return ret;
}

/* async read */
static void handle_read_cbk(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			    int ret)
{
	aio_command_finish(dev, cmd, ret, true);
}

static int handle_read(struct tcmu_device *dev,
		       struct tcmur_handler *rhandler,
		       struct tcmulib_cmd *cmd,
		       struct iovec *iovec, size_t iov_cnt, off_t off)
{
	int ret;
	struct tcmu_call_stub stub;

	ret = check_lba_and_length(dev, cmd, tcmu_get_xfer_length(cmd->cdb));
	if (ret)
		return ret;

	stub.sop = TCMU_STORE_OP_READ;
	stub.callout_cbk = handle_read_cbk;

	stub.u.rw.exec = rhandler->read;
	stub.u.rw.iov = iovec;
	stub.u.rw.iov_cnt = iov_cnt;
	stub.u.rw.off = off;

	aio_command_start(dev);
	ret = async_call_command(dev, cmd, &stub);
	if (ret != TCMU_ASYNC_HANDLED)
		aio_command_finish(dev, cmd, ret, false);
	return ret;
}

/* command passthrough */
static void
handle_passthrough_cbk(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
		       int ret)
{
	aio_command_finish(dev, cmd, ret,
			    (ret != TCMU_ASYNC_HANDLED) ? true : false);
}

static int handle_passthrough(struct tcmu_device *dev,
			      struct tcmur_handler *rhandler,
			      struct tcmulib_cmd *cmd)
{
	int ret;
	struct tcmu_call_stub stub;

	stub.sop = TCMU_STORE_OP_HANDLE_CMD;
	stub.callout_cbk = handle_passthrough_cbk;
	stub.u.handle_cmd.exec = rhandler->handle_cmd;

	aio_command_start(dev);
	ret = async_call_command(dev, cmd, &stub);
	if (ret != TCMU_ASYNC_HANDLED)
		aio_command_finish(dev, cmd, ret, false);
	return ret;
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
	struct tcmulib_handler *handler = tcmu_get_dev_handler(dev);
	struct tcmur_handler *rhandler = handler->hm_private;
	uint8_t *cdb = cmd->cdb;
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
	uint32_t block_size = tcmu_get_dev_block_size(dev);
	off_t offset = block_size * tcmu_get_lba(cdb);

	if (tcmur_handler_is_passthrough_only(rhandler))
		goto passthrough;

	switch(cdb[0]) {
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		return handle_read(dev, rhandler, cmd, iovec, iov_cnt, offset);
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		return handle_write(dev, rhandler, cmd, iovec, iov_cnt, offset);
	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16:
		return handle_flush(dev, rhandler, cmd);
	case COMPARE_AND_WRITE:
		return handle_caw(dev, rhandler, cmd, iovec, iov_cnt, offset);
	case WRITE_VERIFY:
		return handle_write_verify(dev, cmd, offset);
	}

passthrough:
	/*
	 * note that TCMU_NOT_HANDLED is returned when a tcmur handler does not
	 * handle a passthrough command, but since we call ->handle_cmd via
	 * async_call_command(), ->handle_cmd can finish in the callers context
	 * (asynchronous handler) or work queue context (synchronous handlers),
	 * thus we'd need to check if ->handle_cmd handled the passthough
	 * command here as well as in handle_passthrough_cbk().
	 */
	if (rhandler->handle_cmd)
		ret = handle_passthrough(dev, rhandler, cmd);
	return ret;
}
