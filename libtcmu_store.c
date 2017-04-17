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
#include "libtcmu_aio.h"
#include "libtcmu_log.h"
#include "libtcmu_priv.h"
#include "libtcmu_store.h"
#include "tcmu-runner.h"

static void aio_command_start(struct tcmu_device *dev)
{
	track_aio_request_start(dev);
}

static void aio_command_finish(struct tcmu_device *dev,
			       struct tcmulib_cmd *tcmulib_cmd,
			       int rc, bool complete)
{
	int wakeup;

	track_aio_request_finish(dev, &wakeup);
	if (complete) {
		tcmulib_command_complete(dev, tcmulib_cmd, rc);
		if (wakeup)
			tcmulib_processing_complete(dev);
	}
}

static struct iovec *
alloc_and_assign_single_iovec(struct tcmulib_cmd *tcmulib_cmd, size_t length)
{
	struct iovec *iov;

	assert(!tcmulib_cmd->iovec);

	iov = calloc(1, sizeof(*iov));
	if (!iov)
		goto out;
	iov->iov_base = calloc(1, length);
	if (!iov->iov_base)
		goto free_iov;
	iov->iov_len = length;

	tcmulib_cmd->iovec = iov;
	tcmulib_cmd->iov_cnt = 1;
	return iov;

free_iov:
	free(iov);
out:
	return NULL;
}

static void free_single_iovec(struct tcmulib_cmd *tcmulib_cmd)
{
	assert(tcmulib_cmd->iovec);
	assert(tcmulib_cmd->iovec->iov_base);

	free(tcmulib_cmd->iovec->iov_base);
	free(tcmulib_cmd->iovec);

	tcmulib_cmd->iov_cnt = 0;
	tcmulib_cmd->iovec = NULL;
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

static void call_store_write_verify_read_cbk(struct tcmu_device *dev,
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
	free_single_iovec(readcmd);
	write_verify_free_readcmd(readcmd);
	write_verify_free_writecmd(writecmd);
	aio_command_finish(dev, writecmd, ret, true);
}

static int write_verify_do_read(struct tcmu_device *dev,
				struct tcmulib_cmd *readcmd,
				off_t off, size_t length)
{
	int ret;
	struct iovec *iov;
	struct tcmu_call_stub stub;
	struct tcmulib_cmd *writecmd = readcmd->cmdstate;
	uint8_t *sense = writecmd->sense_buf;
	struct tcmulib_handler *handler = tcmu_get_dev_handler(dev);
	struct tcmur_handler *store = handler->hm_private;

	ret = errno_to_sam_status(-ENOMEM, sense);

	/* do realloc() ? */
	iov = alloc_and_assign_single_iovec(readcmd, length);
	if (!iov)
		goto out;

	stub.sop = TCMU_STORE_OP_READ;
	stub.callout_cbk = call_store_write_verify_read_cbk;

	stub.u.rw.exec = store->read;
	stub.u.rw.iov = iov;
	stub.u.rw.iov_cnt = 1;
	stub.u.rw.off = off;

	ret = async_call_command(dev, readcmd, &stub);
	if (ret != TCMU_ASYNC_HANDLED)
		goto free_iov;
	return TCMU_ASYNC_HANDLED;

free_iov:
	free_single_iovec(readcmd);
out:
	return ret;
}

static void call_store_write_verify_write_cbk(struct tcmu_device *dev,
					      struct tcmulib_cmd *writecmd, int ret)
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
	struct tcmur_handler *store = handler->hm_private;

	stub.sop = TCMU_STORE_OP_WRITE;
	stub.callout_cbk = call_store_write_verify_write_cbk;

	stub.u.rw.exec = store->write;
	stub.u.rw.iov = iovec;
	stub.u.rw.iov_cnt = iov_cnt;
	stub.u.rw.off = off;

	return async_call_command(dev, writecmd, &stub);
}

static int call_store_write_verify(struct tcmu_device *dev,
				   struct tcmulib_cmd *tcmulib_cmd, off_t off)
{
	int ret;
	uint8_t *cdb = tcmulib_cmd->cdb;
	struct tcmulib_cmd *readcmd, *writecmd;
	uint8_t *sense = tcmulib_cmd->sense_buf;
	size_t length = tcmu_get_xfer_length(cdb) * tcmu_get_dev_block_size(dev);

	ret = errno_to_sam_status(-ENOMEM, sense);

	readcmd = write_verify_init_readcmd(tcmulib_cmd);
	if (!readcmd)
		goto out;
	writecmd = write_verify_init_writecmd(tcmulib_cmd, readcmd, off, length);
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
	struct iovec *iov;
	struct tcmulib_cmd *readcmd;
	struct tcmu_caw_state *state;

	state = calloc(1, sizeof(*state));
	if (!state)
		goto out;
	readcmd = calloc(1, sizeof(*readcmd));
	if (!readcmd)
		goto free_state;

	readcmd->iov_cnt = 0;
	readcmd->iovec = NULL;
	iov = alloc_and_assign_single_iovec(readcmd, length);
	if (!iov)
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

	free_single_iovec(readcmd);
	free(state);
	free(readcmd);
}

static void call_store_caw_write_cbk(struct tcmu_device *dev,
				     struct tcmulib_cmd *tcmulib_cmd, int ret)
{
	pthread_mutex_unlock(&dev->caw_lock);
	aio_command_finish(dev, tcmulib_cmd, ret, true);
}

static void call_store_caw_read_cbk(struct tcmu_device *dev,
				    struct tcmulib_cmd *readcmd, int ret)
{
	uint32_t cmp_offset;
	struct tcmu_call_stub stub;
	struct tcmu_caw_state *state = readcmd->cmdstate;
	struct tcmulib_cmd *origcmd = state->origcmd;
	uint8_t *sense = origcmd->sense_buf;
	struct tcmulib_handler *handler = tcmu_get_dev_handler(dev);
	struct tcmur_handler *store = handler->hm_private;

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
	stub.callout_cbk = call_store_caw_write_cbk;

	stub.u.rw.exec = store->write;
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

static int call_store_caw(struct tcmu_device *dev,
			  struct tcmur_handler *store,
			  struct tcmulib_cmd *tcmulib_cmd,
			  struct iovec *iovec, size_t iov_cnt, off_t off)
{
	int ret;
	struct tcmu_call_stub stub;
	struct tcmulib_cmd *readcmd;
	uint8_t *sense = tcmulib_cmd->sense_buf;
	ssize_t half = (tcmu_iovec_length(iovec, iov_cnt)) / 2;

	ret = errno_to_sam_status(-ENOMEM, sense);

	readcmd = caw_init_readcmd(tcmulib_cmd, off, half);
	if (!readcmd)
		goto out;

	stub.sop = TCMU_STORE_OP_READ;
	stub.callout_cbk = call_store_caw_read_cbk;

	stub.u.rw.exec = store->read;
	stub.u.rw.iov = readcmd->iovec;
	stub.u.rw.iov_cnt = readcmd->iov_cnt;
	stub.u.rw.off = off;

	aio_command_start(dev);
	pthread_mutex_lock(&dev->caw_lock);

	ret = async_call_command(dev, readcmd, &stub);
	if (ret == TCMU_ASYNC_HANDLED)
		return TCMU_ASYNC_HANDLED;

	pthread_mutex_unlock(&dev->caw_lock);
	aio_command_finish(dev, tcmulib_cmd, ret, false);

	caw_free_readcmd(readcmd);
out:
	return ret;
}

/* async flush */
static void call_store_flush_cbk(struct tcmu_device *dev,
				 struct tcmulib_cmd *tcmulib_cmd, int ret)
{
	aio_command_finish(dev, tcmulib_cmd, ret, true);
}

static int call_store_flush(struct tcmu_device *dev,
			    struct tcmur_handler *store,
			    struct tcmulib_cmd *tcmulib_cmd)
{
	int ret;
	struct tcmu_call_stub stub;

	stub.sop = TCMU_STORE_OP_FLUSH;
	stub.callout_cbk = call_store_flush_cbk;
	stub.u.flush.exec = store->flush;

	aio_command_start(dev);
	ret = async_call_command(dev, tcmulib_cmd, &stub);
	if (ret != TCMU_ASYNC_HANDLED)
		aio_command_finish(dev, tcmulib_cmd, ret, false);
	return ret;
}

/* async write */
static void call_store_write_cbk(struct tcmu_device *dev,
				 struct tcmulib_cmd *tcmulib_cmd, int ret)
{
	aio_command_finish(dev, tcmulib_cmd, ret, true);
}

static int call_store_write(struct tcmu_device *dev,
			    struct tcmur_handler *store,
			    struct tcmulib_cmd *tcmulib_cmd,
			    struct iovec *iovec, size_t iov_cnt, off_t off)
{
	int ret;
	struct tcmu_call_stub stub;

	stub.sop = TCMU_STORE_OP_WRITE;
	stub.callout_cbk = call_store_write_cbk;

	stub.u.rw.exec = store->write;
	stub.u.rw.iov = iovec;
	stub.u.rw.iov_cnt = iov_cnt;
	stub.u.rw.off = off;

	aio_command_start(dev);
	ret = async_call_command(dev, tcmulib_cmd, &stub);
	if (ret != TCMU_ASYNC_HANDLED)
		aio_command_finish(dev, tcmulib_cmd, ret, false);
	return ret;
}

/* async read */
static void call_store_read_cbk(struct tcmu_device *dev,
				struct tcmulib_cmd *tcmulib_cmd, int ret)
{
	aio_command_finish(dev, tcmulib_cmd, ret, true);
}

static int call_store_read(struct tcmu_device *dev,
			   struct tcmur_handler *store,
			   struct tcmulib_cmd *tcmulib_cmd,
			   struct iovec *iovec, size_t iov_cnt, off_t off)
{
	int ret;
	struct tcmu_call_stub stub;

	stub.sop = TCMU_STORE_OP_READ;
	stub.callout_cbk = call_store_read_cbk;

	stub.u.rw.exec = store->read;
	stub.u.rw.iov = iovec;
	stub.u.rw.iov_cnt = iov_cnt;
	stub.u.rw.off = off;

	aio_command_start(dev);
	ret = async_call_command(dev, tcmulib_cmd, &stub);
	if (ret != TCMU_ASYNC_HANDLED)
		aio_command_finish(dev, tcmulib_cmd, ret, false);
	return ret;
}

int call_store_handler(struct tcmu_device *dev,
		       struct tcmur_handler *store,
		       struct tcmulib_cmd *tcmulib_cmd, int cmd)
{
	uint8_t *cdb = tcmulib_cmd->cdb;
	struct iovec *iovec = tcmulib_cmd->iovec;
	size_t iov_cnt = tcmulib_cmd->iov_cnt;
	uint32_t block_size = tcmu_get_dev_block_size(dev);
	off_t offset = block_size * tcmu_get_lba(cdb);

	switch(cmd) {
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		return call_store_read(dev, store,
				       tcmulib_cmd, iovec, iov_cnt, offset);
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		return call_store_write(dev, store,
					tcmulib_cmd, iovec, iov_cnt, offset);
	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16:
		return call_store_flush(dev, store, tcmulib_cmd);
	case COMPARE_AND_WRITE:
		return call_store_caw(dev, store,
				      tcmulib_cmd, iovec, iov_cnt, offset);
	case WRITE_VERIFY:
		return call_store_write_verify(dev, tcmulib_cmd, offset);
	default:
		tcmu_err("unknown command %x\n", cdb[0]);
		return TCMU_NOT_HANDLED;
	}
}

/* command passthrough */
static void
call_store_passthrough_cbk(struct tcmu_device *dev,
			   struct tcmulib_cmd *tcmulib_cmd, int ret)
{
	uint8_t cmd = (tcmulib_cmd->cdb)[0];
	struct tcmulib_handler *handler = tcmu_get_dev_handler(dev);
	struct tcmur_handler *store = handler->hm_private;

	if (ret != TCMU_NOT_HANDLED) {
		aio_command_finish(dev, tcmulib_cmd, ret, true);
		return;
	}

	/* passthrough command was not handled - fallback to generic handling */
	ret = call_store_handler(dev, store, tcmulib_cmd, cmd);
	aio_command_finish(dev, tcmulib_cmd, ret,
			    (ret != TCMU_ASYNC_HANDLED) ? true : false);
}

static int call_store_passthrough(struct tcmu_device *dev,
				  struct tcmur_handler *store,
				  struct tcmulib_cmd *tcmulib_cmd)
{
	int ret;
	struct tcmu_call_stub stub;

	stub.sop = TCMU_STORE_OP_HANDLE_CMD;
	stub.callout_cbk = call_store_passthrough_cbk;
	stub.u.handle_cmd.exec = store->handle_cmd;

	aio_command_start(dev);
	ret = async_call_command(dev, tcmulib_cmd, &stub);
	if (ret != TCMU_ASYNC_HANDLED)
		aio_command_finish(dev, tcmulib_cmd, ret, false);
	return ret;
}

/*
 * try to passthrough the command if handler supports command passthrough.
 * note that TCMU_NOT_HANDLED is returned when a store handler does not
 * handle a passthrough command, but since we call ->handle_cmd via
 * async_call_command(), ->handle_cmd can finish in the callers context
 * (asynchronous handler) or work queue context (synchronous handlers),
 * thus we'd need to check if ->handle_cmd handled the passthough command
 * here as well as in call_store_passthrough_cbk().
 */
int call_store(struct tcmu_device *dev,
	       struct tcmulib_cmd *tcmulib_cmd, uint8_t cmd)
{
	int ret;
	struct tcmulib_handler *handler = tcmu_get_dev_handler(dev);
	struct tcmur_handler *store = handler->hm_private;

	if (store->handle_cmd) {
		ret = call_store_passthrough(dev, store, tcmulib_cmd);
		if ((ret == TCMU_ASYNC_HANDLED) || (ret != TCMU_NOT_HANDLED))
			return ret;
	}

	return call_store_handler(dev, store, tcmulib_cmd, cmd);
}
