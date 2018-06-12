/*
 * Copyright (c) 2017 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */

#define _GNU_SOURCE
#include <scsi/scsi.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "ccan/list/list.h"

#include "darray.h"
#include "libtcmu.h"
#include "libtcmu_log.h"
#include "libtcmu_priv.h"
#include "libtcmu_common.h"
#include "libtcmu_aio.h"
#include "libtcmu_device.h"
#include "tcmur_cmd_handler.h"
#include "libtcmu_alua.h"
#include "libtcmu_scsi.h"

bool tcmulib_backstore_handler_is_passthrough_only(struct tcmulib_backstore_handler *rhandler)
{
	if (rhandler->write || rhandler->read || rhandler->flush)
		return false;

	return true;
}

int tcmur_cmd_passthrough_handler(struct tcmu_device *dev,
				  struct tcmulib_cmd *cmd)
{
	struct tcmulib_backstore_handler *rhandler = tcmu_get_runner_handler(dev);
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	int ret;

	if (!rhandler->handle_cmd)
		return TCMU_STS_NOT_HANDLED;

	/*
	 * Support handlers that implement their own threading/AIO
	 * and only use runner's main event loop.
	 */
	if (!rhandler->nr_threads)
		return rhandler->handle_cmd(dev, cmd);
	/*
	 * Since we call ->handle_cmd via async_handle_cmd(), ->handle_cmd
	 * can finish in the callers context(asynchronous handler) or work
	 * queue context (synchronous handlers), thus we'd need to check if
	 * ->handle_cmd handled the passthough command here as well as in
	 * handle_passthrough_cbk().
	 */
	track_aio_request_start(rdev);
	ret = handle_passthrough(dev, cmd);
	if (ret != TCMU_STS_ASYNC_HANDLED)
		track_aio_request_finish(rdev, NULL);

	return ret;
}

static int tcmur_cmd_handler(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	int ret = TCMU_STS_NOT_HANDLED;
	struct tcmulib_backstore_handler *rhandler = tcmu_get_runner_handler(dev);
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	uint8_t *cdb = cmd->cdb;

	track_aio_request_start(rdev);

	if (tcmu_dev_in_recovery(dev)) {
		ret = TCMU_STS_BUSY;
		goto untrack;
	}

	/* Don't perform alua implicit transition if command is not supported */
	switch(cdb[0]) {
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
	case UNMAP:
	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16:
	case EXTENDED_COPY:
	case COMPARE_AND_WRITE:
	case WRITE_VERIFY:
	case WRITE_VERIFY_16:
	case WRITE_SAME:
	case WRITE_SAME_16:
	case FORMAT_UNIT:
		ret = alua_check_state(dev, cmd);
		if (ret)
			goto untrack;
		break;
	default:
		break;
	}

	switch(cdb[0]) {
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		ret = handle_read(dev, cmd);
		break;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		ret = handle_write(dev, cmd);
		break;
	case UNMAP:
		ret = handle_unmap(dev, cmd);
		break;
	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16:
		if (rhandler->flush)
			ret = handle_flush(dev, cmd);
		break;
	case EXTENDED_COPY:
		ret = handle_xcopy(dev, cmd);
		break;
	case COMPARE_AND_WRITE:
		ret = handle_caw(dev, cmd);
		break;
	case WRITE_VERIFY:
	case WRITE_VERIFY_16:
		ret = handle_write_verify(dev, cmd);
		break;
	case WRITE_SAME:
	case WRITE_SAME_16:
		ret = handle_writesame(dev, cmd);
		break;
	case FORMAT_UNIT:
		ret = handle_format_unit(dev, cmd);
		break;
	default:
		ret = TCMU_STS_NOT_HANDLED;
	}

untrack:
	if (ret != TCMU_STS_ASYNC_HANDLED)
		track_aio_request_finish(rdev, NULL);
	return ret;
}

static int handle_sync_cmd(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	uint8_t *cdb = cmd->cdb;
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
	uint32_t block_size = tcmu_get_dev_block_size(dev);
	uint64_t num_lbas = tcmu_get_dev_num_lbas(dev);

	switch (cdb[0]) {
	case INQUIRY:
		return handle_inquiry(dev, cmd);
	case TEST_UNIT_READY:
		return tcmu_emulate_test_unit_ready(cdb, iovec, iov_cnt);
	case SERVICE_ACTION_IN_16:
		if (cdb[1] == READ_CAPACITY_16)
			return tcmu_emulate_read_capacity_16(num_lbas,
							     block_size,
							     cdb, iovec,
							     iov_cnt);
		else
			return TCMU_STS_NOT_HANDLED;
	case READ_CAPACITY:
		if ((cdb[1] & 0x01) || (cdb[8] & 0x01))
			/* Reserved bits for MM logical units */
			return TCMU_STS_INVALID_CDB;
		else
			return tcmu_emulate_read_capacity_10(num_lbas,
							     block_size,
							     cdb, iovec,
							     iov_cnt);
	case MODE_SENSE:
	case MODE_SENSE_10:
		return tcmu_emulate_mode_sense(dev, cdb, iovec, iov_cnt);
	case START_STOP:
		return tcmu_emulate_start_stop(dev, cdb);
	case MODE_SELECT:
	case MODE_SELECT_10:
		return tcmu_emulate_mode_select(dev, cdb, iovec, iov_cnt);
	case RECEIVE_COPY_RESULTS:
		if ((cdb[1] & 0x1f) == RCR_SA_OPERATING_PARAMETERS)
			return handle_recv_copy_result(dev, cmd);
		return TCMU_STS_NOT_HANDLED;
	case MAINTENANCE_OUT:
		if (cdb[1] == MO_SET_TARGET_PGS)
			return handle_stpg(dev, cmd);
		return TCMU_STS_NOT_HANDLED;
	case MAINTENANCE_IN:
		if ((cdb[1] & 0x1f) == MI_REPORT_TARGET_PGS)
			return handle_rtpg(dev, cmd);
		return TCMU_STS_NOT_HANDLED;
	default:
		return TCMU_STS_NOT_HANDLED;
	}
}

static int handle_try_passthrough(struct tcmu_device *dev,
				  struct tcmulib_cmd *cmd)
{
	struct tcmulib_backstore_handler *rhandler = tcmu_get_runner_handler(dev);
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	int ret;

	if (!rhandler->handle_cmd)
		return TCMU_STS_NOT_HANDLED;

	track_aio_request_start(rdev);

	if (tcmu_dev_in_recovery(dev)) {
		ret = TCMU_STS_BUSY;
	} else {
		ret = rhandler->handle_cmd(dev, cmd);
	}

	if (ret != TCMU_STS_ASYNC_HANDLED)
		track_aio_request_finish(rdev, NULL);

	return ret;
}

int tcmur_generic_handle_cmd(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	int ret;

	ret = handle_pending_ua(rdev, cmd);
	if (ret != TCMU_STS_NOT_HANDLED)
		return ret;

	if (rdev->flags & TCMUR_DEV_FLAG_FORMATTING && cmd->cdb[0] != INQUIRY) {
		tcmu_set_sense_key_specific_info(cmd->sense_buf,
						 rdev->format_progress);
		return TCMU_STS_FRMT_IN_PROGRESS;
	}

	/*
	 * The handler want to handle some commands by itself,
	 * try to passthrough it first
	 */
	ret = handle_try_passthrough(dev, cmd);
	if (ret != TCMU_STS_NOT_HANDLED)
		return ret;

	/* Falls back to the runner's generic handle callout */
	ret = handle_sync_cmd(dev, cmd);
	if (ret == TCMU_STS_NOT_HANDLED)
		ret = tcmur_cmd_handler(dev, cmd);
	return ret;
}
