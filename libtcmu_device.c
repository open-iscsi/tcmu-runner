/*
 * Copyright (c) 2017 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>

#include "libtcmu.h"
#include "libtcmu_log.h"
#include "libtcmu_common.h"
#include "libtcmu_device.h"
#include "libtcmu_priv.h"
#include "tcmur_cmd_handler.h"
#include "libtcmu_tpg.h"
#include "libtcmu_scsi.h"
#include "libtcmu_aio.h"
#include "tcmuhandler-generated.h"
#include "libtcmu_config.h"
#include "libtcmu_log.h"
#include "libtcmu_alua.h"

bool tcmu_dev_in_recovery(struct tcmu_device *dev)
{
	int in_recov = false;

	pthread_mutex_lock(&dev->state_lock);
	if (dev->flags & TCMUR_DEV_FLAG_IN_RECOVERY)
		in_recov = true;
	pthread_mutex_unlock(&dev->state_lock);
	return in_recov;
}

/*
 * TCMUR_DEV_FLAG_IN_RECOVERY must be set before calling
 */
int __tcmu_reopen_dev(struct tcmu_device *dev, bool in_lock_thread, int retries)
{
	struct tcmulib_backstore_handler *rhandler = tcmu_get_runner_handler(dev);
	int ret, attempt = 0;

	tcmu_dev_dbg(dev, "Waiting for outstanding commands to complete\n");
	ret = aio_wait_for_empty_queue(dev);

	pthread_mutex_lock(&dev->state_lock);
	if (ret)
		goto done;

	if (dev->flags & TCMUR_DEV_FLAG_STOPPING) {
		ret = 0;
		goto done;
	}
	pthread_mutex_unlock(&dev->state_lock);

	/*
	 * There are no SCSI commands running but there may be
	 * async lock requests in progress that might be accessing
	 * the device.
	 */
	if (!in_lock_thread)
		tcmu_cancel_lock_thread(dev);

	/*
	 * Force a reacquisition of the lock when we have reopend the
	 * device, so it can update state. If we are being called from
	 * the lock code path then do not change state.
	 */
	pthread_mutex_lock(&dev->state_lock);
	if (dev->lock_state != TCMUR_DEV_LOCK_LOCKING)
		dev->lock_state = TCMUR_DEV_LOCK_UNLOCKED;
	pthread_mutex_unlock(&dev->state_lock);

	tcmu_dev_dbg(dev, "Closing device.\n");
	rhandler->close(dev);

	pthread_mutex_lock(&dev->state_lock);
	dev->flags &= ~TCMUR_DEV_FLAG_IS_OPEN;
	ret = -EIO;
	while (ret != 0 && !(dev->flags & TCMUR_DEV_FLAG_STOPPING) &&
	       (retries < 0 || attempt <= retries)) {
		pthread_mutex_unlock(&dev->state_lock);

		tcmu_dev_dbg(dev, "Opening device. Attempt %d\n", attempt);
		ret = rhandler->open(dev, true);
		if (ret) {
			/* Avoid busy loop ? */
			sleep(1);
		}

		pthread_mutex_lock(&dev->state_lock);
		if (!ret) {
			dev->flags |= TCMUR_DEV_FLAG_IS_OPEN;
		}
		attempt++;
	}

done:
	dev->flags &= ~TCMUR_DEV_FLAG_IN_RECOVERY;
	pthread_mutex_unlock(&dev->state_lock);

	return ret;
}

/*
 * tcmu_reopen_dev - close and open device.
 * @dev: device to reopen
 * @in_lock_thread: true if called from locking thread.
 * @retries: number of times to retry open() call. -1 indicates infinite.
 */
int tcmu_reopen_dev(struct tcmu_device *dev, bool in_lock_thread, int retries)
{
	pthread_mutex_lock(&dev->state_lock);
	if (dev->flags & TCMUR_DEV_FLAG_IN_RECOVERY) {
		pthread_mutex_unlock(&dev->state_lock);
		return -EBUSY;
	}
	dev->flags |= TCMUR_DEV_FLAG_IN_RECOVERY;
	pthread_mutex_unlock(&dev->state_lock);

	return __tcmu_reopen_dev(dev, in_lock_thread, retries);
}

void tcmu_cancel_recovery(struct tcmu_device *dev)
{
	/*
	 * Only file and qcow can be canceled in their open/close calls, but
	 * they do not support recovery, so wait here for rbd/glfs type of
	 * handlers to fail/complete normally to avoid a segfault.
	 */
	tcmu_dev_dbg(dev, "Waiting on recovery thread\n");
	pthread_mutex_lock(&dev->state_lock);
	while (dev->flags & TCMUR_DEV_FLAG_IN_RECOVERY) {
		pthread_mutex_unlock(&dev->state_lock);
		sleep(1);
		pthread_mutex_lock(&dev->state_lock);
	}
	pthread_mutex_unlock(&dev->state_lock);
	tcmu_dev_dbg(dev, "Recovery thread wait done\n");
}

/**
 * tcmu_notify_conn_lost - notify runner the device instace has lost its
 * 			   connection to its backend storage.
 * @dev: device that has lost its connection
 *
 * Handlers should call this function when they detect they cannot reach their
 * backend storage/medium/cache, so new commands will not be queued until
 * the device has been reopened.
 */
void tcmu_notify_conn_lost(struct tcmu_device *dev)
{
	pthread_mutex_lock(&dev->state_lock);

	/*
	 * Although there are 2 checks for STOPPING in __tcmu_reopen_dev
	 * which is called a little later by the recovery thread, STOPPING
	 * checking is still needed here.
	 *
	 * In device removal, tcmu_get_alua_grps will never get access to
	 * configfs dir resource which is holded by kernel in configfs_rmdir,
	 * thus tcmulib_cmd->done() will never get a chance to clear
	 * tracked_aio_ops. This will cause a deadlock in dev_removed
	 * which is polling tracked_aio_ops.
	 */
	if ((dev->flags & TCMUR_DEV_FLAG_STOPPING) ||
		(dev->flags & TCMUR_DEV_FLAG_IN_RECOVERY))
		goto unlock;

	tcmu_dev_err(dev, "Handler connection lost (lock state %d)\n",
		     dev->lock_state);

	if (!tcmu_add_dev_to_recovery_list(dev))
		dev->flags |= TCMUR_DEV_FLAG_IN_RECOVERY;
unlock:
	pthread_mutex_unlock(&dev->state_lock);
}

/**
 * tcmu_notify_lock_lost - notify runner the device instance has lost the lock
 * @dev: device that has lost the lock
 *
 * Handlers should call this function when they detect they have lost
 * the lock, so runner can re-acquire. It must be called before completing
 * a command that had caused the failure.
 */
void tcmu_notify_lock_lost(struct tcmu_device *dev)
{
	pthread_mutex_lock(&dev->state_lock);
	tcmu_dev_warn(dev, "Async lock drop. Old state %d\n", dev->lock_state);
	/*
	 * We could be getting stale IO completions. If we are trying to
	 * reaquire the lock do not change state.
	 */
	if (dev->lock_state != TCMUR_DEV_LOCK_LOCKING)
		dev->lock_state = TCMUR_DEV_LOCK_UNLOCKED;
	pthread_mutex_unlock(&dev->state_lock);
}

int tcmu_cancel_lock_thread(struct tcmu_device *dev)
{
	int ret;

	pthread_mutex_lock(&dev->state_lock);
	if (dev->lock_state != TCMUR_DEV_LOCK_LOCKING) {
		pthread_mutex_unlock(&dev->state_lock);
		return 0;
	}
	/*
	 * It looks like lock calls are not cancelable, so
	 * we wait here to avoid crashes.
	 */
	tcmu_dev_dbg(dev, "Waiting on lock thread\n");

	tcmu_dev_dbg(dev, "waiting for lock thread to exit\n");
	ret = pthread_cond_wait(&dev->lock_cond, &dev->state_lock);
	pthread_mutex_unlock(&dev->state_lock);

	return ret;
}

void tcmu_release_dev_lock(struct tcmu_device *dev)
{
	struct tcmulib_backstore_handler *rhandler = tcmu_get_runner_handler(dev);
	int ret;

	pthread_mutex_lock(&dev->state_lock);
	if (dev->lock_state != TCMUR_DEV_LOCK_LOCKED) {
		pthread_mutex_unlock(&dev->state_lock);
		return;
	}
	pthread_mutex_unlock(&dev->state_lock);

	ret = rhandler->unlock(dev);
	if (ret != TCMU_STS_OK)
		tcmu_dev_warn(dev, "Lock not cleanly released. Ret %d.\n",
			      ret);
	/*
	 * If we don't have a clean unlock we still report success and set
	 * to unlocked to prevent new IO from executing in case the lock
	 * is in a state where it cannot be fenced.
	 */
	pthread_mutex_lock(&dev->state_lock);
	dev->lock_state = TCMUR_DEV_LOCK_UNLOCKED;
	pthread_mutex_unlock(&dev->state_lock);
}

int tcmu_get_lock_tag(struct tcmu_device *dev, uint16_t *tag)
{
	struct tcmulib_backstore_handler *rhandler = tcmu_get_runner_handler(dev);
	int retry = 0, ret;

	if (dev->failover_type != TMCUR_DEV_FAILOVER_EXPLICIT)
		return 0;

retry:
	ret = rhandler->get_lock_tag(dev, tag);
	tcmu_dev_dbg(dev, "Got rc %d tag %hu\n", ret, *tag);

	switch (ret) {
	case TCMU_STS_OK:
		break;
	case TCMU_STS_NO_LOCK_HOLDERS:
		/* No lock holder yet */
		break;
	case TCMU_STS_FENCED:
		/*
		 * This is safe without blocking/flushing because it
		 * is called from the main IO thread and will wait for
		 * commands started before it via the aio wait call.
		 */
		tcmu_dev_dbg(dev, "Could not access dev. Try reopen.");
		ret = tcmu_reopen_dev(dev, false, 0);
		if (!ret && retry < 1) {
			retry++;
			goto retry;
		}
		/* fallthrough */
	case TCMU_STS_TIMEOUT:
	default:
		tcmu_dev_dbg(dev, "Could not reach device to get locker id\n");
		/*
		 * In spc4r37 and newer
		 * "5.15.2.7 Target port asymmetric access state reporting"
		 * states that the initiator should consider the info
		 * returned through our enabled port current for that
		 * enabled port. If a RTPG sent through another port
		 * returns different info, then the info for the enabled
		 * port returned through the enabled port should be
		 * considered current.
		 *
		 * ESX though assumes the all port info in a RTPG to be
		 * current so we drop the session here to prevent sending
		 * inconsistent info. We probably want to do this regardless
		 * of ESX, because that value is returned when the handler
		 * cannot connect to the cluster so all requests are
		 * going to fail.
		 */
		tcmu_notify_conn_lost(dev);
		/*
		 * To try and not return inconsistent info and not look
		 * like a hard device error, fail the command so it is
		 * retried and the retry will be handled like other commands
		 * during session level recovery.
		 */
		return TCMU_STS_BUSY;
	}

	return ret;
}

int tcmu_acquire_dev_lock(struct tcmu_device *dev, bool is_sync,
			  uint16_t tag)
{
	struct tcmulib_backstore_handler *rhandler = tcmu_get_runner_handler(dev);
	int retries = 0, ret = TCMU_STS_OK;

	/* Block the kernel device. */
	tcmu_block_device(dev);

	tcmu_dev_dbg(dev, "Waiting for outstanding commands to complete\n");
	if (aio_wait_for_empty_queue(dev)) {
		tcmu_dev_err(dev, "Not able to flush queue before taking lock.\n");
		goto done;
	}

	/*
	 * Handle race where cmd could be in tcmur_generic_handle_cmd before
	 * the aio handler. For explicit ALUA, we execute the lock call from
	 * the main io processing thread, so this will deadlock waiting on
	 * the STPG.
	 */
	if (!is_sync)
		tcmu_flush_device(dev);

retry:
	tcmu_dev_dbg(dev, "lock call state %d retries %d. tag %hu\n",
		     dev->lock_state, retries, tag);

	ret = rhandler->lock(dev, tag);
	switch (ret) {
	case TCMU_STS_FENCED:
		/*
		 * Try to reopen the backend device. If this
		 * fails then go into recovery, so the initaitor
		 * can drop down to another path.
		 */
		tcmu_dev_dbg(dev, "Try to reopen device. %d\n", retries);
		if (retries < 1 && !tcmu_reopen_dev(dev, true, 0)) {
			retries++;
			goto retry;
		}
		/* fallthrough */
	case TCMU_STS_TIMEOUT:
		tcmu_dev_dbg(dev, "Fail handler device connection.\n");
		tcmu_notify_conn_lost(dev);
		break;
	}

done:
	/* TODO: set UA based on bgly's patches */
	pthread_mutex_lock(&dev->state_lock);
	if (ret == TCMU_STS_OK)
		dev->lock_state = TCMUR_DEV_LOCK_LOCKED;
	else
		dev->lock_state = TCMUR_DEV_LOCK_UNLOCKED;
	tcmu_dev_dbg(dev, "lock call done. lock state %d\n", dev->lock_state);
	pthread_cond_signal(&dev->lock_cond);
	pthread_mutex_unlock(&dev->state_lock);

	tcmu_unblock_device(dev);

	return ret;
}

/*
 * tcmur_stop_device - stop device for removal
 * @arg: tcmu_device to stop
 *
 * Stop internal tcmur device operations like lock and recovery and close
 * the device. Running IO must be stopped before calling this.
 */
static void tcmur_stop_device(void *arg)
{
	struct tcmu_device *dev = arg;
	struct tcmulib_backstore_handler *rhandler = tcmu_get_runner_handler(dev);
	bool is_open = false;

	pthread_mutex_lock(&dev->state_lock);
	/* check if this was already called due to thread cancelation */
	if (dev->flags & TCMUR_DEV_FLAG_STOPPED) {
		pthread_mutex_unlock(&dev->state_lock);
		return;
	}
	dev->flags |= TCMUR_DEV_FLAG_STOPPING;
	pthread_mutex_unlock(&dev->state_lock);

	/*
	 * The lock thread can fire off the recovery thread, so make sure
	 * it is done first.
	 */
	tcmu_cancel_lock_thread(dev);
	tcmu_cancel_recovery(dev);

	pthread_mutex_lock(&dev->state_lock);
	if (dev->flags & TCMUR_DEV_FLAG_IS_OPEN) {
		dev->flags &= ~TCMUR_DEV_FLAG_IS_OPEN;
		is_open = true;
	}
	pthread_mutex_unlock(&dev->state_lock);

	if (is_open) {
		tcmu_release_dev_lock(dev);
		rhandler->close(dev);
	}

	pthread_mutex_lock(&dev->state_lock);
	dev->flags |= TCMUR_DEV_FLAG_STOPPED;
	pthread_mutex_unlock(&dev->state_lock);

	tcmu_dev_dbg(dev, "cmdproc cleanup done\n");
}

static void *tcmur_cmdproc_thread(void *arg)
{
	struct tcmu_device *dev = arg;
	struct tcmulib_handler *handler = tcmu_get_dev_handler(dev);
	struct pollfd pfd;
	int ret;
	bool dev_stopping = false;

	pthread_cleanup_push(tcmur_stop_device, dev);

	while (1) {
		int completed = 0;
		struct tcmulib_cmd *cmd;

		tcmulib_processing_start(dev);

		while (!dev_stopping && (cmd = tcmulib_get_next_command(dev)) != NULL) {

			if (tcmu_get_log_level() == TCMU_LOG_DEBUG_SCSI_CMD)
				tcmu_print_cdb_info(dev, cmd, NULL);

			ret = handler->handle_cmds(dev, cmd);
			if (ret == TCMU_STS_NOT_HANDLED)
				tcmu_print_cdb_info(dev, cmd, "is not supported");

			/*
			 * command (processing) completion is called in the following
			 * scenarios:
			 *   - handle_cmd: synchronous handlers
			 *   - generic_handle_cmd: non tcmur handler calls (see generic_cmd())
			 *			   and on errors when calling tcmur handler.
			 */
			if (ret != TCMU_STS_ASYNC_HANDLED) {
				completed = 1;
				tcmur_command_complete(dev, cmd, ret);
			}
		}

		if (completed)
			tcmulib_processing_complete(dev);

		pfd.fd = tcmu_get_dev_fd(dev);
		pfd.events = POLLIN;
		pfd.revents = 0;

		/* Use ppoll instead poll to avoid poll call reschedules during signal
		 * handling. If we were removing a device, then the uio device's memory
		 * could be freed, but the poll would be rescheduled and end up accessing
		 * the released device. */
		ret = ppoll(&pfd, 1, NULL, NULL);
		if (ret == -1) {
			tcmu_err("ppoll() returned %d\n", ret);
			break;
		}

		if (pfd.revents != POLLIN) {
			tcmu_err("ppoll received unexpected revent: 0x%x\n", pfd.revents);
			break;
		}

		/*
		 * LIO will wait for outstanding requests and prevent new ones
		 * from being sent to runner during device removal, but if the
		 * tcmu cmd_time_out has fired tcmu-runner may still be executing
		 * requests that LIO has completed. We only need to wait for replies
		 * for outstanding requests so throttle the cmdproc thread now.
		 */
		pthread_mutex_lock(&dev->state_lock);
		if (dev->flags & TCMUR_DEV_FLAG_STOPPING)
			dev_stopping = true;
		pthread_mutex_unlock(&dev->state_lock);
	}

	/*
	 * If we are doing a clean shutdown via dev_removed the
	 * removing thread will call the cleanup function when
	 * it has stopped and flushed the device.
	 */
	pthread_cleanup_pop(0);
	return NULL;
}

int tcmu_dev_added(struct tcmu_device *dev)
{
	struct tcmulib_backstore_handler *rhandler = tcmu_get_runner_handler(dev);
	struct list_head group_list;
	int32_t block_size, max_sectors;
	uint32_t max_xfer_length;
	int64_t dev_size;
	int ret = -EINVAL;

	list_node_init(&dev->recovery_entry);

	block_size = tcmu_get_attribute(dev, "hw_block_size");
	if (block_size <= 0) {
		tcmu_dev_err(dev, "Could not get hw_block_size\n");
		return ret;
	}
	tcmu_set_dev_block_size(dev, block_size);

	dev_size = tcmu_get_dev_size(dev);
	if (dev_size < 0) {
		tcmu_dev_err(dev, "Could not get device size\n");
		return ret;
	}
	tcmu_set_dev_num_lbas(dev, dev_size / block_size);

	max_sectors = tcmu_get_attribute(dev, "hw_max_sectors");
	if (max_sectors < 0)
		return ret;
	tcmu_set_dev_max_xfer_len(dev, max_sectors);

	tcmu_dev_dbg(dev, "Got block_size %ld, size in bytes %lld\n",
		     block_size, dev_size);

	ret = pthread_spin_init(&dev->lock, 0);
	if (ret != 0)
		return ret;

	ret = pthread_mutex_init(&dev->caw_lock, NULL);
	if (ret != 0)
		goto cleanup_dev_lock;

	ret = pthread_mutex_init(&dev->format_lock, NULL);
	if (ret != 0)
		goto cleanup_caw_lock;

	ret = pthread_mutex_init(&dev->state_lock, NULL);
	if (ret != 0)
		goto cleanup_format_lock;

	ret = setup_io_work_queue(dev);
	if (ret < 0)
		goto cleanup_state_lock;

	ret = setup_aio_tracking(dev);
	if (ret < 0)
		goto cleanup_io_work_queue;

	ret = rhandler->open(dev, false);
	if (ret)
		goto cleanup_aio_tracking;
	/*
	 * On the initial creation ALUA will probably not yet have been setup,
	 * but for reopens it will be so we need to sync our failover state.
	 */
	list_head_init(&group_list);
	tcmu_get_alua_grps(dev, &group_list);
	tcmu_release_alua_grps(&group_list);

	dev->flags |= TCMUR_DEV_FLAG_IS_OPEN;

	ret = pthread_cond_init(&dev->lock_cond, NULL);
	if (ret < 0)
		goto close_dev;

	/*
	 * Set the optimal unmap granularity to max xfer len. Optimal unmap
	 * alignment starts at the begining of the device.
	 */
	max_xfer_length = tcmu_get_dev_max_xfer_len(dev);
	tcmu_set_dev_opt_unmap_gran(dev, max_xfer_length);
	tcmu_set_dev_unmap_gran_align(dev, 0);

	ret = pthread_create(&dev->cmdproc_thread, NULL, tcmur_cmdproc_thread,
			     dev);
	if (ret < 0)
		goto cleanup_lock_cond;

	return 0;

cleanup_lock_cond:
	pthread_cond_destroy(&dev->lock_cond);
close_dev:
	rhandler->close(dev);
cleanup_aio_tracking:
	cleanup_aio_tracking(dev);
cleanup_io_work_queue:
	cleanup_io_work_queue(dev, true);
cleanup_state_lock:
	pthread_mutex_destroy(&dev->state_lock);
cleanup_format_lock:
	pthread_mutex_destroy(&dev->format_lock);
cleanup_caw_lock:
	pthread_mutex_destroy(&dev->caw_lock);
cleanup_dev_lock:
	pthread_spin_destroy(&dev->lock);
	return ret;
}

static void tcmu_cancel_thread(pthread_t thread)
{
	void *join_retval;
	int ret;

	ret = pthread_cancel(thread);
	if (ret) {
		tcmu_err("pthread_cancel failed with value %d\n", ret);
		return;
	}

	ret = pthread_join(thread, &join_retval);
	if (ret) {
		tcmu_err("pthread_join failed with value %d\n", ret);
		return;
	}

	if (join_retval != PTHREAD_CANCELED)
		tcmu_err("unexpected join retval: %p\n", join_retval);
}

void tcmu_dev_removed(struct tcmu_device *dev)
{
	int ret;

	pthread_mutex_lock(&dev->state_lock);
	dev->flags |= TCMUR_DEV_FLAG_STOPPING;
	pthread_mutex_unlock(&dev->state_lock);

	/*
	 * The order of cleaning up worker threads and calling ->removed()
	 * is important: for sync handlers, the worker thread needs to be
	 * terminated before removing the handler (i.e., calling handlers
	 * ->close() callout) in order to ensure that no handler callouts
	 * are getting invoked when shutting down the handler.
	 */
	cleanup_io_work_queue_threads(dev);

	if (aio_wait_for_empty_queue(dev))
		tcmu_dev_err(dev, "could not flush queue.\n");

	tcmu_cancel_thread(dev->cmdproc_thread);
	tcmur_stop_device(dev);

	cleanup_io_work_queue(dev, false);
	cleanup_aio_tracking(dev);

	ret = pthread_cond_destroy(&dev->lock_cond);
	if (ret != 0)
		tcmu_err("could not cleanup lock cond %d\n", ret);

	ret = pthread_mutex_destroy(&dev->state_lock);
	if (ret != 0)
		tcmu_err("could not cleanup state lock %d\n", ret);

	ret = pthread_mutex_destroy(&dev->format_lock);
	if (ret != 0)
		tcmu_err("could not cleanup format lock %d\n", ret);

	ret = pthread_mutex_destroy(&dev->caw_lock);
	if (ret != 0)
		tcmu_err("could not cleanup caw lock %d\n", ret);

	ret = pthread_spin_destroy(&dev->lock);
	if (ret != 0)
		tcmu_err("could not cleanup mailbox lock %d\n", ret);

	tcmu_dev_dbg(dev, "removed from tcmu-runner\n");
}

static int dev_resize(struct tcmu_device *dev, struct tcmulib_cfg_info *cfg)
{
	struct tcmulib_backstore_handler *rhandler = tcmu_get_runner_handler(dev);
	int ret;

	if (tcmu_get_dev_num_lbas(dev) * tcmu_get_dev_block_size(dev) ==
	    cfg->data.dev_size)
		return 0;

	ret = rhandler->reconfig(dev, cfg);
	if (ret)
		return ret;

	ret = tcmu_update_num_lbas(dev, cfg->data.dev_size);
	if (!ret)
		tcmur_set_pending_ua(dev, TCMUR_UA_DEV_SIZE_CHANGED);

	return ret;
}

int tcmu_dev_reconfig(struct tcmu_device *dev, struct tcmulib_cfg_info *cfg)
{
	struct tcmulib_backstore_handler *rhandler = tcmu_get_runner_handler(dev);

	if (!rhandler->reconfig) {
		tcmu_dev_err(dev, "Reconfiguration is not supported with this device.\n");
		return -EOPNOTSUPP;
	}

	switch (cfg->type) {
	case TCMULIB_CFG_DEV_SIZE:
		return dev_resize(dev, cfg);
	default:
		return rhandler->reconfig(dev, cfg);
	}
}

