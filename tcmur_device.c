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

#include "libtcmu_log.h"
#include "libtcmu_common.h"
#include "tcmu-runner.h"
#include "tcmur_device.h"
#include "tcmur_cmd_handler.h"
#include "target.h"

bool tcmu_dev_in_recovery(struct tcmu_device *dev)
{
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	int in_recov = false;

	pthread_mutex_lock(&rdev->state_lock);
	if (rdev->flags & TCMUR_DEV_FLAG_IN_RECOVERY)
		in_recov = true;
	pthread_mutex_unlock(&rdev->state_lock);
	return in_recov;
}

/*
 * TCMUR_DEV_FLAG_IN_RECOVERY must be set before calling
 */
int __tcmu_reopen_dev(struct tcmu_device *dev, bool in_lock_thread, int retries)
{
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);
	int ret, attempt = 0;

	tcmu_dev_dbg(dev, "Waiting for outstanding commands to complete\n");
	ret = aio_wait_for_empty_queue(rdev);

	pthread_mutex_lock(&rdev->state_lock);
	if (ret)
		goto done;

	if (rdev->flags & TCMUR_DEV_FLAG_STOPPING) {
		ret = 0;
		goto done;
	}
	pthread_mutex_unlock(&rdev->state_lock);

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
	pthread_mutex_lock(&rdev->state_lock);
	if (rdev->lock_state != TCMUR_DEV_LOCK_LOCKING)
		rdev->lock_state = TCMUR_DEV_LOCK_UNLOCKED;
	pthread_mutex_unlock(&rdev->state_lock);

	tcmu_dev_dbg(dev, "Closing device.\n");
	rhandler->close(dev);

	pthread_mutex_lock(&rdev->state_lock);
	rdev->flags &= ~TCMUR_DEV_FLAG_IS_OPEN;
	ret = -EIO;
	while (ret != 0 && !(rdev->flags & TCMUR_DEV_FLAG_STOPPING) &&
	       (retries < 0 || attempt <= retries)) {
		pthread_mutex_unlock(&rdev->state_lock);

		tcmu_dev_dbg(dev, "Opening device. Attempt %d\n", attempt);
		ret = rhandler->open(dev, true);
		if (ret) {
			/* Avoid busy loop ? */
			sleep(1);
		}

		pthread_mutex_lock(&rdev->state_lock);
		if (!ret) {
			rdev->flags |= TCMUR_DEV_FLAG_IS_OPEN;
		}
		attempt++;
	}

done:
	rdev->flags &= ~TCMUR_DEV_FLAG_IN_RECOVERY;
	pthread_mutex_unlock(&rdev->state_lock);

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
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);

	pthread_mutex_lock(&rdev->state_lock);
	if (rdev->flags & TCMUR_DEV_FLAG_IN_RECOVERY) {
		pthread_mutex_unlock(&rdev->state_lock);
		return -EBUSY;
	}
	rdev->flags |= TCMUR_DEV_FLAG_IN_RECOVERY;
	pthread_mutex_unlock(&rdev->state_lock);

	return __tcmu_reopen_dev(dev, in_lock_thread, retries);
}

void tcmu_cancel_recovery(struct tcmu_device *dev)
{
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);

	/*
	 * Only file and qcow can be canceled in their open/close calls, but
	 * they do not support recovery, so wait here for rbd/glfs type of
	 * handlers to fail/complete normally to avoid a segfault.
	 */
	tcmu_dev_dbg(dev, "Waiting on recovery thread\n");
	pthread_mutex_lock(&rdev->state_lock);
	while (rdev->flags & TCMUR_DEV_FLAG_IN_RECOVERY) {
		pthread_mutex_unlock(&rdev->state_lock);
		sleep(1);
		pthread_mutex_lock(&rdev->state_lock);
	}
	pthread_mutex_unlock(&rdev->state_lock);
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
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);

	pthread_mutex_lock(&rdev->state_lock);

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
	if ((rdev->flags & TCMUR_DEV_FLAG_STOPPING) ||
		(rdev->flags & TCMUR_DEV_FLAG_IN_RECOVERY))
		goto unlock;

	tcmu_dev_err(dev, "Handler connection lost (lock state %d)\n",
		     rdev->lock_state);

	if (!tcmu_add_dev_to_recovery_list(dev))
		rdev->flags |= TCMUR_DEV_FLAG_IN_RECOVERY;
unlock:
	pthread_mutex_unlock(&rdev->state_lock);
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
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);

	pthread_mutex_lock(&rdev->state_lock);
	tcmu_dev_warn(dev, "Async lock drop. Old state %d\n", rdev->lock_state);
	/*
	 * We could be getting stale IO completions. If we are trying to
	 * reaquire the lock do not change state.
	 */
	if (rdev->lock_state != TCMUR_DEV_LOCK_LOCKING)
		rdev->lock_state = TCMUR_DEV_LOCK_UNLOCKED;
	pthread_mutex_unlock(&rdev->state_lock);
}

int tcmu_cancel_lock_thread(struct tcmu_device *dev)
{
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	int ret;

	pthread_mutex_lock(&rdev->state_lock);
	if (rdev->lock_state != TCMUR_DEV_LOCK_LOCKING) {
		pthread_mutex_unlock(&rdev->state_lock);
		return 0;
	}
	/*
	 * It looks like lock calls are not cancelable, so
	 * we wait here to avoid crashes.
	 */
	tcmu_dev_dbg(dev, "Waiting on lock thread\n");

	tcmu_dev_dbg(rdev->dev, "waiting for lock thread to exit\n");
	ret = pthread_cond_wait(&rdev->lock_cond, &rdev->state_lock);
	pthread_mutex_unlock(&rdev->state_lock);

	return ret;
}

void tcmu_release_dev_lock(struct tcmu_device *dev)
{
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	int ret;

	pthread_mutex_lock(&rdev->state_lock);
	if (rdev->lock_state != TCMUR_DEV_LOCK_LOCKED) {
		pthread_mutex_unlock(&rdev->state_lock);
		return;
	}
	pthread_mutex_unlock(&rdev->state_lock);

	ret = rhandler->unlock(dev);
	if (ret != TCMU_STS_OK)
		tcmu_dev_warn(dev, "Lock not cleanly released. Ret %d.\n",
			      ret);
	/*
	 * If we don't have a clean unlock we still report success and set
	 * to unlocked to prevent new IO from executing in case the lock
	 * is in a state where it cannot be fenced.
	 */
	pthread_mutex_lock(&rdev->state_lock);
	rdev->lock_state = TCMUR_DEV_LOCK_UNLOCKED;
	pthread_mutex_unlock(&rdev->state_lock);
}

int tcmu_get_lock_tag(struct tcmu_device *dev, uint16_t *tag)
{
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	int retry = 0, ret;

	if (rdev->failover_type != TMCUR_DEV_FAILOVER_EXPLICIT)
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
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	int retries = 0, ret = TCMU_STS_OK;

	/* Block the kernel device. */
	tcmu_block_device(dev);

	tcmu_dev_dbg(dev, "Waiting for outstanding commands to complete\n");
	if (aio_wait_for_empty_queue(rdev)) {
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
		     rdev->lock_state, retries, tag);

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
	pthread_mutex_lock(&rdev->state_lock);
	if (ret == TCMU_STS_OK)
		rdev->lock_state = TCMUR_DEV_LOCK_LOCKED;
	else
		rdev->lock_state = TCMUR_DEV_LOCK_UNLOCKED;
	tcmu_dev_dbg(dev, "lock call done. lock state %d\n", rdev->lock_state);
	pthread_cond_signal(&rdev->lock_cond);
	pthread_mutex_unlock(&rdev->state_lock);

	tcmu_unblock_device(dev);

	return ret;
}
