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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <pthread.h>

#include "libtcmu_log.h"
#include "libtcmu_common.h"
#include "tcmur_device.h"

/**
 * tcmu_notify_lock_lost - notify runner the device instance has lost the lock
 * @dev: device that has lost the lock
 *
 * Handlers should call this function when they detect they have lost
 * the lock, so runner can re-acquire.
 */
void tcmu_notify_lock_lost(struct tcmu_device *dev)
{
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);

	pthread_mutex_lock(&rdev->state_lock);
	tcmu_dev_err(dev, "Async lock drop. Old state %d\n", rdev->lock_state);
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
	void *join_retval;
	int ret;

	pthread_mutex_lock(&rdev->state_lock);
	if (rdev->lock_state != TCMUR_DEV_LOCK_LOCKING) {
		pthread_mutex_unlock(&rdev->state_lock);
		return 0;
	}
	pthread_mutex_unlock(&rdev->state_lock);
	/*
	 * It looks like lock calls are not cancelable, so
	 * we wait here to avoid crashes.
	 */
	tcmu_dev_dbg(dev, "Waiting on lock thread\n");
	ret = pthread_join(rdev->lock_thread, &join_retval);
	if (ret)
		tcmu_dev_err(dev, "pthread_join failed with value %d\n", ret);
	return ret;
}
