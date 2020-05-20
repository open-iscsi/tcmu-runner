/*
 * Copyright (c) 2020 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */

#ifndef __TCMU_WORK_H
#define __TCMU_WORK_H

#include <pthread.h>

#include "ccan/list/list.h"

struct tcmu_device;

struct tcmur_work {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	int refcnt;
};

struct tcmur_work *tcmur_create_work(void);
void tcmur_destroy_work(struct tcmur_work *work);
int tcmur_run_work(struct tcmur_work *work, void *data,
		   void (*work_fn)(void *));
void tcmur_flush_work(struct tcmur_work *work);

#endif
