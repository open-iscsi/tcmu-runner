/*
 * tcmu timer wheel
 *
 * Copyright (c) 2018 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */

#ifndef __LIBTCMU_TIMER_H
#define __LIBTCMU_TIMER_H

#include <pthread.h>
#include "ccan/list/list.h"

struct tcmu_timer {
        void *data;
        unsigned long expires;

        void (*function)(struct tcmu_timer *, void *);

        struct list_node entry;
};

int tcmu_init_timer_base(void);
void tcmu_cleanup_timer_base(void);
int tcmu_add_timer(struct tcmu_timer *);
int tcmu_del_timer(struct tcmu_timer *);
int tcmu_mod_timer_pending(struct tcmu_timer *, unsigned long);
int tcmu_mod_timer(struct tcmu_timer *, unsigned long);

#endif
