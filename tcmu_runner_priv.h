/*
 * Copyright (c) 2018 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */

/*
 * This header defines structures private to tcmu-runner, and should not
 * be used by anyone else.
 */

#ifndef __TCMU_RUNNER_PRIV_H
#define __TCMU_RUNNER_PRIV_H

struct tcmu_device;
struct tcmur_handler;

struct tcmur_handler *tcmu_get_runner_handler(struct tcmu_device *dev);

#endif
