/*
 * Copyright (c) 2017 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */

#ifndef __TCMUR_CMD_HANDLER_H
#define __TCMUR_CMD_HANDLER_H

#include <stdint.h>

#include "libtcmu.h"

struct tcmu_device;
struct tcmulib_cmd;

int tcmur_generic_handle_cmd(struct tcmu_device *dev, struct tcmulib_cmd *cmd);
int tcmur_cmd_passthrough_handler(struct tcmu_device *dev, struct tcmulib_cmd *cmd);
bool tcmulib_backstore_handler_is_passthrough_only(struct tcmulib_backstore_handler *rhandler);
typedef int (*tcmur_writesame_fn_t)(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			   uint64_t off, uint64_t len, struct iovec *iov, size_t iov_cnt);
int tcmur_handle_writesame(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			   tcmur_writesame_fn_t write_same_fn);

typedef int (*tcmur_caw_fn_t)(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
                              uint64_t off, uint64_t len, struct iovec *iov,
                              size_t iov_cnt);
int tcmur_handle_caw(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
                     tcmur_caw_fn_t caw_fn);

#endif /* __TCMUR_CMD_HANDLER_H */
