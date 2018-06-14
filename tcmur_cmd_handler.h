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

#endif /* __TCMUR_CMD_HANDLER_H */
