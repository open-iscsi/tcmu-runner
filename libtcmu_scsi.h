/*
 * Copyright (c) 2017 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */

#ifndef __LIBTCMU_SCSI_H
#define __LIBTCMU_SCSI_H

#include <stdbool.h>
#include <inttypes.h>
#include <sys/types.h>

#include "libtcmu.h"
#include "libtcmu_common.h"

struct tcmu_device;
struct tcmulib_cmd;


void tcmur_command_complete(struct tcmu_device *dev, struct tcmulib_cmd *cmd, int rc);
int handle_passthrough(struct tcmu_device *dev, struct tcmulib_cmd *cmd);
int handle_unmap(struct tcmu_device *dev, struct tcmulib_cmd *origcmd);
int handle_writesame(struct tcmu_device *dev, struct tcmulib_cmd *cmd);
int tcmur_handle_writesame(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			   tcmur_writesame_fn_t write_same_fn);
int handle_write_verify(struct tcmu_device *dev, struct tcmulib_cmd *cmd);
int handle_xcopy(struct tcmu_device *dev, struct tcmulib_cmd *cmd);
int handle_caw(struct tcmu_device *dev, struct tcmulib_cmd *cmd);
int tcmur_handle_caw(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
		     tcmur_caw_fn_t caw_fn);
int handle_flush(struct tcmu_device *dev, struct tcmulib_cmd *cmd);
int handle_recv_copy_result(struct tcmu_device *dev, struct tcmulib_cmd *cmd);
int handle_write(struct tcmu_device *dev, struct tcmulib_cmd *cmd);
int handle_read(struct tcmu_device *dev, struct tcmulib_cmd *cmd);
int handle_format_unit(struct tcmu_device *dev, struct tcmulib_cmd *cmd);
int handle_stpg(struct tcmu_device *dev, struct tcmulib_cmd *cmd);
int handle_rtpg(struct tcmu_device *dev, struct tcmulib_cmd *cmd);
int handle_inquiry(struct tcmu_device *dev, struct tcmulib_cmd *cmd);
int tcmur_dev_update_size(struct tcmu_device *dev, unsigned long new_size);
void tcmur_set_pending_ua(struct tcmu_device *dev, int ua);
int handle_pending_ua(struct tcmur_device *rdev, struct tcmulib_cmd *cmd);

#endif
