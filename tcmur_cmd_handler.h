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

#ifndef __TCMUR_CMD_HANDLER_H
#define __TCMUR_CMD_HANDLER_H

#include <stdint.h>

struct tcmu_device;
struct tcmulib_cmd;

void tcmur_set_pending_ua(struct tcmu_device *dev, int ua);
int tcmur_generic_handle_cmd(struct tcmu_device *dev, struct tcmulib_cmd *cmd);
int tcmur_cmd_passthrough_handler(struct tcmu_device *dev, struct tcmulib_cmd *cmd);
bool tcmur_handler_is_passthrough_only(struct tcmur_handler *rhandler);
void tcmur_command_complete(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			    int ret);
typedef int (*tcmur_writesame_fn_t)(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			   uint64_t off, uint64_t len, struct iovec *iov, size_t iov_cnt);
int tcmur_handle_writesame(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			   tcmur_writesame_fn_t write_same_fn);


#endif /* __TCMUR_CMD_HANDLER_H */
