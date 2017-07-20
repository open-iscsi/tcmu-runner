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

#ifndef __LIBTCMU_CMD_HANDLER_H
#define __LIBTCMU_CMD_HANDLER_H

#include <stdint.h>

struct tcmu_device;
struct tcmulib_cmd;

int tcmulib_handle_cmds(struct tcmu_device *dev, struct tcmulib_cmd *cmd);
int tcmulib_passthrough_cmds(struct tcmu_device *dev, struct tcmulib_cmd *cmd);
bool tcmulib_handler_is_passthrough_only(struct tcmur_handler *rhandler);
void tcmulib_handle_cmd_complete(struct tcmu_device *dev, struct tcmulib_cmd *cmd, int ret);

#endif /* __LIBTCMU_CMD_HANDLER_H */
