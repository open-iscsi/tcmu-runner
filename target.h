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

#ifndef __TCMU_TARGET_H
#define __TCMU_TARGET_H

#include "ccan/list/list.h"

struct tgt_port_grp;

struct tgt_port {
	uint16_t rel_port_id;
	uint8_t proto_id;
	char *wwn;

	/* LIO settings */
	char *fabric;
	bool enabled;
	/* configfs tpgt */
	uint16_t tpgt;

	struct alua_grp *grp;
	/* entry on group's tgt_ports list */
	struct list_node entry;
};

void tcmu_free_tgt_port(struct tgt_port *port);
struct tgt_port *tcmu_get_tgt_port(char *member_str);
int tcmu_add_dev_to_recovery_list(struct tcmu_device *dev);

#endif
