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

#ifndef __TCMU_ALUA_H
#define __TCMU_ALUA_H

#include "ccan/list/list.h"

struct tcmu_device;

struct tgt_port {
	uint16_t rel_port_id;
	uint8_t proto_id;
	char *wwn;

	/* LIO settings */
	char *fabric;
	bool enabled;
	/* configfs tpgt */
	uint16_t tpgt;

	struct tgt_port_grp *grp;
	/* entry on group's tgt_ports list */
	struct list_node entry;
};

struct tgt_port_grp {
	/* ALUA spec values */
	uint8_t state;
	uint8_t supported_states;
	uint8_t tpgs;
	uint8_t status;
	uint8_t implicit_trans_secs;
	bool pref;
	uint16_t id;

	/* LIO settings */
	char *name;
	unsigned nonop_delay_msecs;
	unsigned trans_delay_msecs;

	struct tcmu_device *dev;
	uint8_t num_tgt_ports;
	/* entry on list returned by lib */
	struct list_node entry;
	struct list_head tgt_ports;
};

struct tgt_port *tcmu_get_enabled_port(struct list_head *);
int tcmu_get_tgt_port_grps(struct tcmu_device *, struct list_head *);
void tcmu_release_tgt_port_grps(struct list_head *);

#endif
