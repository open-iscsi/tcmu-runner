/*
 * Copyright (c) 2017 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
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
