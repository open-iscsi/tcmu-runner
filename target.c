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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <inttypes.h>
#include <limits.h>

#include "ccan/list/list.h"

#include "libtcmu_log.h"
#include "libtcmu_common.h"
#include "tcmur_device.h"
#include "target.h"
#include "alua.h"

static int tcmu_set_tpgt_int(struct tgt_port *port, const char *name, int val)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), CFGFS_ROOT"/%s/%s/tpgt_%hu/%s",
		 port->fabric, port->wwn, port->tpgt, name);
	return tcmu_set_cfgfs_ul(path, val);
}

static int tcmu_get_tpgt_int(struct tgt_port *port, const char *name)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path),
		 CFGFS_ROOT"/%s/%s/tpgt_%hu/%s",
		 port->fabric, port->wwn, port->tpgt, name);
	return tcmu_get_cfgfs_int(path);
}

static int tcmu_get_lun_int_stat(struct tgt_port *port, uint64_t lun,
				 const char *stat_name)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path),
		 CFGFS_ROOT"/%s/%s/tpgt_%hu/lun/lun_%"PRIu64"/statistics/%s",
		 port->fabric, port->wwn, port->tpgt, lun, stat_name);
	return tcmu_get_cfgfs_int(path);
}

void tcmu_free_tgt_port(struct tgt_port *port)
{
	if (port->wwn)
		free(port->wwn);
	if (port->fabric)
		free(port->fabric);
	free(port);
}

struct tgt_port *tcmu_get_tgt_port(char *member_str)
{
	struct tgt_port *port;
	char fabric[17], wwn[224];
	uint64_t lun;
	uint16_t tpgt;
	int ret;

	if (!strlen(member_str))
		return NULL;

	ret = sscanf(member_str, "%16[^/]/%223[^/]/tpgt_%hu/lun_%"PRIu64,
		     fabric, wwn, &tpgt, &lun);
	if (ret != 4) {
		tcmu_err("Invalid ALUA member %s\n", member_str);
		return NULL;
	}

	port = calloc(1, sizeof(*port));
	if (!port)
		return NULL;
	list_node_init(&port->entry);

	if (!strcmp(fabric, "iSCSI"))
		/*
		 * iSCSI's fabric name and target_core_fabric_ops name do
		 * not match.
		 */
		port->fabric = strdup("iscsi");
	else
		port->fabric = strdup(fabric);
	if (!port->fabric)
		goto free_port;

	port->wwn = strdup(wwn);
	if (!port->wwn)
		goto free_port;

	port->tpgt = tpgt;

	ret = tcmu_get_lun_int_stat(port, lun, "scsi_port/indx");
	if (ret < 0)
		goto free_port;

	port->rel_port_id = ret;

	ret = tcmu_get_lun_int_stat(port, lun, "scsi_transport/proto_id");
	if (ret < 0)
		goto free_port;
	port->proto_id = ret;

	ret = tcmu_get_tpgt_int(port, "enable");
	if (ret < 0)
		goto free_port;
	port->enabled = ret;

	return port;

free_port:
	tcmu_free_tgt_port(port);
	return NULL;
}

/*
 * Disable the target tpg to avoid flip flopping between paths
 * (transport path is ok so multipath layer switches to it, but
 * then sends IO only for it to fail due to the handler not
 * being able to reach its backend).
 */
static int tcmu_reset_tpg(struct tcmu_device *dev, struct tgt_port *port)
{
	int ret;

	/*
	 * This will return when all running commands have completed at
	 * the target layer.
	 */
	tcmu_dev_dbg(dev, "Disabling %s/%s/tpgt_%hu.\n", port->fabric,
		     port->wwn, port->tpgt);
	ret = tcmu_set_tpgt_int(port, "enable", 0);
	if (ret < 0) {
		tcmu_dev_err(dev, "Could not disable %s/%s/tpgt_%hu (err %d).\n",
			     ret, port->fabric, port->wwn, port->tpgt);
		return ret;
	}

	tcmu_dev_info(dev, "Disabled %s/%s/tpgt_%hu.\n", port->fabric,
		      port->wwn, port->tpgt);

	ret = tcmu_reopen_dev(dev);
	if (ret) {
		tcmu_dev_err(dev, "Could not reset device. (err %d).\n", ret);
		return ret;
	}

	ret = tcmu_set_tpgt_int(port, "enable", 1);
	if (ret) {
		tcmu_dev_err(dev, "Could not enable %s/%s/tpgt_%hu (err %d).\n",
			     ret, port->fabric, port->wwn, port->tpgt);
	} else {
		tcmu_dev_info(dev, "Enabled %s/%s/tpgt_%hu.\n", port->fabric,
			      port->wwn, port->tpgt);
	}

	return ret;
}

void tcmu_reset_tpgs(struct tcmu_device *dev)
{
	struct list_head group_list;
	struct tgt_port_grp *group;
	struct tgt_port *port;
	int ret;

	list_head_init(&group_list);
	ret = tcmu_get_tgt_port_grps(dev, &group_list);
	if (ret) {
		tcmu_dev_err(dev, "Could not find any tpgs.\n");
		return;
	}

	list_for_each(&group_list, group, entry) {
		list_for_each(&group->tgt_ports, port, entry) {
			if (port->enabled) {
				tcmu_reset_tpg(dev, port);
			}
		}
	}

	tcmu_release_tgt_port_grps(&group_list);
}
