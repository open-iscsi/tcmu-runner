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

#include <scsi/scsi.h>

#include "libtcmu_log.h"
#include "libtcmu_common.h"
#include "libtcmu_priv.h"
#include "alua.h"

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

static char *tcmu_get_alua_str_setting(struct tgt_port_grp *group,
				       const char *setting)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), CFGFS_CORE"/%s/%s/alua/%s/%s",
		 group->dev->tcm_hba_name, group->dev->tcm_dev_name,
		 group->name, setting);
	return tcmu_get_cfgfs_str(path);
}

static int tcmu_get_alua_int_setting(struct tgt_port_grp *group,
				     const char *setting)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), CFGFS_CORE"/%s/%s/alua/%s/%s",
		 group->dev->tcm_hba_name, group->dev->tcm_dev_name,
		 group->name, setting);
	return tcmu_get_cfgfs_int(path);
}

static int tcmu_set_alua_int_setting(struct tgt_port_grp *group,
				     const char *setting, int val)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), CFGFS_CORE"/%s/%s/alua/%s/%s",
		 group->dev->tcm_hba_name, group->dev->tcm_dev_name,
		 group->name, setting);
	return tcmu_set_cfgfs_ul(path, val);
}

static void tcmu_free_tgt_port(struct tgt_port *port)
{
	if (port->wwn)
		free(port->wwn);
	if (port->fabric)
		free(port->fabric);
	free(port);
}

static void tcmu_release_tgt_ports(struct tgt_port_grp *group)
{
	struct tgt_port *port, *port_next;

	list_for_each_safe(&group->tgt_ports, port, port_next, entry) {
		list_del(&port->entry);
		tcmu_free_tgt_port(port);
	}
}

static struct tgt_port *
tcmu_get_tgt_port(struct tgt_port_grp *group, char *member_str)
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
		tcmu_err("Invalid ALUA member %s for group %s\n", member_str,
			 group->name);
		return NULL;
	}

	port = calloc(1, sizeof(*port));
	if (!port)
		return NULL;
	list_node_init(&port->entry);
	port->grp = group;

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

static void tcmu_free_tgt_port_grp(struct tgt_port_grp *group)
{
	tcmu_release_tgt_ports(group);

	if (group->name)
		free(group->name);
	free(group);
}

static struct tgt_port_grp *
tcmu_get_tgt_port_grp(struct tcmu_device *dev, const char *name)
{
	struct tgt_port_grp *group;
	struct tgt_port *port;
	char *str_val, *orig_str_val, *member;
	int val;

	group = calloc(1, sizeof(*group));
	if (!group)
		return NULL;
	list_head_init(&group->tgt_ports);
	list_node_init(&group->entry);
	group->dev = dev;
	group->name = strdup(name);
	if (!group->name)
		goto free_group;

	val = tcmu_get_alua_int_setting(group, "alua_access_state");
	if (val < 0)
		goto free_group;
	group->state = val;

	val = tcmu_get_alua_int_setting(group, "alua_support_active_nonoptimized");
	if (val < 0)
		goto free_group;
	if (val)
		group->supported_states |= ALUA_SUP_NON_OPTIMIZED;

	val = tcmu_get_alua_int_setting(group, "alua_support_active_optimized");
	if (val < 0)
		goto free_group;
	if (val)
		group->supported_states |= ALUA_SUP_OPTIMIZED;

	val = tcmu_get_alua_int_setting(group, "alua_support_lba_dependent");
	if (val < 0)
		goto free_group;
	if (val)
		group->supported_states |= ALUA_SUP_LBA_DEPENDENT;

	val = tcmu_get_alua_int_setting(group, "alua_support_offline");
	if (val < 0)
		goto free_group;
	if (val)
		group->supported_states |= ALUA_SUP_OFFLINE;

	val = tcmu_get_alua_int_setting(group, "alua_support_standby");
	if (val < 0)
		goto free_group;
	if (val)
		group->supported_states |= ALUA_SUP_STANDBY;

	val = tcmu_get_alua_int_setting(group, "alua_support_transitioning");
	if (val < 0)
		goto free_group;
	if (val)
		group->supported_states |= ALUA_SUP_TRANSITIONING;

	val = tcmu_get_alua_int_setting(group, "alua_support_unavailable");
	if (val < 0)
		goto free_group;
	if (val)
		group->supported_states |= ALUA_SUP_UNAVAILABLE;

	val = tcmu_get_alua_int_setting(group, "implicit_trans_secs");
	if (val < 0)
		goto free_group;
	group->implicit_trans_secs = val;

	val = tcmu_get_alua_int_setting(group, "nonop_delay_msecs");
	if (val < 0)
		goto free_group;
	group->nonop_delay_msecs = val;

	val = tcmu_get_alua_int_setting(group, "trans_delay_msecs");
	if (val < 0)
		goto free_group;
	group->trans_delay_msecs = val;

	val = tcmu_get_alua_int_setting(group, "tg_pt_gp_id");
	if (val < 0)
		goto free_group;
	group->id = val;

	val = tcmu_get_alua_int_setting(group, "preferred");
	if (val < 0)
		goto free_group;
	group->pref = val ? true : false;

	str_val = tcmu_get_alua_str_setting(group, "alua_access_status");
	if (!str_val)
		goto free_group;

	if (!strcmp(str_val, "None"))
		group->status = ALUA_STAT_NONE;
	else if (!strcmp(str_val, "Altered by Explicit STPG"))
		group->status = ALUA_STAT_ALTERED_BY_EXPLICIT_STPG;
	else if (!strcmp(str_val, "Altered by Implicit ALUA"))
		group->status = ALUA_STAT_ALTERED_BY_IMPLICIT_ALUA;
	else
		tcmu_err("Invalid ALUA status %s", str_val);
	free(str_val);

	str_val = tcmu_get_alua_str_setting(group, "alua_access_type");
	if (!str_val)
		goto free_group;

	if (!strcmp(str_val, "None"))
		group->tpgs = TPGS_ALUA_NONE;
	else if (!strcmp(str_val, "Implicit"))
		group->tpgs = TPGS_ALUA_IMPLICIT;
	else if (!strcmp(str_val, "Explicit"))
		group->tpgs = TPGS_ALUA_EXPLICIT;
	else if (!strcmp(str_val, "Implicit and Explicit"))
		group->tpgs = (TPGS_ALUA_IMPLICIT | TPGS_ALUA_EXPLICIT);
	else
		tcmu_err("Invalid ALUA type %s", str_val);
	free(str_val);

	str_val = orig_str_val = tcmu_get_alua_str_setting(group, "members");
	if (str_val) {
		while ((member = strsep(&str_val, "\n"))) {
			if (!strlen(member))
				continue;

			port = tcmu_get_tgt_port(group, member);
			if (!port) {
				free(orig_str_val);
				goto free_ports;
			}
			group->num_tgt_ports++;
			list_add_tail(&group->tgt_ports, &port->entry);
		}
	}

	free(orig_str_val);
	return group;

free_ports:
	tcmu_release_tgt_ports(group);
free_group:
	tcmu_free_tgt_port_grp(group);
	return NULL;
}

void tcmu_release_tgt_port_grps(struct list_head *group_list)
{
	struct tgt_port_grp *group, *group_next;

	list_for_each_safe(group_list, group, group_next, entry) {
		list_del(&group->entry);
		tcmu_free_tgt_port_grp(group);
	}
}

static int alua_filter(const struct dirent *dir)
{
        return strcmp(dir->d_name, ".") && strcmp(dir->d_name, "..");
}

/**
 * tcmu_get_tgt_port_grps: Fill group_list with the kernel's port groups.
 * @dev: device to get groups for.
 * @group_list: list allocated by the caller to add groups to.
 *
 * User must call tcmu_release_tgt_port_grps when finished with the list of
 * groups.
 */
int tcmu_get_tgt_port_grps(struct tcmu_device *dev,
			   struct list_head *group_list)
{
	struct tgt_port_grp *group;
	struct dirent **namelist;
	char path[PATH_MAX];
	int i, n, ret = 0;

	snprintf(path, sizeof(path), CFGFS_CORE"/%s/%s/alua",
		 dev->tcm_hba_name, dev->tcm_dev_name);
	n = scandir(path, &namelist, alua_filter, alphasort);
	if (n < 0) {
		tcmu_err("Could not get ALUA dirs for %s\n", path);
		return -errno;
	}

	for (i = 0; i < n; i++) {
		group = tcmu_get_tgt_port_grp(dev, namelist[i]->d_name);
		if (!group)
			goto free_groups;
		list_add_tail(group_list, &group->entry);
	}
	goto free_names;

free_groups:
	tcmu_release_tgt_port_grps(group_list);
free_names:
	for (i = 0; i < n; i++)
		free(namelist[i]);
	free(namelist);
	return ret;
}

/*
 * tcmu does not pass up the target port that the command was
 * received on, so if a LUN is exported through multiple ports
 * in different ALUA target port group we do not know which group
 * to use.
 *
 * For now we support one target port group that contains all
 * enabled ports, or for HA configs one local target port group with
 * enabled ports and N remote port groups which are marked disabled
 * on the the local node.
 */
struct tgt_port *tcmu_get_enabled_port(struct list_head *group_list)
{
	struct tgt_port_grp *group;
	struct tgt_port *port;

	list_for_each(group_list, group, entry) {
		list_for_each(&group->tgt_ports, port, entry) {
			if (port->enabled)
				return port;
		}
	}

	return NULL;
}
