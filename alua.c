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
	else {
		tcmu_dev_err(dev, "Invalid ALUA status %s", str_val);
		goto free_str_val;
	}
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
	else {
		tcmu_dev_err(dev, "Invalid ALUA type %s", str_val);
		goto free_str_val;
	}
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

free_str_val:
	free(str_val);
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
 *
 * For now, we will only support ALUA if the user has defined groups.
 * tcmu ALUA support was added in 4.11, but not all fabric modules support
 * it. Depending on the kernel version and tools used we could have:
 *
 * 1. The default ALUA group, but empty members.
 * 2. The default ALUA group, and reading/writing to members will return
 *    a error or crash the kernel.
 * 3. The default ALUA group, and members set to it, but some fabric
 *    modules did not report the target port group/tag properly so
 *    we cannot match groups to ports.
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
		tcmu_dev_err(dev, "Could not get ALUA dirs for %s\n", path);
		return -errno;
	}

	for (i = 0; i < n; i++) {
		if (!strcmp(namelist[i]->d_name, "default_tg_pt_gp"))
			continue;

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

static bool alua_check_sup_state(uint8_t state, uint8_t sup)
{
	switch (state) {
	case ALUA_ACCESS_STATE_OPTIMIZED:
		if (sup & ALUA_SUP_OPTIMIZED)
			return true;
		return false;
	case ALUA_ACCESS_STATE_NON_OPTIMIZED:
		if (sup & ALUA_SUP_NON_OPTIMIZED)
			return true;
		return false;
	case ALUA_ACCESS_STATE_STANDBY:
		if (sup & ALUA_SUP_STANDBY)
			return true;
		return false;
	case ALUA_ACCESS_STATE_UNAVAILABLE:
		if (sup & ALUA_SUP_UNAVAILABLE)
			return true;
		return false;
	case ALUA_ACCESS_STATE_OFFLINE:
		/*
		 * TODO: support secondary states
		 */
		return false;
	}

	return false;
}

static int tcmu_do_transition(struct tcmu_device *dev,
			      struct tgt_port_grp *group, uint8_t new_state,
			      uint8_t *sense)
{
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);
	int ret;

	switch (new_state) {
	case ALUA_ACCESS_STATE_OPTIMIZED:
	case ALUA_ACCESS_STATE_NON_OPTIMIZED:
		if (rhandler->lock && rhandler->lock(dev))
			return tcmu_set_sense_data(sense, HARDWARE_ERROR,
						   ASC_STPG_CMD_FAILED, NULL);
		/* TODO for ESX set remote ports to standby */
		return SAM_STAT_GOOD;
	case ALUA_ACCESS_STATE_STANDBY:
	case ALUA_ACCESS_STATE_UNAVAILABLE:
	case ALUA_ACCESS_STATE_OFFLINE:
		if (rhandler->unlock) {
			ret = rhandler->unlock(dev);
			if (ret < 0)
				/*
				 * Return success even though we failed. The initiator
				 * will send a STPG to the port it wants to activate,
				 * and that node will grab the lock from us if it hasn't
				 * already.
				 */
				tcmu_dev_err(dev, "Could not release lock. (Err %d)\n",
					     ret);
		}
		return SAM_STAT_GOOD;
	}

	return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
				   ASC_INVALID_FIELD_IN_PARAMETER_LIST, NULL);
}

int tcmu_transition_tgt_port_grp(struct tgt_port_grp *group, uint8_t new_state,
				 uint8_t alua_status, uint8_t *sense)
{
	struct tcmu_device *dev = group->dev;
	int ret;

	tcmu_dev_dbg(dev, "transition group %u new state %u old state %u sup 0x%x\n",
		 group->id, new_state, group->state, group->supported_states);

	if (!alua_check_sup_state(new_state, group->supported_states)) {
		if (sense)
			return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
						   ASC_INVALID_FIELD_IN_PARAMETER_LIST,
						   NULL);
		else
			return SAM_STAT_CHECK_CONDITION;
	}

	if (sense) {
		ret = tcmu_do_transition(dev, group, new_state, sense);
		if (ret != SAM_STAT_GOOD)
			return ret;
	}

	ret = tcmu_set_alua_int_setting(group, "alua_access_state", new_state);
	if (ret) {
		tcmu_dev_err(dev, "Could not change kernel state to %u\n", new_state);
		if (sense)
			return tcmu_set_sense_data(sense, HARDWARE_ERROR,
						   ASC_STPG_CMD_FAILED, NULL);
		else
			return SAM_STAT_CHECK_CONDITION;
	}

	ret = tcmu_set_alua_int_setting(group, "alua_access_status", alua_status);
	if (ret)
		tcmu_dev_err(dev, "Could not set alua_access_status for group %s:%d\n",
			 group->name, group->id);

	group->state = new_state;
	group->status = alua_status;
	return SAM_STAT_GOOD;
}

static int tcmu_report_state(struct tcmu_device *dev,
			     struct tgt_port_grp *group)
{
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);
	int ret;

	/* TODO: For ESX return remote ports */

	if (!rhandler->has_lock)
		return group->state;

	ret = rhandler->has_lock(dev);
	if (ret <= 0) {
		return ALUA_ACCESS_STATE_STANDBY;
	} else {
		return ALUA_ACCESS_STATE_OPTIMIZED;
	}
}

int tcmu_emulate_report_tgt_port_grps(struct tcmu_device *dev,
				      struct list_head *group_list,
				      struct tcmulib_cmd *cmd)
{
	struct tgt_port_grp *group;
	struct tgt_port *port;
	int ext_hdr = cmd->cdb[1] & 0x20;
	uint32_t off = 4, ret_data_len = 0, ret32;
	uint32_t alloc_len = tcmu_get_xfer_length(cmd->cdb);
	uint8_t *buf, state;

	if (!tcmu_get_enabled_port(group_list))
		return TCMU_NOT_HANDLED;

	if (alloc_len < 4)
		return tcmu_set_sense_data(cmd->sense_buf, HARDWARE_ERROR,
					   ASC_INTERNAL_TARGET_FAILURE, NULL);

	buf = calloc(1, alloc_len);
	if (!buf)
		return tcmu_set_sense_data(cmd->sense_buf, HARDWARE_ERROR,
					   ASC_INTERNAL_TARGET_FAILURE, NULL);

	if (ext_hdr && alloc_len > 5) {
		buf[4] = 0x10;
		/*
		 * assume all groups will have the same value for now.
		 */
		group = list_first_entry(group_list, struct tgt_port_grp,
					 entry);
		if (group)
			buf[5] = group->implicit_trans_secs;
		off = 8;
	}

	list_for_each(group_list, group, entry) {
		int next_off = off + 8 + (group->num_tgt_ports * 4);

		if (next_off > alloc_len) {
			ret_data_len += next_off;
			continue;
		}

		if (group->pref)
			buf[off] = 0x80;

		state = tcmu_report_state(dev, group);
		/*
		 * Some handlers are not able to async update state,
		 * so check it now and update.
		 */
		if (state != group->state) {
			if (tcmu_transition_tgt_port_grp(group, state,
							 ALUA_STAT_ALTERED_BY_IMPLICIT_ALUA,
							 NULL))
				tcmu_dev_err(dev, "Could not perform implicit state change for group %u\n", group->id);
		}

		buf[off++] |= state;
		buf[off++] |= group->supported_states;
		buf[off++] = (group->id >> 8) & 0xff;
		buf[off++] = group->id & 0xff;
		/* reserved */
		off++;
		buf[off++] = group->status;
		/* vendor specific */
		off++;
		buf[off++] = group->num_tgt_ports;

		ret_data_len += 8;

		list_for_each(&group->tgt_ports, port, entry) {
			/* reserved */
			off += 2;
			buf[off++] = (port->rel_port_id >> 8) & 0xff;
			buf[off++] = port->rel_port_id & 0xff;

			ret_data_len += 4;
		}

	}
	ret32 = htobe32(ret_data_len);
	memcpy(&buf[0], &ret32, 4);

	tcmu_memcpy_into_iovec(cmd->iovec, cmd->iov_cnt, buf, alloc_len);
	free(buf);
	return SAM_STAT_GOOD;
}

int tcmu_emulate_set_tgt_port_grps(struct tcmu_device *dev,
				   struct list_head *group_list,
				   struct tcmulib_cmd *cmd)
{
	struct tgt_port_grp *group;
	uint32_t off = 4, param_list_len = tcmu_get_xfer_length(cmd->cdb);
	uint16_t id, tmp_id;
	char *buf, new_state;
	int found, ret = SAM_STAT_GOOD;

	if (!tcmu_get_enabled_port(group_list))
		return TCMU_NOT_HANDLED;

	if (!param_list_len)
		return SAM_STAT_GOOD;

	buf = calloc(1, param_list_len);
	if (!buf)
		return tcmu_set_sense_data(cmd->sense_buf, HARDWARE_ERROR,
					   ASC_INTERNAL_TARGET_FAILURE, NULL);

	if (tcmu_memcpy_from_iovec(buf, param_list_len, cmd->iovec,
				   cmd->iov_cnt) != param_list_len) {
		ret = tcmu_set_sense_data(cmd->sense_buf, ILLEGAL_REQUEST,
					  ASC_PARAMETER_LIST_LENGTH_ERROR,
					  NULL);
		goto free_buf;
	}

	while (off < param_list_len) {
		new_state = buf[off++] & 0x0f;
		/* reserved */
		off++;
		memcpy(&tmp_id, &buf[off], sizeof(tmp_id));
		id = be16toh(tmp_id);
		off += 2;

		found = 0;
		list_for_each(group_list, group, entry) {
			if (group->id != id)
				continue;

			tcmu_dev_dbg(dev, "Got STPG for group %u\n", id);
			ret = tcmu_transition_tgt_port_grp(group, new_state,
							   ALUA_STAT_ALTERED_BY_EXPLICIT_STPG,
							   cmd->sense_buf);
			if (ret) {
				tcmu_dev_err(dev, "Failing STPG for group %d\n", id);
				goto free_buf;
			}
			found = 1;
			break;
		}

		if (!found) {
			/*
			 * Could not find what error code to return in
			 * SCSI spec.
			 */
			tcmu_dev_err(dev, "Could not find group for %u for STPG\n", id);
			ret = tcmu_set_sense_data(cmd->sense_buf,
					HARDWARE_ERROR,
					ASC_STPG_CMD_FAILED, NULL);
			break;
		}
	}

free_buf:
	free(buf);
	return ret;
}
