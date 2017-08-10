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
#include "tcmur_device.h"
#include "target.h"
#include "alua.h"

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

static void tcmu_release_tgt_ports(struct tgt_port_grp *group)
{
	struct tgt_port *port, *port_next;

	list_for_each_safe(&group->tgt_ports, port, port_next, entry) {
		list_del(&port->entry);
		tcmu_free_tgt_port(port);
	}
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
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
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

	if (!strcmp(str_val, "None")) {
		/*
		 * Assume user wanted to do active-active.
		 * We still want the initiator to use RTPG and we
		 * can manually change states, so report this as
		 * implicit.
		 */
		rdev->failover_type = TMCUR_DEV_FAILOVER_ALL_ACTIVE;

		group->tpgs = TPGS_ALUA_IMPLICIT;
	} else if (!strcmp(str_val, "Implicit")) {
		rdev->failover_type = TMCUR_DEV_FAILOVER_IMPLICIT;

		group->tpgs = TPGS_ALUA_IMPLICIT;
	} else if (!strcmp(str_val, "Explicit") ||
		   !strcmp(str_val, "Implicit and Explicit")) {
		tcmu_dev_warn(dev, "Unsupported alua_access_type: Explicit failover not supported.\n");
		goto free_str_val;
	} else {
		tcmu_dev_err(dev, "Invalid ALUA type %s", str_val);
		goto free_str_val;
	}
	free(str_val);

	str_val = orig_str_val = tcmu_get_alua_str_setting(group, "members");
	if (str_val) {
		while ((member = strsep(&str_val, "\n"))) {
			if (!strlen(member))
				continue;

			port = tcmu_get_tgt_port(member);
			if (!port) {
				free(orig_str_val);
				goto free_ports;
			}
			port->grp = group;
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

int tcmu_emulate_report_tgt_port_grps(struct tcmu_device *dev,
				      struct list_head *group_list,
				      struct tcmulib_cmd *cmd)
{
	struct tgt_port_grp *group;
	struct tgt_port *port;
	int ext_hdr = cmd->cdb[1] & 0x20;
	uint32_t off = 4, ret_data_len = 0, ret32;
	uint32_t alloc_len = tcmu_get_xfer_length(cmd->cdb);
	uint8_t *buf;

	if (!tcmu_get_enabled_port(group_list))
		return TCMU_NOT_HANDLED;

	if (alloc_len < 4)
		return tcmu_set_sense_data(cmd->sense_buf, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_CDB, NULL);

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

		buf[off++] |= group->state;
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

static void *alua_lock_thread_fn(void *arg)
{
	struct tcmu_device *dev = arg;
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	int ret;

	tcmu_dev_dbg(dev, "Waiting for outstanding commands to complete\n");
	ret = aio_wait_for_empty_queue(rdev);
	if (ret) {
		tcmu_dev_err(dev, "Could not flush queue while performing lock operation. Err %d\n",
			     ret);
		pthread_mutex_lock(&rdev->state_lock);
		rdev->lock_state = TCMUR_DEV_LOCK_UNLOCKED;
		pthread_mutex_unlock(&rdev->state_lock);
		return NULL;
	}

	ret = rhandler->lock(dev);

	pthread_mutex_lock(&rdev->state_lock);
	switch (ret) {
	case TCMUR_LOCK_BUSY:
		rdev->lock_state = TCMUR_DEV_LOCK_LOCKING;
		break;
	case TCMUR_LOCK_FAILED:
		rdev->lock_state = TCMUR_DEV_LOCK_UNLOCKED;
		break;
	case TCMUR_LOCK_SUCCESS:
		rdev->lock_state = TCMUR_DEV_LOCK_LOCKED;
		break;
	}

	tcmu_dev_dbg(dev, "lock thread done. lock state %d\n", rdev->lock_state);
	/* TODO: set UA based on bgly's patches */
	pthread_mutex_unlock(&rdev->state_lock);
	return NULL;
}

int alua_implicit_transition(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	int ret = SAM_STAT_GOOD;

	pthread_mutex_lock(&rdev->state_lock);
	tcmu_dev_dbg(dev, "lock state %d\n", rdev->lock_state);
	if (rdev->lock_state == TCMUR_DEV_LOCK_LOCKED) {
		goto done;
	} else if (rdev->lock_state == TCMUR_DEV_LOCK_LOCKING) {
		ret = tcmu_set_sense_data(cmd->sense_buf, NOT_READY,
					  ASC_STATE_TRANSITION, NULL);
		goto done;
	}

	rdev->lock_state = TCMUR_DEV_LOCK_LOCKING;
	/*
	 * The initiator is going to be queueing commands, so do this
	 * in the background to avoid command timeouts.
	 */
	if (pthread_create(&rdev->lock_thread, NULL, alua_lock_thread_fn,
			   dev)) {
		tcmu_dev_err(dev, "Could not start implicit transition thread.\n");
		rdev->lock_state = TCMUR_DEV_LOCK_UNLOCKED;
		ret = tcmu_set_sense_data(cmd->sense_buf, UNIT_ATTENTION,
					  ASC_STATE_TRANSITION_FAILED, NULL);
	}

done:
	pthread_mutex_unlock(&rdev->state_lock);
	return ret;
}
