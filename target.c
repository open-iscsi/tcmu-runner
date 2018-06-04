/*
 * Copyright (c) 2017 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
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
#include <pthread.h>

#include "ccan/list/list.h"

#include "libtcmu_log.h"
#include "libtcmu_common.h"
#include "tcmur_device.h"
#include "target.h"
#include "alua.h"

static struct list_head tpg_recovery_list = LIST_HEAD_INIT(tpg_recovery_list);
/*
 * Locking ordering:
 * rdev->state_lock
 * tpg_recovery_lock
 */
static pthread_mutex_t tpg_recovery_lock = PTHREAD_MUTEX_INITIALIZER;

struct tgt_port_grp {
	char *wwn;
	char *fabric;
	uint16_t tpgt;

	/* entry on tpg_recovery_list */
	struct list_node recovery_entry;
	/* list of devs to recover */
	struct list_head devs;
	pthread_t recovery_thread;
};

static int tcmu_set_tpg_int(struct tgt_port_grp *tpg, const char *name,
			     int val)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), CFGFS_ROOT"/%s/%s/tpgt_%hu/%s",
		 tpg->fabric, tpg->wwn, tpg->tpgt, name);
	return tcmu_set_cfgfs_ul(path, val);
}

static int tcmu_get_tpg_int(struct tgt_port *port, const char *name)
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
		tcmu_err("Invalid ALUA member %s:%s\n", member_str,
			 strerror(errno));
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

	ret = tcmu_get_tpg_int(port, "enable");
	if (ret < 0)
		goto free_port;
	port->enabled = ret;

	return port;

free_port:
	tcmu_free_tgt_port(port);
	return NULL;
}

static bool port_is_on_tgt_port_grp(struct tgt_port *port,
				   struct tgt_port_grp *tpg)
{
	if (!strcmp(port->fabric, tpg->fabric) &&
	    !strcmp(port->wwn, tpg->wwn) && port->tpgt == tpg->tpgt)
		return true;
	return false;
}

static struct tgt_port_grp *port_is_on_recovery_list(struct tgt_port *port)
{
	struct tgt_port_grp *tpg;

	list_for_each(&tpg_recovery_list, tpg, recovery_entry) {
		if (port_is_on_tgt_port_grp(port, tpg))
			return tpg;
	}
	return NULL;
}

static void free_tgt_port_grp(struct tgt_port_grp *tpg)
{
	free(tpg->fabric);
	free(tpg->wwn);
	free(tpg);
}

static struct tgt_port_grp *setup_tgt_port_grp(struct tgt_port *port)
{
	struct tgt_port_grp *tpg;

	tpg = calloc(1, sizeof(*tpg));
	if (!tpg)
		goto fail;

	list_head_init(&tpg->devs);
	list_node_init(&tpg->recovery_entry);
	tpg->tpgt = port->tpgt;

	tpg->wwn = strdup(port->wwn);
	if (!tpg->wwn)
		goto free_tpg;

	tpg->fabric = strdup(port->fabric);
	if (!tpg->fabric)
		goto free_wwn;

	return tpg;

free_wwn:
	free(tpg->wwn);
free_tpg:
	free(tpg);
fail:
	return NULL;
}

/*
 * Disable the target tpg to avoid flip flopping between paths
 * (transport path is ok so multipath layer switches to it, but
 * then sends IO only for it to fail due to the handler not
 * being able to reach its backend).
 */
static void *tgt_port_grp_recovery_thread_fn(void *arg)
{
	struct tgt_port_grp *tpg = arg;
	struct tcmur_device *rdev, *tmp_rdev;
	bool enable_tpg = false;
	int ret;

	tcmu_dbg("Disabling %s/%s/tpgt_%hu.\n", tpg->fabric, tpg->wwn,
		  tpg->tpgt);
	/*
	 * This will return when all running commands have completed at
	 * the target layer. Handlers must call tcmu_notify_lock_lost
	 * before completing the failed command, so the device will be on
	 * the list reopen list when setting enable=0 returns..
	 */
	ret = tcmu_set_tpg_int(tpg, "enable", 0);

	pthread_mutex_lock(&tpg_recovery_lock);
	list_del(&tpg->recovery_entry);
	pthread_mutex_unlock(&tpg_recovery_lock);

	if (ret < 0) {
		tcmu_err("Could not disable %s/%s/tpgt_%hu (err %d).\n",
			 ret, tpg->fabric, tpg->wwn, tpg->tpgt);
		/* just recover the devs and leave the tpg in curr state */
		goto done;
	}

	enable_tpg = true;
	tcmu_info("Disabled %s/%s/tpgt_%hu.\n", tpg->fabric, tpg->wwn,
		  tpg->tpgt);

done:
	/*
	 * TODO - the transport is stopped, so we should use the
	 * cmdproc thread to reopen all these in parallel.
	 */
	list_for_each_safe(&tpg->devs, rdev, tmp_rdev, recovery_entry) {
		ret = __tcmu_reopen_dev(rdev->dev, false, -1);
		if (ret) {
			tcmu_dev_err(rdev->dev, "Could not reinitialize device. (err %d).\n",
				     ret);
			if (!(rdev->flags & TCMUR_DEV_FLAG_STOPPING))
				/* assume fatal error so do not enable tpg */
				enable_tpg = false;
		}
	}

	if (enable_tpg) {
		ret = tcmu_set_tpg_int(tpg, "enable", 1);
		if (ret) {
			tcmu_err("Could not enable %s/%s/tpgt_%hu (err %d).\n",
				 ret, tpg->fabric, tpg->wwn, tpg->tpgt);
		} else {
			tcmu_info("Enabled %s/%s/tpgt_%hu.\n", tpg->fabric, tpg->wwn,
				  tpg->tpgt);
		}
	}

	free_tgt_port_grp(tpg);
        return NULL;
}

int tcmu_add_dev_to_recovery_list(struct tcmu_device *dev)
{
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	struct list_head alua_list;
	struct alua_grp *group;
	struct tgt_port_grp *tpg;
	struct tgt_port *port, *enabled_port = NULL;
	int ret;

	pthread_mutex_lock(&tpg_recovery_lock);

	list_head_init(&alua_list);
	ret = tcmu_get_alua_grps(dev, &alua_list);
	if (ret) {
		/* User is deleting device so fast fail */
		tcmu_dev_warn(dev, "Could not find any tpgs.\n");
		goto done;
	}

	/*
	 * This assumes a tcmu_dev is only exported though one local
	 * enabled tpg. The kernel members file only returns
	 * the one and runner is not passed info about which
	 * tpg/port IO was received on.
	 */
	list_for_each(&alua_list, group, entry) {
		list_for_each(&group->tgt_ports, port, entry) {
			if (port->enabled)
				enabled_port = port;
			/*
			 * If another device already kicked off recovery
			 * the enabled bit might not be set.
			 */
			tpg = port_is_on_recovery_list(port);
			if (tpg)
				goto add_to_list;
		}
	}

	if (!enabled_port) {
		ret = -EIO;
		/* User disabled port from under us? */
		tcmu_dev_err(dev, "Could not find enabled port.\n");
		goto done;
	}

	tpg = setup_tgt_port_grp(enabled_port);
	if (!tpg) {
		ret = -ENOMEM;
		goto done;
	}
	ret = pthread_create(&tpg->recovery_thread, NULL,
			     tgt_port_grp_recovery_thread_fn, tpg);
	if (ret) {
		tcmu_dev_err(dev, "Could not start recovery thread. Err %d\n",
			     ret);
		free_tgt_port_grp(tpg);
		goto done;
	}
	list_add(&tpg_recovery_list, &tpg->recovery_entry);

add_to_list:
	list_add(&tpg->devs, &rdev->recovery_entry);
done:
	tcmu_release_alua_grps(&alua_list);
	pthread_mutex_unlock(&tpg_recovery_lock);
	return ret;
}
