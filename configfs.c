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
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include "libtcmu_log.h"
#include "libtcmu_common.h"
#include "libtcmu_priv.h"

#define CFGFS_BUF_SIZE 4096

int tcmu_cfgfs_get_int(const char *path)
{
	int fd;
	char buf[16];
	ssize_t ret;
	unsigned long val;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
                if (errno == ENOENT) {
			tcmu_err("Kernel does not support configfs file %s.\n",
				 path);
		} else {
			tcmu_err("Could not open configfs file %s: %s\n",
				 path, strerror(errno));
		}
		return -errno;
	}

	ret = read(fd, buf, sizeof(buf));
	close(fd);
	if (ret == -1) {
		tcmu_err("Could not read configfs to read attribute %s: %s\n",
			 path, strerror(errno));
		return -errno;
	}

	val = strtoul(buf, NULL, 0);
	if (val > INT_MAX ) {
		tcmu_err("could not convert string %s to value\n", buf);
		return -EINVAL;
	}

	return val;
}

int tcmu_cfgfs_dev_get_attr_int(struct tcmu_device *dev, const char *name)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), CFGFS_CORE"/%s/%s/attrib/%s",
		 dev->tcm_hba_name, dev->tcm_dev_name, name);
	return tcmu_cfgfs_get_int(path);
}

uint64_t tcmu_cfgfs_dev_get_info_u64(struct tcmu_device *dev, const char *name,
				     int *fn_ret)
{
	int fd;
	char path[PATH_MAX];
	char buf[CFGFS_BUF_SIZE];
	ssize_t ret;
	char *rover;
	char *search_pattern;
	uint64_t val;

	*fn_ret = 0;
	snprintf(path, sizeof(path), CFGFS_CORE"/%s/%s/info",
		 dev->tcm_hba_name, dev->tcm_dev_name);

	fd = open(path, O_RDONLY);
	if (fd == -1) {
                if (errno == ENOENT) {
			tcmu_err("Kernel does not support device info file %s.\n",
				 path);
		} else {
			tcmu_err("Could not open device info file %s: %s\n",
				 path, strerror(errno));
		}
		*fn_ret = -errno;
		return 0;
	}

	ret = read(fd, buf, sizeof(buf));
	close(fd);
	if (ret == -1) {
		tcmu_err("Could not read configfs to read dev info: %s\n",
			 strerror(errno));
		*fn_ret = -EINVAL;
		return 0;
	}
	buf[sizeof(buf)-1] = '\0'; /* paranoid? Ensure null terminated */

	if (asprintf(&search_pattern, " %s: ", name) < 0) {
		tcmu_err("Could not create search string.\n");
		*fn_ret = -ENOMEM;
		return 0;
	}

	rover = strstr(buf, search_pattern);
	free(search_pattern);
	if (!rover) {
		tcmu_err("Could not find \" %s: \" in %s: %s\n", name, path,
			 strerror(errno));
		*fn_ret = -EINVAL;
		return 0;
	}
	rover += strlen(name) + 3; /* name plus ':' and spaces before/after */

	val = strtoull(rover, NULL, 0);
	if (val == ULLONG_MAX) {
		tcmu_err("Could not get %s: %s\n", name, strerror(errno));
		*fn_ret = -EINVAL;
		return 0;
	}

	return val;
}

int tcmu_cfgfs_dev_set_ctrl_u64(struct tcmu_device *dev, const char *key,
				uint64_t val)
{
	char path[PATH_MAX];
	char buf[CFGFS_BUF_SIZE];

	snprintf(path, sizeof(path), CFGFS_CORE"/%s/%s/control",
		 dev->tcm_hba_name, dev->tcm_dev_name);
	snprintf(buf, sizeof(buf), "%s=%"PRIu64"", key, val);

	return tcmu_cfgfs_set_str(path, buf, strlen(buf) + 1);
}

static bool tcmu_cfgfs_mod_param_is_supported(const char *name)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), CFGFS_MOD_PARAM"/%s", name);

	if (access(path, F_OK) == -1)
		return false;

	return true;
}

int tcmu_cfgfs_nl_block(void)
{
	char path[PATH_MAX];
	int rc;

	if (!tcmu_cfgfs_mod_param_is_supported("block_netlink")) {
		tcmu_warn("Kernel does not support blocking netlink.\n");
		return -EOPNOTSUPP;
	}

	snprintf(path, sizeof(path), CFGFS_MOD_PARAM"/block_netlink");

	tcmu_dbg("blocking netlink\n");
	rc = tcmu_cfgfs_set_u32(path, 1);
	if (rc) {
		tcmu_warn("Could not block netlink %d.\n", rc);
		return rc;
	}
	tcmu_dbg("block netlink done\n");
	return 0;
}

int tcmu_cfgfs_nl_unblock(void)
{
	char path[PATH_MAX];
	int rc;

	if (!tcmu_cfgfs_mod_param_is_supported("block_netlink")) {
		tcmu_warn("Kernel does not support unblocking netlink.\n");
		return -EOPNOTSUPP;
	}

	snprintf(path, sizeof(path), CFGFS_MOD_PARAM"/block_netlink");

	tcmu_dbg("unblocking netlink\n");
	rc = tcmu_cfgfs_set_u32(path, 0);
	if (rc) {
		tcmu_warn("Could not unblock netlink %d.\n", rc);
		return rc;
	}
	tcmu_dbg("unblock netlink done\n");
	return 0;
}

/*
 * Usually this will be used when the daemon is starting just before
 * it could receive and handle the kernel netlink requests.
 *
 * It will reset all the pending netlink msg, of which the reply maybe
 * lost for some reason, such as the userspace dameon crashed just before
 * it could reply to it, in kernel space.
 *
 * This must be called after blocking the netlink, and after this unblocking
 * is a must.
 */
int tcmu_cfgfs_nl_reset(void)
{
	char path[PATH_MAX];
	int rc;

	if (!tcmu_cfgfs_mod_param_is_supported("reset_netlink")) {
		tcmu_warn("Kernel does not support reseting netlink.\n");
		return -EOPNOTSUPP;
	}

	snprintf(path, sizeof(path), CFGFS_MOD_PARAM"/reset_netlink");

	tcmu_dbg("reseting netlink\n");
	rc = tcmu_cfgfs_set_u32(path, 1);
	if (rc) {
		tcmu_warn("Could not reset netlink: %d\n", rc);
		return rc;
	}

	tcmu_dbg("reset netlink done\n");
	return 0;
}

/*
 * Return a string that contains the device's WWN, or NULL.
 *
 * Callers must free the result with free().
 */
char *tcmu_cfgfs_dev_get_wwn(struct tcmu_device *dev)
{
	int fd;
	char path[PATH_MAX];
	char buf[CFGFS_BUF_SIZE];
	char *ret_buf;
	int ret;

	snprintf(path, sizeof(path),
		 CFGFS_CORE"/%s/%s/wwn/vpd_unit_serial",
		 dev->tcm_hba_name, dev->tcm_dev_name);

	fd = open(path, O_RDONLY);
	if (fd == -1) {
                if (errno == ENOENT) {
			tcmu_err("Kernel does not support unit serial file %s.\n",
				 path);
		} else {
			tcmu_err("Could not open unit serial file %s: %s\n",
				 path, strerror(errno));
		}
		return NULL;
	}

	ret = read(fd, buf, sizeof(buf));
	close(fd);
	if (ret == -1) {
		tcmu_err("Could not read configfs to read unit serial: %s\n",
			 strerror(errno));
		return NULL;
	}

	/* Kill the trailing '\n' */
	buf[ret-1] = '\0';

	/* Skip to the good stuff */
	ret = asprintf(&ret_buf, "%s", &buf[28]);
	if (ret == -1) {
		tcmu_err("could not convert string to value: %s\n",
			 strerror(errno));
		return NULL;
	}

	return ret_buf;
}

char *tcmu_cfgfs_get_str(const char *path)
{
	int fd, n;
	char buf[CFGFS_BUF_SIZE];
	ssize_t ret;
	char *val;

	memset(buf, 0, sizeof(buf));
	fd = open(path, O_RDONLY);
	if (fd == -1) {
                if (errno == ENOENT) {
			tcmu_err("Kernel does not support configfs file %s.\n",
				 path);
		} else {
			tcmu_err("Could not open configfs file %s: %s\n",
				 path, strerror(errno));
		}
		return NULL;
	}

	ret = read(fd, buf, sizeof(buf));
	close(fd);
	if (ret == -1) {
		tcmu_err("Could not read configfs to read attribute %s: %s\n",
		         path, strerror(errno));
		return NULL;
	}

	if (ret == 0)
		return NULL;

	/*
	 * Some files like members will terminate each member/line with a null
	 * char. Except for the last one, replace it with '\n' so parsers will
	 * just see an empty member.
	 */
	if (ret != strlen(buf)) {
		do {
			n = strlen(buf);
			buf[n] = '\n';
		} while (n < ret);
	}

	/*
	 * Some files like members ends with a null char, but other files like
	 * the alua ones end with a newline.
	 */
	if (buf[ret - 1] == '\n')
		buf[ret - 1] = '\0';

	if (buf[ret - 1] != '\0') {
		if (ret >= CFGFS_BUF_SIZE) {
			tcmu_err("Invalid cfgfs file %s: not enough space for ending null char.\n",
				 path);
			return NULL;
		}
		/*
		 * In case the file does "return sprintf()" with no ending
		 * newline add the ending null so we will not crash below.
		 */
		buf[ret] = '\0';
	}

	val = strdup(buf);
	if (!val) {
		tcmu_err("could not copy buffer %s : %s\n",
			 buf, strerror(errno));
		return NULL;
	}

	return val;
}

int tcmu_cfgfs_set_str(const char *path, const char *val, int val_len)
{
	int fd;
	ssize_t ret;

	fd = open(path, O_WRONLY);
	if (fd == -1) {
                if (errno == ENOENT) {
			tcmu_err("Kernel does not support configfs file %s.\n",
				 path);
		} else {
			tcmu_err("Could not open configfs file %s: %s\n",
				 path, strerror(errno));
		}
		return -errno;
	}

	ret = write(fd, val, val_len);
	close(fd);
	if (ret == -1) {
		tcmu_err("Could not write configfs to write attribute %s: %s\n",
			 path, strerror(errno));
		return -errno;
	}

	return 0;
}

int tcmu_cfgfs_set_u32(const char *path, uint32_t val)
{
	char buf[20];

	sprintf(buf, "%"PRIu32"", val);
	return tcmu_cfgfs_set_str(path, buf, strlen(buf) + 1);
}

int tcmu_cfgfs_dev_exec_action(struct tcmu_device *dev, const char *name,
			       uint32_t val)
{
	char path[PATH_MAX];
	int ret;

	snprintf(path, sizeof(path), CFGFS_CORE"/%s/%s/action/%s",
		 dev->tcm_hba_name, dev->tcm_dev_name, name);
	tcmu_dev_dbg(dev, "executing action %s\n", name);
	ret = tcmu_cfgfs_set_u32(path, val);
	tcmu_dev_dbg(dev, "action %s done\n", name);
	return ret;
}
