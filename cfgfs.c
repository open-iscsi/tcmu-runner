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
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include "libtcmu_log.h"
#include "libtcmu_common.h"
#include "libtcmu_priv.h"

int tcmu_get_attribute(struct tcmu_device *dev, const char *name)
{
	int fd;
	char path[256];
	char buf[16];
	ssize_t ret;
	unsigned int val;

	snprintf(path, sizeof(path), "/sys/kernel/config/target/core/%s/%s/attrib/%s",
		 dev->tcm_hba_name, dev->tcm_dev_name, name);

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		tcmu_err("Could not open configfs to read attribute %s\n", name);
		return -EINVAL;
	}

	ret = read(fd, buf, sizeof(buf));
	close(fd);
	if (ret == -1) {
		tcmu_err("Could not read configfs to read attribute %s\n", name);
		return -EINVAL;
	}

	val = strtoul(buf, NULL, 0);
	if (val == ULONG_MAX) {
		tcmu_err("could not convert string to value\n");
		return -EINVAL;
	}

	return val;
}


/*
 * Return a string that contains the device's WWN, or NULL.
 *
 * Callers must free the result with free().
 */
char *tcmu_get_wwn(struct tcmu_device *dev)
{
	int fd;
	char path[256];
	char buf[256];
	char *ret_buf;
	int ret;

	snprintf(path, sizeof(path),
		 "/sys/kernel/config/target/core/%s/%s/wwn/vpd_unit_serial",
		 dev->tcm_hba_name, dev->tcm_dev_name);

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		tcmu_err("Could not open configfs to read unit serial\n");
		return NULL;
	}

	ret = read(fd, buf, sizeof(buf));
	close(fd);
	if (ret == -1) {
		tcmu_err("Could not read configfs to read unit serial\n");
		return NULL;
	}

	/* Kill the trailing '\n' */
	buf[ret-1] = '\0';

	/* Skip to the good stuff */
	ret = asprintf(&ret_buf, "%s", &buf[28]);
	if (ret == -1) {
		tcmu_err("could not convert string to value\n");
		return NULL;
	}

	return ret_buf;
}

long long tcmu_get_device_size(struct tcmu_device *dev)
{
	int fd;
	char path[256];
	char buf[4096];
	ssize_t ret;
	char *rover;
	unsigned long long size;

	snprintf(path, sizeof(path), "/sys/kernel/config/target/core/%s/%s/info",
		 dev->tcm_hba_name, dev->tcm_dev_name);

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		tcmu_err("Could not open configfs to read dev info\n");
		return -EINVAL;
	}

	ret = read(fd, buf, sizeof(buf));
	close(fd);
	if (ret == -1) {
		tcmu_err("Could not read configfs to read dev info\n");
		return -EINVAL;
	}
	buf[sizeof(buf)-1] = '\0'; /* paranoid? Ensure null terminated */

	rover = strstr(buf, " Size: ");
	if (!rover) {
		tcmu_err("Could not find \" Size: \" in %s\n", path);
		return -EINVAL;
	}
	rover += 7; /* get to the value */

	size = strtoull(rover, NULL, 0);
	if (size == ULLONG_MAX) {
		tcmu_err("Could not get size\n");
		return -EINVAL;
	}

	return size;
}
