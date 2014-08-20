/*
 * Copyright 2014, Red Hat, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <sys/uio.h>
#include <string.h>

#include "tcmu-runner.h"

int tcmu_get_attribute(struct tcmu_device *dev, char *name)
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
		printf("Could not open configfs to read attribute %s\n", name);
		return -1;
	}

	ret = read(fd, buf, sizeof(buf));
	close(fd);
	if (ret == -1) {
		printf("Could not read configfs to read attribute %s\n", name);
		return -1;
	}

	val = strtoul(buf, NULL, 0);
	if (val == ULONG_MAX) {
		printf("could not convert string to value\n");
		return -1;
	}

	return val;
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
		printf("Could not open configfs to read dev info\n");
		return -1;
	}

	ret = read(fd, buf, sizeof(buf));
	close(fd);
	if (ret == -1) {
		printf("Could not read configfs to read dev info\n");
		return -1;
	}
	buf[sizeof(buf)-1] = '\0'; /* paranoid? Ensure null terminated */

	rover = strstr(buf, " Size: ");
	if (!rover) {
		printf("Could not find \" Size: \" in %s\n", path);
		return -1;
	}
	rover += 7; /* get to the value */

	size = strtoull(rover, NULL, 0);
	if (size == ULLONG_MAX) {
		printf("Could not get map length\n");
		return -1;
	}

	return size;
}

