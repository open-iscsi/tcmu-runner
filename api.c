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

#define min(a,b)	       \
	({ __typeof__ (a) _a = (a);		\
		__typeof__ (b) _b = (b);	\
		_a < _b ? _a : _b; })

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

static inline int get_cdb_length(uint8_t *cdb)
{
	uint8_t opcode = cdb[0];

	// See spc-4 4.2.5.1 operation code
	//
	if (opcode <= 0x1f)
		return 6;
	else if (opcode <= 0x5f)
		return 10;
	else if (opcode >= 0x80 && opcode <= 0x9f)
		return 16;
	else if (opcode >= 0xa0 && opcode <= 0xbf)
		return 12;
	else
		return -1;
}

uint64_t tcmu_get_lba(uint8_t *cdb)
{
	uint8_t val6;

	switch (get_cdb_length(cdb)) {
	case 6:
		val6 = be16toh(*((uint16_t *)&cdb[2]));
		return val6 ? val6 : 256;
	case 10:
		return be32toh(*((u_int32_t *)&cdb[2]));
	case 12:
		return be32toh(*((u_int32_t *)&cdb[2]));
	case 16:
		return be64toh(*((u_int64_t *)&cdb[2]));
	default:
		return -1;
	}
}

uint32_t tcmu_get_xfer_length(uint8_t *cdb)
{
	switch (get_cdb_length(cdb)) {
	case 6:
		return cdb[4];
	case 10:
		return be16toh(*((uint16_t *)&cdb[7]));
	case 12:
		return be32toh(*((u_int32_t *)&cdb[6]));
	case 16:
		return be32toh(*((u_int32_t *)&cdb[10]));
	default:
		return -1;
	}
}

/*
 * Returns location of first mismatch between bytes in mem and the iovec.
 * If they are the same, return -1.
 */
off_t tcmu_compare_with_iovec(void *mem, struct iovec *iovec, size_t size)
{
	off_t mem_off;
	int ret;

	mem_off = 0;
	while (size) {
		size_t part = min(size, iovec->iov_len);

		ret = memcmp(mem + mem_off, iovec->iov_base, part);
		if (ret) {
			size_t pos;
			char *spos = mem + mem_off;
			char *dpos = iovec->iov_base;

			/*
			 * Data differed, this is assumed to be 'rare'
			 * so use a much more expensive byte-by-byte
			 * comparison to find out at which offset the
			 * data differs.
			 */
			for (pos = 0; pos < part && *spos++ == *dpos++;
			     pos++)
				;

			return pos + mem_off;
		}

		size -= part;
		mem_off += part;
		iovec++;
	}

	return -1;
}

void tcmu_seek_in_iovec(struct iovec *iovec, size_t count)
{
	while (count) {
		if (count >= iovec->iov_len) {
			count -= iovec->iov_len;
			iovec->iov_len = 0;
			iovec++;
		} else {
			iovec->iov_base += count;
			iovec->iov_len -= count;
			count = 0;
		}
	}
}

size_t tcmu_iovec_length(struct iovec *iovec, size_t iov_cnt)
{
	size_t length = 0;

	while (iov_cnt) {
		length += iovec->iov_len;
		iovec++;
		iov_cnt--;
	}

	return length;
}

void tcmu_set_sense_data(uint8_t *sense_buf, uint8_t key, uint16_t asc_ascq, uint32_t *info)
{
	sense_buf[0] = 0x70;	/* fixed, current */
	sense_buf[2] = key;
	sense_buf[7] = 0xa;
	sense_buf[12] = (asc_ascq >> 8) & 0xff;
	sense_buf[13] = asc_ascq & 0xff;
	if (info) {
		uint32_t val32 = htobe32(*info);

		memcpy(&sense_buf[3], &val32, 4);
		sense_buf[0] |= 0x80;
	}
}
