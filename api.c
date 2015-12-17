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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <sys/uio.h>
#include <string.h>
#include <scsi/scsi.h>
#include <endian.h>
#include <errno.h>

#include "libtcmu_common.h"
#include "libtcmu_priv.h"

#define min(a,b)	       \
	({ __typeof__ (a) _a = (a);		\
		__typeof__ (b) _b = (b);	\
		_a < _b ? _a : _b; })

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

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
		errp(dev->cxt, "Could not open configfs to read attribute %s\n", name);
		return -EINVAL;
	}

	ret = read(fd, buf, sizeof(buf));
	close(fd);
	if (ret == -1) {
		errp(dev->cxt, "Could not read configfs to read attribute %s\n", name);
		return -EINVAL;
	}

	val = strtoul(buf, NULL, 0);
	if (val == ULONG_MAX) {
		errp(dev->cxt, "could not convert string to value\n");
		return -EINVAL;
	}

	return val;
}


/*
 * Return a string that contains the device's WWN, or NULL.
 *
 * Callers must free the result with free().
 */
static char *tcmu_get_wwn(struct tcmu_device *dev)
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
		errp(dev->cxt, "Could not open configfs to read unit serial\n");
		return NULL;
	}

	ret = read(fd, buf, sizeof(buf));
	close(fd);
	if (ret == -1) {
		errp(dev->cxt, "Could not read configfs to read unit serial\n");
		return NULL;
	}

	/* Kill the trailing '\n' */
	buf[ret-1] = '\0';

	/* Skip to the good stuff */
	ret = asprintf(&ret_buf, "%s", &buf[28]);
	if (ret == -1) {
		errp(dev->cxt, "could not convert string to value\n");
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
		errp(dev->cxt, "Could not open configfs to read dev info\n");
		return -EINVAL;
	}

	ret = read(fd, buf, sizeof(buf));
	close(fd);
	if (ret == -1) {
		errp(dev->cxt, "Could not read configfs to read dev info\n");
		return -EINVAL;
	}
	buf[sizeof(buf)-1] = '\0'; /* paranoid? Ensure null terminated */

	rover = strstr(buf, " Size: ");
	if (!rover) {
		errp(dev->cxt, "Could not find \" Size: \" in %s\n", path);
		return -EINVAL;
	}
	rover += 7; /* get to the value */

	size = strtoull(rover, NULL, 0);
	if (size == ULLONG_MAX) {
		errp(dev->cxt, "Could not get size\n");
		return -EINVAL;
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
		return -EINVAL;
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
		return -EINVAL;
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
		return -EINVAL;
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

/*
 * Consume an iovec. Count must not exceed the total iovec[] size.
 */
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

int tcmu_set_sense_data(uint8_t *sense_buf, uint8_t key, uint16_t asc_ascq, uint32_t *info)
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

	/*
	 * It's very common to set sense and return check condition.
	 * Returning this lets us do both in one go. Or, just ignore
	 * this and return scsi_status yourself.
	 */
	return SAM_STAT_CHECK_CONDITION;
}

/*
 * Copy data into an iovec, and consume the space in the iovec.
 *
 * Will truncate instead of overrunning the iovec.
 */
size_t tcmu_memcpy_into_iovec(
	struct iovec *iovec,
	size_t iov_cnt,
	void *src,
	size_t len)
{
	size_t copied = 0;

	while (len && iov_cnt) {
		size_t to_copy = min(iovec->iov_len, len);

		if (to_copy) {
			memcpy(iovec->iov_base, src + copied, to_copy);

			len -= to_copy;
			copied += to_copy;
			iovec->iov_base += to_copy;
			iovec->iov_len -= to_copy;
		}

		iovec++;
		iov_cnt--;
	}

	return copied;
}

/*
 * Copy data from an iovec, and consume the space in the iovec.
 */
size_t tcmu_memcpy_from_iovec(
	void *dest,
	size_t len,
	struct iovec *iovec,
	size_t iov_cnt)
{
	size_t copied = 0;

	while (len && iov_cnt) {
		size_t to_copy = min(iovec->iov_len, len);

		if (to_copy) {
			memcpy(dest + copied, iovec->iov_base, to_copy);

			len -= to_copy;
			copied += to_copy;
			iovec->iov_base += to_copy;
			iovec->iov_len -= to_copy;
		}

		iovec++;
		iov_cnt--;
	}

	return copied;
}

int tcmu_emulate_std_inquiry(
	uint8_t *cdb,
	struct iovec *iovec,
	size_t iov_cnt,
	uint8_t *sense)
{
	uint8_t buf[36];

	memset(buf, 0, sizeof(buf));

	buf[2] = 0x05; /* SPC-3 */
	buf[3] = 0x02; /* response data format */
	buf[7] = 0x02; /* CmdQue */

	memcpy(&buf[8], "LIO-ORG ", 8);
	memset(&buf[16], 0x20, 16);
	memcpy(&buf[16], "TCMU device", 11);
	memcpy(&buf[32], "0002", 4);
	buf[4] = 31; /* Set additional length to 31 */

	tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, sizeof(buf));

	return SAM_STAT_GOOD;
}

/* This func from CCAN str/hex/hex.c. Public Domain */
static bool char_to_hex(unsigned char *val, char c)
{
	if (c >= '0' && c <= '9') {
		*val = c - '0';
		return true;
	}
	if (c >= 'a' && c <= 'f') {
		*val = c - 'a' + 10;
		return true;
	}
	if (c >= 'A' && c <= 'F') {
		*val = c - 'A' + 10;
		return true;
	}
	return false;
}

int tcmu_emulate_evpd_inquiry(
	struct tcmu_device *dev,
	uint8_t *cdb,
	struct iovec *iovec,
	size_t iov_cnt,
	uint8_t *sense)
{
	switch (cdb[2]) {
	case 0x0: /* Supported VPD pages */
	{
		/* The absolute minimum. */
		char data[6];

		memset(data, 0, sizeof(data));

		/* 0x0 and 0x83 only */
		data[5] = 0x83;

		data[3] = 2;

		tcmu_memcpy_into_iovec(iovec, iov_cnt, data, sizeof(data));

		return SAM_STAT_GOOD;
	}
	break;
	case 0x83: /* Device identification */
	{
		char data[512];
		char *ptr;
		size_t used = 0;
		char *wwn;
		size_t len;
		uint16_t *tot_len = (uint16_t*) &data[2];

		memset(data, 0, sizeof(data));

		data[1] = 0x83;

		wwn = tcmu_get_wwn(dev);
		if (!wwn) {
			return tcmu_set_sense_data(sense, HARDWARE_ERROR,
						   ASC_INTERNAL_TARGET_FAILURE, NULL);
		}

		ptr = &data[4];

		/* 1/3: T10 Vendor id */
		ptr[0] = 2; /* code set: ASCII */
		ptr[1] = 1; /* identifier: T10 vendor id */
		memcpy(&ptr[4], "LIO-ORG ", 8);
		len = snprintf(&ptr[12], sizeof(data) - 16, "%s", wwn);

		ptr[3] = 8 + len + 1;
		used += ptr[3] + 4;
		ptr += used;

		/* 2/3: NAA binary */
		ptr[0] = 1; /* code set: binary */
		ptr[1] = 3; /* identifier: NAA */
		ptr[3] = 16; /* body length for naa registered extended format */

		/*
		 * Set type 6 and use OpenFabrics IEEE Company ID: 00 14 05
		 */
		ptr[4] = 0x60;
		ptr[5] = 0x01;
		ptr[6] = 0x40;
		ptr[7] = 0x50;

		/*
		 * Fill in the rest with a binary representation of WWN
		 *
		 * This implementation only uses a nibble out of every byte of
		 * WWN, but this is what the kernel does, and it's nice for our
		 * values to match.
		 */
		char *p = wwn;
		bool next = true;
		int i = 7;
		for ( ; *p && i < 20; p++) {
			uint8_t val;

			if (!char_to_hex(&val, *p))
				continue;

			if (next) {
				next = false;
				ptr[i++] |= val;
			} else {
				next = true;
				ptr[i] = val << 4;
			}
		}

		used += 20;
		ptr += 20;

		/* 3/3: Vendor specific */
		ptr[0] = 2; /* code set: ASCII */
		ptr[1] = 0; /* identifier: vendor-specific */

		len = snprintf(&ptr[4], sizeof(data) - used - 4, "%s", dev->cfgstring);
		ptr[3] = len + 1;

		used += ptr[3] + 4;

		/* Done with descriptor list */

		*tot_len = htobe16(used);

		tcmu_memcpy_into_iovec(iovec, iov_cnt, data, *tot_len + 4);

		free(wwn);
		wwn = NULL;

		return SAM_STAT_GOOD;
	}
	break;
	default:
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_CDB, NULL);
	}
}

/*
 * Emulate INQUIRY(0x12)
 */
int tcmu_emulate_inquiry(
	struct tcmu_device *dev,
	uint8_t *cdb,
	struct iovec *iovec,
	size_t iov_cnt,
	uint8_t *sense)
{
	if (!(cdb[1] & 0x01)) {
		if (!cdb[2])
			return tcmu_emulate_std_inquiry(cdb, iovec, iov_cnt, sense);
		else
			return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
						   ASC_INVALID_FIELD_IN_CDB, NULL);
	}
	else {
		return tcmu_emulate_evpd_inquiry(dev, cdb, iovec, iov_cnt, sense);
	}
}

int tcmu_emulate_test_unit_ready(
	uint8_t *cdb,
	struct iovec *iovec,
	size_t iov_cnt,
	uint8_t *sense)
{
	return SAM_STAT_GOOD;
}

int tcmu_emulate_read_capacity_16(
	uint64_t num_lbas,
	uint32_t block_size,
	uint8_t *cdb,
	struct iovec *iovec,
	size_t iov_cnt,
	uint8_t *sense)
{
	uint8_t buf[32];
	uint64_t val64;
	uint32_t val32;

	memset(buf, 0, sizeof(buf));

	val64 = htobe64(num_lbas);
	memcpy(&buf[0], &val64, 8);

	val32 = htobe32(block_size);
	memcpy(&buf[8], &val32, 8);

	/* all else is zero */

	tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, sizeof(buf));

	return SAM_STAT_GOOD;
}

static struct {
	uint8_t page;
	uint8_t subpage;
	int (*get)(uint8_t *buf, size_t buf_len);
} modesense_handlers[] = {
	/* TODO: implement caching mode page (8) */
};

/*
 * Handle MODE_SENSE(6) and MODE_SENSE(10).
 *
 * For TYPE_DISK only.
 */
int tcmu_emulate_mode_sense(
	uint8_t *cdb,
	struct iovec *iovec,
	size_t iov_cnt,
	uint8_t *sense)
{
	bool sense_ten = (cdb[0] == MODE_SENSE_10);
	uint8_t page_code = cdb[2] & 0x3f;
	size_t alloc_len = cdb[4];
	int i;
	int ret;
	size_t used_len;
	uint8_t buf[512];
	bool got_sense = false;

	memset(buf, 0, sizeof(buf));

	/* Mode parameter header. Mode data length filled in at the end. */
	used_len = sense_ten ? 8 : 4;

	/* Don't fill in device-specific parameter */
	/* Don't report block descriptors */

	if (page_code == 0x3f) {
		got_sense = true;
		for (i = 0; i < ARRAY_SIZE(modesense_handlers); i++) {
			ret = modesense_handlers[i].get(&buf[used_len], sizeof(buf) - used_len);
			if (ret <= 0)
				break;

			if  (sense_ten && (used_len + ret >= 255))
				break;

			if (used_len + ret > alloc_len)
				break;

			used_len += ret;
		}
	}
	else {
		for (i = 0; i < ARRAY_SIZE(modesense_handlers); i++) {
			if (page_code == modesense_handlers[i].page) {
				ret = modesense_handlers[i].get(&buf[used_len],
								sizeof(buf) - used_len);
				if (ret <= 0)
					break;

				if  (!sense_ten && (used_len + ret >= 255))
					break;

				if (used_len + ret > alloc_len)
					break;

				used_len += ret;
				got_sense = true;
				break;
			}
		}
	}

	if (!got_sense)
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
				    ASC_INVALID_FIELD_IN_CDB, NULL);

	if (sense_ten) {
		uint16_t *ptr = (uint16_t*) buf;
		*ptr = htobe16(used_len - 2);
	}
	else {
		buf[0] = used_len - 1;
	}

	tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, sizeof(buf));

	return SAM_STAT_GOOD;
}

/*
 * Handle MODE_SELECT(6) and MODE_SELECT(10).
 *
 * For TYPE_DISK only.
 */
int tcmu_emulate_mode_select(
	uint8_t *cdb,
	struct iovec *iovec,
	size_t iov_cnt,
	uint8_t *sense)
{
	bool select_ten = (cdb[0] == MODE_SELECT_10);
	uint8_t page_code = cdb[2] & 0x3f;
	size_t alloc_len = tcmu_get_xfer_length(cdb);
	int i;
	int ret = 0;
	size_t hdr_len = select_ten ? 8 : 4;
	uint8_t buf[512];
	uint8_t in_buf[512];
	bool got_sense = false;

	if (!alloc_len)
		return SAM_STAT_GOOD;

	if (tcmu_memcpy_from_iovec(in_buf, sizeof(in_buf), iovec, iov_cnt) >= sizeof(in_buf))
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_PARAMETER_LIST_LENGTH_ERROR, NULL);

	/* Abort if !pf or sp */
	if (!(cdb[1] & 0x10) || (cdb[1] & 0x01))
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_CDB, NULL);

	memset(buf, 0, sizeof(buf));
	for (i = 0; i < ARRAY_SIZE(modesense_handlers); i++) {
		if (page_code == modesense_handlers[i].page) {
			ret = modesense_handlers[i].get(&buf[hdr_len],
							sizeof(buf) - hdr_len);
			if (ret <= 0)
				return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
							   ASC_INVALID_FIELD_IN_CDB, NULL);

			if  (!select_ten && (hdr_len + ret >= 255))
				return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
							   ASC_INVALID_FIELD_IN_CDB, NULL);

			got_sense = true;
			break;
		}
	}

	if (!got_sense)
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_CDB, NULL);

	if (alloc_len < (hdr_len + ret))
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_PARAMETER_LIST_LENGTH_ERROR, NULL);

	/* Verify what was selected is identical to what sense returns, since we
	   don't support actually setting anything. */
	if (memcmp(&buf[hdr_len], &in_buf[hdr_len], ret))
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_PARAMETER_LIST, NULL);

	return SAM_STAT_GOOD;
}
