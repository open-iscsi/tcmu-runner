/*
 * Copyright 2016, IBM Corp.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */

/*
 * Block driver for the File Optical Format.
 *
 * Copyright (C) 2016, IBM Corp.
 * Authors: Michael Cyr <mikecyr@linux.vnet.ibm.com>
 * Authors: Bryant G. Ly <bryantly@linux.vnet.ibm.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <endian.h>
#include <scsi/scsi.h>
#include <linux/cdrom.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>

#include "be_byteshift.h"
#include "libtcmu.h"
#include "libtcmu_log.h"
#include "scsi_defs.h"

struct fbo_state {
	int fd;
	uint64_t num_lbas;
	uint32_t block_size;
	uint32_t cur_lba;

#define FBO_READ_ONLY		0x01
#define FBO_PREV_EJECT		0x02
#define FBO_DEV_IO		0x04
#define FBO_BUSY_EVENT		0x08
#define FBO_FORMATTING		0x10
#define FBO_FORMAT_IMMED	0x20
	uint32_t flags;
	uint32_t format_progress;
	uint8_t event_op_ch_code;
	uint8_t async_cache_count;
	pthread_mutex_t state_mtx;
	int curr_handler;
};

static int fbo_handle_cmd(struct tcmu_device *dev, struct tcmulib_cmd *cmd);

static void fbo_report_op_change(struct tcmu_device *dev, uint8_t code)
{
	struct fbo_state *state = tcmu_get_dev_private(dev);

	pthread_mutex_lock(&state->state_mtx);
	if (code > state->event_op_ch_code)
		state->event_op_ch_code = code;
	pthread_mutex_unlock(&state->state_mtx);
}

/* Note: this is called per lun, not per mapping */
static int fbo_open(struct tcmu_device *dev, bool reopen)
{
	struct fbo_state *state;
	int64_t size;
	char *options;
	char *path;

	state = calloc(1, sizeof(*state));
	if (!state)
		return -ENOMEM;

	tcmu_set_dev_private(dev, state);

#if 0
	/* TBD: If we can figure out how the hw_block_size attribute
	 * gets set (and change it), we could use that in the future.
	 */
	state->block_size = tcmu_get_attribute(dev, "hw_block_size");
	if (state->block_size == -1) {
		tcmu_err("Could not get device block size\n");
		goto err;
	}
	tcmu_set_dev_block_size(dev, state->block_size);
#else
	/* MM logical units use a block size of 2048 */
	state->block_size = 2048;
	tcmu_set_dev_block_size(dev, state->block_size);
#endif

	size = tcmu_get_dev_size(dev);
	if (size == -1) {
		tcmu_err("Could not get device size\n");
		goto err;
	}

	tcmu_set_dev_num_lbas(dev, size / state->block_size);
	state->num_lbas = size / state->block_size;

	tcmu_dbg("open: cfgstring %s\n", tcmu_get_dev_cfgstring(dev));
	options = strchr(tcmu_get_dev_cfgstring(dev), '/');
	if (!options) {
		tcmu_err("invalid cfgstring\n");
		goto err;
	}
	options += 1; /* get past '/' */
	while (options[0] != '/') {
		if (!strncasecmp(options, "ro/", 3))
			state->flags |= FBO_READ_ONLY;
		else
			tcmu_err("Ignoring unknown option %s\n", options);

		options = strchr(options, '/');
		if (!options) {
			tcmu_err("no path found in cfgstring");
			goto err;
		}
		options += 1;
	}

	path = options;
	if (!path) {
		tcmu_err("no path found in cfgstring\n");
		goto err;
	}

	if (access(path, F_OK) == -1)
		state->fd = open(path, O_CREAT | O_RDWR | O_EXCL,
				 S_IRUSR | S_IWUSR);
	else if (state->flags & FBO_READ_ONLY)
		state->fd = open(path, O_RDONLY, 0);
	else
		state->fd = open(path, O_RDWR, 0);
	if (state->fd == -1) {
		tcmu_err("could not open %s: %m\n", path);
		goto err;
	}
	tcmu_dbg("FBO Open: fd %d\n", state->fd);

	pthread_mutex_init(&state->state_mtx, NULL);

	/* Record that we've changed our Operational state */
	fbo_report_op_change(dev, 0x02);

	return 0;

err:
	free(state);
	return -EINVAL;
}

static void fbo_close(struct tcmu_device *dev)
{
	struct fbo_state *state = tcmu_get_dev_private(dev);

	close(state->fd);
	free(state);
}

static int fbo_emulate_inquiry(uint8_t *cdb, struct iovec *iovec, size_t iov_cnt,
			       uint8_t *sense)
{
	uint8_t	buf[36];

	if ((cdb[1] & 0x01) || cdb[2])
		return TCMU_STS_INVALID_CDB;

	memset(buf, 0, sizeof(buf));

	buf[0] = 0x05;	/* CD/DVD device */
	buf[1] = 0x80;	/* Removable Medium Bit */
	buf[2] = 0x05;	/* SPC-3 */
	buf[3] = 0x02;	/* response data format */
	buf[7] = 0x02;	/* CmdQue */

	memcpy(&buf[8], "LIO-ORG ", 8);
	memset(&buf[16], 0x20, 16);
	memcpy(&buf[16], "VOPTA", 5);
	memcpy(&buf[32], "0001", 4);

	buf[4] = 31;	/* additional length */

	/* TBD: Resid data? */
	tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, sizeof(buf));

	return TCMU_STS_OK;
}

static int fbo_emulate_request_sense(struct tcmu_device *dev, uint8_t *cdb,
				     struct iovec *iovec, size_t iov_cnt,
				     uint8_t *sense)
{
	struct fbo_state *state = tcmu_get_dev_private(dev);
	uint8_t buf[18];

	if (cdb[1] & 0x01)
		return TCMU_STS_INVALID_CDB;

	/* Note that upon successful completion, Request Sense returns the
	 * sense data in the data buffer, not as sense data.
	 */
	memset(buf, 0, sizeof(buf));

	buf[0] = 0x70;
	buf[7] = 0xa;
	if (state->flags & FBO_FORMATTING) {
		buf[2] = NOT_READY;
		buf[12] = 0x04;		// Not Ready
		buf[13] = 0x04;		// Format in progress
		buf[15] = 0x80;
		put_unaligned_be16(state->format_progress, &buf[16]);
	}
	else {
		buf[2] = NO_SENSE;
	}

	tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, sizeof(buf));

	return TCMU_STS_OK;
}

static int fbo_handle_rwerp_page(uint8_t *buf, size_t buf_len,
				 uint8_t page_control)
{
	if (buf_len < 12)
		return -1;

	buf[0] = GPMODE_R_W_ERROR_PAGE;
	buf[1] = 10;
	if (page_control != 1) {
		buf[3] = 5;	/* Read Retry Count */
		buf[8] = 5;	/* Write Retry Count */
	}

	return 12;
}

static int fbo_handle_cache_page(uint8_t *buf, size_t buf_len,
				 uint8_t page_control)
{
	if (buf_len < 12)
		return -1;

	buf[0] = GPMODE_WCACHING_PAGE;
	buf[1] = 10;
	if (page_control != 1) {
		buf[2] = 4;	/* WCE=1 */
	}

	return 12;
}

static int fbo_handle_timeout_page(uint8_t *buf, size_t buf_len,
				   uint8_t page_control)
{
	if (buf_len < 10)
		return -1;

	buf[0] = GPMODE_TO_PROTECT_PAGE;
	buf[1] = 8;
	if (page_control != 1) {
		buf[6] = 0xff;
		buf[7] = 0xff;
		buf[8] = 0xff;
		buf[9] = 0xff;
	}

	return 10;
}

static struct {
	uint8_t page;
	int (*get)(uint8_t *buf, size_t buf_len, uint8_t page_control);
} fbo_modesense_handlers[] = {
	{ GPMODE_R_W_ERROR_PAGE, fbo_handle_rwerp_page },
	{ GPMODE_WCACHING_PAGE, fbo_handle_cache_page },
	{ GPMODE_TO_PROTECT_PAGE, fbo_handle_timeout_page },
};

static int fbo_emulate_mode_sense(uint8_t *cdb, struct iovec *iovec,
				  size_t iov_cnt, uint8_t *sense)
{
	bool sense_ten = (cdb[0] == MODE_SENSE_10);
	uint8_t page_control = (cdb[2] >> 6) & 0x3;
	uint8_t page_code = cdb[2] & 0x3F;
	bool return_pages = true;
	size_t alloc_len = tcmu_get_xfer_length(cdb);
	int i;
	int ret;
	int used_len;
	uint8_t buf[512];
	bool got_sense = false;

	/* We don't support saved pages */
	if (page_control == 3)
		return TCMU_STS_NOTSUPP_SAVE_PARAMS;

	memset(buf, 0, sizeof(buf));

	if ((page_code == 0) && (page_control == 0))
		return_pages = false;

	/* Mode parameter header length */
	used_len = sense_ten ? 8 : 4;

	if (return_pages) {
		if (page_code == 0x3f) {
			got_sense = true;
			for (i = 0; i < ARRAY_SIZE(fbo_modesense_handlers);
			     i++) {
				ret = fbo_modesense_handlers[i].get(&buf[used_len],
								    sizeof(buf) - used_len,
								    page_control);
				if (ret <= 0)
					break;

				if (used_len + ret >= alloc_len)
					break;

				used_len += ret;
			}
		}
		else {
			for (i = 0; i < ARRAY_SIZE(fbo_modesense_handlers);
			     i++) {
				if (page_code == fbo_modesense_handlers[i].page) {
					ret = fbo_modesense_handlers[i].get(&buf[used_len],
									    sizeof(buf) - used_len,
									    page_control);
					if (ret <= 0)
						break;

					used_len += ret;
					got_sense = true;
					break;
				}
			}
		}

		if (!got_sense)
			return TCMU_STS_INVALID_CDB;
	}

	if (sense_ten) {
		uint16_t *ptr = (uint16_t *)buf;
		*ptr = htobe16(used_len - 2);
	}
	else {
		buf[0] = used_len - 1;
	}

	tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, used_len);

	return TCMU_STS_OK;
}

static int fbo_emulate_mode_select(uint8_t *cdb, struct iovec *iovec,
				   size_t iov_cnt, uint8_t *sense)
{
	bool select_ten = (cdb[0] == MODE_SELECT_10);
	uint8_t page_code;
	size_t alloc_len = tcmu_get_xfer_length(cdb);
	int i;
	int ret;
	int used_len;
	uint8_t buf[512];
	uint8_t in_buf[512];
	bool got_sense;

	/* Abort if !PF or SP */
	if (!(cdb[1] & 0x10) || (cdb[1] & 0x01))
		return TCMU_STS_INVALID_CDB;

	if (alloc_len > sizeof(in_buf))
		return TCMU_STS_INVALID_PARAM_LIST_LEN;

	memset(buf, 0, sizeof(buf));

	if (tcmu_memcpy_from_iovec(in_buf, sizeof(in_buf), iovec, iov_cnt) !=
	    alloc_len)
		return TCMU_STS_INVALID_PARAM_LIST_LEN;

	/* Mode parameter header length */
	used_len = select_ten ? 8 : 4;

	while (alloc_len > used_len) {
		got_sense = false;
		page_code = in_buf[used_len];
		for (i = 0; i < ARRAY_SIZE(fbo_modesense_handlers); i++) {
			if (page_code == fbo_modesense_handlers[i].page) {
				ret = fbo_modesense_handlers[i].get(&buf[used_len],
								    sizeof(buf) - used_len,
								    0);
				if (ret <= 0)
					return TCMU_STS_INVALID_CDB;

				if (used_len + ret > alloc_len)
					return TCMU_STS_INVALID_PARAM_LIST_LEN;

				got_sense = true;
				break;
			}
		}

		if (!got_sense)
			return TCMU_STS_INVALID_PARAM_LIST;

		/* We don't support changing anything, so data must match */
		if (memcmp(&buf[used_len], &in_buf[used_len], ret))
			return TCMU_STS_INVALID_PARAM_LIST;

		used_len += ret;
	}

	return TCMU_STS_OK;
}

static int fbo_emulate_allow_medium_removal(struct tcmu_device *dev,
					    uint8_t *cdb, uint8_t *sense)
{
	struct fbo_state *state = tcmu_get_dev_private(dev);

	pthread_mutex_lock(&state->state_mtx);
	/* We're ignoring the persistent prevent bit */
	if (cdb[4] & 0x01)
		state->flags |= FBO_PREV_EJECT;
	else
		state->flags &= ~FBO_PREV_EJECT;
	pthread_mutex_unlock(&state->state_mtx);

	return TCMU_STS_OK;
}

static int fbo_emulate_read_toc(struct tcmu_device *dev, uint8_t *cdb,
				struct iovec *iovec, size_t iov_cnt,
				uint8_t *sense)
{
	struct fbo_state *state = tcmu_get_dev_private(dev);
	uint8_t time_bit = cdb[1] & 0x02;
	uint8_t format = cdb[2] & 0x0f;
	uint8_t buf[512];

	memset(buf, 0, sizeof(buf));

	// TBD: If we simulate start/stop, then fail if stopped
	switch (format) {
	case 0x00:	// Formatted TOC
		buf[1] = 0x12;			// TOC Data Length
		buf[2] = 1;			// First Track
		buf[3] = 1;			// Last Track
		buf[5] = 0x14;			// ADR + CONTROL
		buf[6] = 1;			// Track #
		if (time_bit)
			buf[10] = CDROM_MSF;	// 00:00:02:00
		if (state->flags & FBO_READ_ONLY)
			buf[13] = 0x14;		// ADR + CONTROL
		else
			buf[13] = 0x17;		// ADR + CONTROL
		buf[14] = CDROM_LEADOUT;	// Track #
		if (time_bit) {
			/* Max time address is 00:FF:3B:4A */
			if (state->num_lbas >=
			    (0xff * CD_SECS + CD_SECS - 1) * CD_FRAMES +
			    CD_FRAMES - 1 - CD_MSF_OFFSET) {
				buf[17] = 0xff;
				buf[18] = CD_SECS - 1;
				buf[19] = CD_FRAMES - 1;
			}
			else {
				buf[17] = (state->num_lbas / CD_FRAMES + 2) /
					CD_SECS;
				buf[18] = (state->num_lbas / CD_FRAMES + 2) %
					CD_SECS;
				buf[19] = state->num_lbas % CD_FRAMES;
			}
		}
		else {
			put_unaligned_be32(state->num_lbas, &buf[16]);
		}

		tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, 0x14);
		break;

	case 0x01:	// Multi-Session Information
		buf[1] = 0xa;			// TOC Data Length
		buf[2] = 1;			// First Complete Session
		buf[3] = 1;			// Last Complete Session
		buf[5] = 0x14;			// ADR + CONTROL
		buf[6] = 1;			// Track #
		if (time_bit)
			buf[10] = 2;		// 00:00:02:00

		tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, 0xc);
		break;

	default:
		return TCMU_STS_INVALID_CDB;
	}

	return TCMU_STS_OK;
}

static int fbo_emulate_get_configuration(struct tcmu_device *dev, uint8_t *cdb,
					 struct iovec *iovec, size_t iov_cnt,
					 uint8_t *sense)
{
	struct fbo_state *state = tcmu_get_dev_private(dev);
	uint8_t rt = cdb[1] & 0x03;
	uint16_t start = be16toh(*(uint16_t *)&cdb[2]);
	int used_len;
	uint8_t *cur;
	uint8_t buf[512];

	/* Reserved value for RT */
	if (rt == 3)
		return TCMU_STS_INVALID_CDB;

	memset(buf, 0, sizeof(buf));

	/* Set current profile in the feature header */
	if (state->flags & FBO_READ_ONLY)
		put_unaligned_be16(0x10, &buf[6]); //DVD-ROM
	else
		put_unaligned_be16(0x12, &buf[6]); //DVD-ROM

	/* Feature header */
	used_len = 8;

	/* Profile List Feature */
	if ((rt == 2 && start == 0x0000) ||
	    (start <= 0x0000 && (rt == 0 || rt == 1))) {
		cur = &buf[used_len];
		*(uint16_t *)&cur[0] = htobe16(0x0000);
		cur[2] = 3;		// persistent=1, current=1
		cur[3] = 16;		// # of profile descriptors * 4

		*(uint16_t *)&cur[4] = htobe16(0x12);	// DVD-RAM Profile
		if (!(state->flags & FBO_READ_ONLY))
			cur[6] = 1;			// active profile

		*(uint16_t *)&cur[8] = htobe16(0x10);	// DVD-ROM Profile
		if (state->flags & FBO_READ_ONLY)
			cur[10] = 1;			// active profile

		*(uint16_t *)&cur[12] = htobe16(0x0a);	// CD-RW Profile

		*(uint16_t *)&cur[16] = htobe16(0x08);	// CD-ROM Profile

		used_len += 20;
	}

	/* Core Feature */
	if ((rt == 2 && start == 0x0001) ||
	    (start <= 0x0001 && (rt == 0 || rt == 1))) {
		cur = &buf[used_len];
		*(uint16_t *)&cur[0] = htobe16(0x0001);
		cur[2] = 7;	// version=1, persistent=1, current=1
		cur[3] = 8;	// additional length

		/* SCSI Physical Interface Standard */
		*(uint32_t *)&cur[4] = htobe32(1);
		cur[8] = 1;	// Device Busy Event

		used_len += 12;
	}

	/* Morphing Feature */
	if ((rt == 2 && start == 0x0002) ||
	    (start <= 0x0002 && (rt == 0 || rt == 1))) {
		cur = &buf[used_len];
		*(uint16_t *)&cur[0] = htobe16(0x0002);
		cur[2] = 7;	// version=1, persistent=1, current=1
		cur[3] = 4;	// additional length

		cur[4] = 2;	// OCEvent = 1, ASYNC = 0

		used_len += 8;
	}

	/* Removable Medium Feature */
	if ((rt == 2 && start == 0x0003) ||
	    (start <= 0x0003 && (rt == 0 || rt == 1))) {
		cur = &buf[used_len];
		*(uint16_t *)&cur[0] = htobe16(0x0003);
		cur[2] = 3;	// persistent=1, current=1
		cur[3] = 4;	// additional length

		cur[4] = 0x20;	// mechanism=1, eject=0, pvnt jmpr=0, lock=0

		used_len += 8;
	}

	/* Random Readable Feature */
	if ((rt == 2 && start == 0x0010) ||
	    (start <= 0x0010 && (rt == 0 || rt == 1))) {
		cur = &buf[used_len];
		*(uint16_t *)&cur[0] = htobe16(0x0010);
		cur[2] = 1;	// version=0, persistent=0, current=1
		cur[3] = 8;	// additional length

		*(uint32_t *)&cur[4] = htobe32(state->block_size);
		*(uint16_t *)&cur[8] = htobe16(0x10);	// Blocking
		cur[10] = 0x01;	// PP=1

		used_len += 12;
	}

	/* Multi Read Feature - never current */
	if ((rt == 2 && start == 0x001d) ||
	    (start <= 0x001d && rt == 0)) {
		cur = &buf[used_len];
		*(uint16_t *)&cur[0] = htobe16(0x001d);
		cur[2] = 0;	// version=0, persistent=0, current=0
		cur[3] = 0;	// additional length

		used_len += 4;
	}

	/* CD Read Feature - never current */
	if ((rt == 2 && start == 0x001e) ||
	    (start <= 0x001e && rt == 0)) {
		cur = &buf[used_len];
		*(uint16_t *)&cur[0] = htobe16(0x001e);
		cur[2] = 8;	// version=2, persistent=0, current=0
		cur[3] = 4;	// additional length

		used_len += 8;
	}

	/* DVD Read Feature */
	if ((rt == 2 && start == 0x001f) ||
	    (start <= 0x001f && (rt == 0 || rt == 1))) {
		cur = &buf[used_len];
		*(uint16_t *)&cur[0] = htobe16(0x001f);
		cur[2] = 1;	// version=0, persistent=0, current=1
		cur[3] = 0;	// additional length

		used_len += 4;
	}

	/* Random Writable Feature */
	if ((rt == 2 && start == CDF_RWRT) ||
	    (start <= CDF_RWRT &&
	     (rt == 0 || (rt == 1 && !(state->flags & FBO_READ_ONLY))))) {
		cur = &buf[used_len];
		*(uint16_t *)&cur[0] = htobe16(CDF_RWRT);
		if (state->flags & FBO_READ_ONLY)
			cur[2] = 4;	// version=1, persistent=0, current=0
		else
			cur[2] = 5;	// version=1, persistent=0, current=1
		cur[3] = 0xc;		// additional length

		*(uint32_t *)&cur[4] = htobe32(state->num_lbas - 1);
		*(uint32_t *)&cur[8] = htobe32(state->block_size);
		*(uint16_t *)&cur[12] = htobe16(0x10);	// Blocking
		cur[14] = 0x01;		// PP=1

		used_len += 16;
	}

	/* Incremental Streaming Writable Feature - never current */
	if ((rt == 2 && start == 0x0021) ||
	    (start <= 0x0021 && rt == 0)) {
		cur = &buf[used_len];
		*(uint16_t *)&cur[0] = htobe16(0x0021);
		cur[2] = 4;	// version=1, persistent=0, current=0
		cur[3] = 4;	// additional length

		used_len += 8;
	}

	/* Formattable Feature */
	if ((rt == 2 && start == 0x0023) ||
	    (start <= 0x0023 &&
	     (rt == 0 || (rt == 1 && !(state->flags & FBO_READ_ONLY))))) {
		cur = &buf[used_len];
		*(uint16_t *)&cur[0] = htobe16(0x0023);
		if (state->flags & FBO_READ_ONLY)
			cur[2] = 0;	// version=0, persistent=0, current=0
		else
			cur[2] = 1;	// version=0, persistent=0, current=1
		cur[3] = 0;	// additional length

		used_len += 4;
	}

	/* Hardware Defect Management Feature */
	if ((rt == 2 && start == CDF_HWDM) ||
	    (start <= CDF_HWDM &&
	     (rt == 0 || (rt == 1 && !(state->flags & FBO_READ_ONLY))))) {
		cur = &buf[used_len];
		*(uint16_t *)&cur[0] = htobe16(CDF_HWDM);
		if (state->flags & FBO_READ_ONLY)
			cur[2] = 4;	// version=1, persistent=0, current=0
		else
			cur[2] = 5;	// version=1, persistent=0, current=1
		cur[3] = 4;	// additional length

		used_len += 8;
	}

	/* Restricted Overwrite Feature - never current */
	if ((rt == 2 && start == 0x0026) ||
	    (start <= 0x0026 && rt == 0)) {
		cur = &buf[used_len];
		*(uint16_t *)&cur[0] = htobe16(0x0026);
		cur[2] = 0;	// version=0, persistent=0, current=0
		cur[3] = 0;	// additional length

		used_len += 4;
	}

	/* CD Track at Once Feature - never current */
	if ((rt == 2 && start == 0x002d) ||
	    (start <= 0x002d && rt == 0)) {
		cur = &buf[used_len];
		*(uint16_t *)&cur[0] = htobe16(0x002d);
		cur[2] = 8;	// version=2, persistent=0, current=0
		cur[3] = 4;	// additional length

		used_len += 8;
	}

	/* Timeout Feature */
	if ((rt == 2 && start == 0x0105) ||
	    (start <= 0x0105 && (rt == 0 || rt == 1))) {
		cur = &buf[used_len];
		*(uint16_t *)&cur[0] = htobe16(0x0105);
		cur[2] = 5;	// version=1, persistent=0, current=1
		cur[3] = 4;	// additional length

		used_len += 8;
	}

	put_unaligned_be32(used_len - 4, &buf[0]);

	tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, used_len);

	return TCMU_STS_OK;
}

static int fbo_emulate_get_event_status_notification(struct tcmu_device *dev,
						     uint8_t *cdb,
						     struct iovec *iovec,
						     size_t iov_cnt,
						     uint8_t *sense)
{
	struct fbo_state *state = tcmu_get_dev_private(dev);
	uint8_t class_req = cdb[4];
	uint16_t alloc_len = tcmu_get_xfer_length(cdb);
	int used_len;
	uint8_t buf[8];

	if (!(cdb[1] & 0x01))
		/* We don't support asynchronous operation */
		return TCMU_STS_INVALID_CDB;

	memset(buf, 0, sizeof(buf));

	buf[3] = 0x42;	// Operational Change and Device Busy

	if (!(class_req & 0x42)) {
		/* We don't support any requested notification classes */
		buf[2] = 0x80;
		used_len = 4;
		goto done;
	}

	pthread_mutex_lock(&state->state_mtx);
	if (class_req & 0x02 &&
	    (state->event_op_ch_code || !(class_req & 0x40) ||
	     !(state->flags & FBO_BUSY_EVENT)))
	{
		/* We're reporting an Operational Change event */
		buf[2] = 1;
		if (alloc_len > 4)
		{
			buf[4] = state->event_op_ch_code;
			if (state->event_op_ch_code)
				put_unaligned_be16(0x0001, &buf[6]);
			state->event_op_ch_code = 0;
			used_len = 8;
		}
		else {
			/* Only return the header */
			used_len = 4;
		}
	}
	else {
		/* We're reporting a Device Busy event */
		buf[2] = 6;
		if (alloc_len > 4)
		{
			if (state->flags & FBO_BUSY_EVENT) {
				/* A Busy Event has occurred */
				buf[4] = 1;
				state->flags &= ~FBO_BUSY_EVENT;
			}
			if ((state->flags & FBO_FORMAT_IMMED) ||
			    state->async_cache_count)
				/* Our current state is "busy" */
				buf[5] = 1;
			used_len = 8;
		}
		else {
			/* Only return the header */
			used_len = 4;
		}
	}
	pthread_mutex_unlock(&state->state_mtx);

done:
	put_unaligned_be16(used_len - 4, &buf[0]);

	tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, used_len);

	return TCMU_STS_OK;
}

static int fbo_emulate_read_disc_information(struct tcmu_device *dev,
                                             uint8_t *cdb, struct iovec *iovec,
                                             size_t iov_cnt, uint8_t *sense)
{
	struct fbo_state *state = tcmu_get_dev_private(dev);
	uint8_t buf[34];

	memset(buf, 0, sizeof(buf));

	buf[1] = 32;            // Disc Information Length
	if (state->flags & FBO_READ_ONLY)
		buf[2] = 0x0E;	// Era=0, Last=3, Status=2
	else
		buf[2] = 0x1F;	// Era=1, Last=3, Status=3
	buf[3] = 1;             // First Track
	buf[4] = 1;		// One session
	buf[5] = 1;		// First Track (LSB)
	buf[6] = 1;		// Last Track (LSB)
	buf[7] = 0x20;		// URU=1

	tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, 34);

	return TCMU_STS_OK;
}

static int fbo_emulate_read_dvd_structure(struct tcmu_device *dev, uint8_t *cdb,
					  struct iovec *iovec, size_t iov_cnt,
					  uint8_t *sense)
{
	struct fbo_state *state = tcmu_get_dev_private(dev);
	uint8_t format = cdb[7];
	uint32_t start_phys;
	uint32_t end_phys;
	char manuf_info[] = "VIRTUAL FB OPT";
	uint8_t buf[512];

	// TBD: If we simulate start/stop, then fail if stopped and format != 0xff
	/* Fail anything other than layer 0 */
	if (cdb[6])
		return TCMU_STS_INVALID_CDB;

	memset(buf, 0, sizeof(buf));

	switch (format) {
	case DVD_STRUCT_PHYSICAL:
		if (state->flags & FBO_READ_ONLY)
			start_phys = 0x30000;
		else
			start_phys = 0x31000;
		buf[1] = 19;			//DVD Structure Data Length
		if (state->flags & FBO_READ_ONLY)
			buf[4] = 0x02;		// Book Type=0, Part Version=2
		else
			buf[4] = 0x12;		// Book Type=1, Part Version=2
		buf[5] = 0x0f;			// Maximum Rate=Not specified
		if (!(state->flags & FBO_READ_ONLY))
			buf[6] = 0x02;		// Layer Type=2
		buf[9] = start_phys >> 16;	// Starting physical sector
		put_unaligned_be16(start_phys & 0xffff, &buf[10]);
		end_phys = start_phys + state->num_lbas - 1;
		buf[13] = end_phys >> 16;
		put_unaligned_be16(end_phys & 0xffff, &buf[14]);

		tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, 21);
		break;

	case DVD_STRUCT_COPYRIGHT:
		buf[1] = 6;	// DVD Structure Data Length

		tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, 8);
		break;

	case DVD_STRUCT_MANUFACT:
		buf[2] = strlen(manuf_info) + 2;	// DVD Struct Data Len
		memcpy(&buf[4], manuf_info, strlen(manuf_info));

		tcmu_memcpy_into_iovec(iovec, iov_cnt, buf,
				       strlen(manuf_info) + 4);
		break;

	case 0x09:	// DVD-RAM Medium Status (Cartridge Info)
		if (state->flags & FBO_READ_ONLY)
			return TCMU_STS_INVALID_CDB;

		buf[1] = 6;	// DVD Structure Data Length
		buf[5] = 0x10;	// Disc Type Identification

		tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, 8);
		break;

	case 0xff:	// Read DVD Structure Capabilities List
		buf[1] = 18;	// DVD Structure Data Length

		buf[4] = 0x00;	// Format Field
		buf[5] = 0x40;	// SDS=0, RDS=1
		buf[7] = 21;	// Structure Length

		buf[8] = 0x01;	// Format Field
		buf[9] = 0x40;	// SDS=0, RDS=1
		buf[11] = 8;	// Structure Length

		buf[12] = 0x04;	// Format Field
		buf[13] = 0x40;	// SDS=0, RDS=1
		buf[15] = strlen(manuf_info) + 4;	// Structure Length

		buf[16] = 0x09;	// Format Field
		buf[17] = 0x40;	// SDS=0, RDS=1
		buf[19] = 8;	// Structure Length

		tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, 20);
		break;

	default:
		return TCMU_STS_INVALID_CDB;
	}

	return TCMU_STS_OK;
}

static int fbo_emulate_mechanism_status(struct tcmu_device *dev, uint8_t *cdb,
					struct iovec *iovec, size_t iov_cnt,
					uint8_t *sense)
{
	struct fbo_state *state = tcmu_get_dev_private(dev);
	uint8_t buf[8];

	memset(buf, 0, sizeof(buf));

	if (state->flags & FBO_DEV_IO) {
		buf[1] = 0x20;	// mechanism state=1 (playing)
		buf[2] = (state->cur_lba >> 16) & 0xff;
		put_unaligned_be16(state->cur_lba & 0xffff, &buf[3]);
	}

	tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, 8);

	return TCMU_STS_OK;
}

static int fbo_do_sync(struct fbo_state *state, uint8_t *sense)
{
	int rc;

	rc = fsync(state->fd);
	if (rc) {
		tcmu_err("sync failed: %m\n");
		return TCMU_STS_WR_ERR;
	}

	return TCMU_STS_OK;
}

static void *fbo_async_sync_cache(void *arg)
{
	struct tcmu_device *dev = (struct tcmu_device *)arg;
	struct fbo_state *state = tcmu_get_dev_private(dev);
	uint8_t sense[SENSE_BUFFERSIZE];

	pthread_mutex_lock(&state->state_mtx);
	state->async_cache_count++;
	state->flags |= FBO_BUSY_EVENT;
	pthread_mutex_unlock(&state->state_mtx);

	/* We don't do deferred sense data, so ignore errors */
	(void)fbo_do_sync(state, sense);

	pthread_mutex_lock(&state->state_mtx);
	state->async_cache_count--;
	/* A Busy Event also applies when we go from "busy" to "not busy" */
	state->flags |= FBO_BUSY_EVENT;
	pthread_mutex_unlock(&state->state_mtx);

	return NULL;
}

static int fbo_synchronize_cache(struct tcmu_device *dev, uint8_t *cdb,
				 uint8_t *sense)
{
	struct fbo_state *state = tcmu_get_dev_private(dev);
	pthread_t thr;

	// TBD: If we simulate start/stop, then fail if stopped
	/* Reserved bit */
	if (cdb[1] & 0x01)
		return TCMU_STS_INVALID_CDB;

	if (cdb[1] & 0x02) {
		/* Immediate Bit set */
		pthread_create(&thr, NULL, fbo_async_sync_cache, dev);

		return TCMU_STS_OK;
	}

	return fbo_do_sync(state, sense);
}

static int fbo_check_lba_and_length(struct fbo_state *state, uint8_t *cdb,
				    uint8_t *sense, uint64_t *plba, int *plen)
{
	uint64_t lba;
	uint32_t num_blocks;

	lba = tcmu_get_lba(cdb);
	num_blocks = tcmu_get_xfer_length(cdb);

	if (lba >= state->num_lbas || lba + num_blocks > state->num_lbas)
		return TCMU_STS_RANGE;

	*plba = lba;
	*plen = num_blocks * state->block_size;

	return TCMU_STS_OK;
}

static int fbo_read(struct tcmu_device *dev, uint8_t *cdb, struct iovec *iovec,
		    size_t iov_cnt, uint8_t *sense)
{
	struct fbo_state *state = tcmu_get_dev_private(dev);
	uint8_t fua = cdb[1] & 0x08;
	uint64_t cur_lba = 0;
	uint64_t offset;
	int length = 0;
	int remaining;
	ssize_t ret;
	int rc;

	// TBD: If we simulate start/stop, then fail if stopped
	/* DPO and RelAdr bits should be 0 */
	if (cdb[0] != READ_6 && cdb[1] & 0x11)
		return TCMU_STS_INVALID_CDB;

	rc = fbo_check_lba_and_length(state, cdb, sense, &cur_lba, &length);
	if (rc)
		return rc;

	offset = state->block_size * cur_lba;

	if (fua) {
		rc = fsync(state->fd);
		if (rc) {
			tcmu_err("sync failed: %m\n");
			return TCMU_STS_RD_ERR;
		}
	}

	pthread_mutex_lock(&state->state_mtx);
	state->cur_lba = cur_lba;
	state->flags |= FBO_DEV_IO;
	pthread_mutex_unlock(&state->state_mtx);

	remaining = length;

	while (remaining) {
		ret = preadv(state->fd, iovec, iov_cnt, offset);
		if (ret < 0) {
			tcmu_err("read failed: %m\n");
			rc = TCMU_STS_RD_ERR;
			break;
		}
		tcmu_seek_in_iovec(iovec, ret);
		offset += ret;
		remaining -= ret;
	}

	pthread_mutex_lock(&state->state_mtx);
	state->flags &= ~FBO_DEV_IO;
	pthread_mutex_unlock(&state->state_mtx);

	return TCMU_STS_OK;
}

static void fbo_cleanup_buffer(void *buf)
{
	free(buf);
}

static int fbo_do_verify(struct fbo_state *state, struct iovec *iovec,
			 size_t iov_cnt, uint64_t offset, int length,
			 uint8_t *sense)
{
	ssize_t ret;
	uint32_t cmp_offset;
	void *buf;
	int rc = TCMU_STS_OK;
	int remaining;

	buf = malloc(length);
	if (!buf)
		return TCMU_STS_NO_RESOURCE;

	pthread_cleanup_push(fbo_cleanup_buffer, buf);
	memset(buf, 0, length);

	pthread_mutex_lock(&state->state_mtx);
	state->cur_lba = offset / state->block_size;
	state->flags |= FBO_DEV_IO;
	pthread_mutex_unlock(&state->state_mtx);

	remaining = length;

	while (remaining) {
		ret = pread(state->fd, buf, remaining, offset);
		if (ret < 0) {
			tcmu_err("read failed: %m\n");
			rc = TCMU_STS_RD_ERR;
			break;
		}

		cmp_offset = tcmu_compare_with_iovec(buf, iovec, ret);
		if (cmp_offset != -1) {
			rc = TCMU_STS_MISCOMPARE;
			tcmu_set_sense_info(sense, cmp_offset);
			break;
		}
		tcmu_seek_in_iovec(iovec, ret);

		offset += ret;
		remaining -= ret;
	}

	pthread_mutex_lock(&state->state_mtx);
	state->flags &= ~FBO_DEV_IO;
	pthread_mutex_unlock(&state->state_mtx);

	free(buf);
	pthread_cleanup_pop(0);

	return rc;
}

static int fbo_write(struct tcmu_device *dev, uint8_t *cdb, struct iovec *iovec,
		     size_t iov_cnt, uint8_t *sense, bool do_verify)
{
	struct fbo_state *state = tcmu_get_dev_private(dev);
	struct iovec write_iovec[iov_cnt];
	uint8_t fua = cdb[1] & 0x08;
	uint64_t cur_lba = 0;
	uint64_t offset;
	int length = 0;
	int remaining;
	ssize_t ret;
	int rc = TCMU_STS_OK;
	int rc1;

	// TBD: If we simulate start/stop, then fail if stopped
	if (state->flags & FBO_READ_ONLY)
		return TCMU_STS_WR_ERR_INCOMPAT_FRMT;

	rc = fbo_check_lba_and_length(state, cdb, sense, &cur_lba, &length);
	if (rc != TCMU_STS_OK)
		return rc;

	offset = state->block_size * cur_lba;

	pthread_mutex_lock(&state->state_mtx);
	state->cur_lba = cur_lba;
	state->flags |= FBO_DEV_IO;
	pthread_mutex_unlock(&state->state_mtx);

	remaining = length;

	memcpy(write_iovec, iovec, sizeof(write_iovec));

	while (remaining) {
		ret = pwritev(state->fd, write_iovec, iov_cnt, offset);
		if (ret < 0) {
			tcmu_err("write failed: %m\n");
			rc = TCMU_STS_WR_ERR;
			break;
		}
		tcmu_seek_in_iovec(write_iovec, ret);
		offset += ret;
		remaining -= ret;
	}

	if (rc == TCMU_STS_OK && (do_verify || fua)) {
		rc1 = fsync(state->fd);
		if (rc1) {
			tcmu_err("sync failed: %m\n");
			rc = TCMU_STS_WR_ERR;
		}
	}

	pthread_mutex_lock(&state->state_mtx);
	state->flags &= ~FBO_DEV_IO;
	pthread_mutex_unlock(&state->state_mtx);

	if (!do_verify || rc != TCMU_STS_OK)
		return rc;

	offset = state->block_size * cur_lba;
	return fbo_do_verify(state, iovec, iov_cnt, offset, length, sense);
}

static int fbo_verify(struct tcmu_device *dev, uint8_t *cdb,
		      struct iovec *iovec, size_t iov_cnt, uint8_t *sense)
{
	struct fbo_state *state = tcmu_get_dev_private(dev);
	uint64_t cur_lba = 0;
	uint64_t offset;
	int length = 0;
	int rc;

	// TBD: If we simulate start/stop, then fail if stopped
	if (state->flags & FBO_READ_ONLY)
		return TCMU_STS_WR_ERR_INCOMPAT_FRMT;

	/* All of these bits are reserved for MM logical units */
	if (cdb[1] & 0x13)
		return TCMU_STS_INVALID_CDB;

	rc = fbo_check_lba_and_length(state, cdb, sense, &cur_lba, &length);
	if (rc)
		return rc;

	offset = state->block_size * cur_lba;

	return fbo_do_verify(state, iovec, iov_cnt, offset, length, sense);
}

static int fbo_do_format(struct tcmu_device *dev, uint8_t *sense)
{
	struct fbo_state *state = tcmu_get_dev_private(dev);
	uint32_t done_blocks = 0;
	uint64_t offset = 0;
	uint8_t *buf;
	unsigned int length = 1024 * 1024;
	ssize_t ret;
	int rc = TCMU_STS_OK;

	buf = malloc(length);
	if (!buf) {
		tcmu_dbg("  malloc failed\n");
		return TCMU_STS_NO_RESOURCE;
	}

	pthread_cleanup_push(fbo_cleanup_buffer, buf);
	memset(buf, 0, length);

	while (done_blocks < state->num_lbas) {
		if ((state->num_lbas - done_blocks) * state->block_size <
		    length)
			length = (state->num_lbas - done_blocks) *
				state->block_size;
		ret = pwrite(state->fd, buf, length, offset);
		if (ret == -1) {
			tcmu_err("Could not write: %m\n");
			rc = TCMU_STS_WR_ERR;
			break;
		}
		done_blocks += length / state->block_size;
		offset += length;
		if (done_blocks < state->num_lbas)
			state->format_progress = (0x10000 * done_blocks) /
				state->num_lbas;
	}

	pthread_mutex_lock(&state->state_mtx);
	state->flags &= ~FBO_FORMATTING;
	pthread_mutex_unlock(&state->state_mtx);

	free(buf);
	pthread_cleanup_pop(0);

	return rc;
}

static void *fbo_async_format(void *arg)
{
	struct tcmu_device *dev = (struct tcmu_device *)arg;
	struct fbo_state *state = tcmu_get_dev_private(dev);
	uint8_t sense[SENSE_BUFFERSIZE];

	pthread_mutex_lock(&state->state_mtx);
	state->flags |= FBO_BUSY_EVENT | FBO_FORMAT_IMMED;
	pthread_mutex_unlock(&state->state_mtx);

	/* We don't do deferred sense data, so ignore errors */
	(void)fbo_do_format(dev, sense);

	pthread_mutex_lock(&state->state_mtx);
	state->flags &= ~FBO_FORMAT_IMMED;
	/* A Busy Event also applies when we go from "busy" to "not busy" */
	state->flags |= FBO_BUSY_EVENT;
	pthread_mutex_unlock(&state->state_mtx);

	return NULL;
}

static int fbo_emulate_format_unit(struct tcmu_device *dev, uint8_t *cdb,
				   struct iovec *iovec, size_t iov_cnt,
				   uint8_t *sense)
{
	struct fbo_state *state = tcmu_get_dev_private(dev);
	pthread_t thr;
	uint8_t param_list[12];

	// TBD: If we simulate start/stop, then fail if stopped
	if (state->flags & FBO_READ_ONLY)
		return TCMU_STS_WR_ERR_INCOMPAT_FRMT;

	if (!(cdb[1] & 0x10) || ((cdb[1] & 0x07) != 1) || cdb[3] || cdb[4])
		return TCMU_STS_INVALID_CDB;

	if (tcmu_memcpy_from_iovec(param_list, 12, iovec, iov_cnt) < 12)
		return TCMU_STS_INVALID_PARAM_LIST_LEN;

	if (!(param_list[1] & 0x80) && (param_list[1] & 0x7c))
		/* Options Valid not set but option bits set */
		return TCMU_STS_INVALID_PARAM_LIST;

	if (param_list[1] & 0x1c)
		/* We don't support these options */
		return TCMU_STS_INVALID_PARAM_LIST;

	if (get_unaligned_be16(&param_list[2]) != 8)
		return TCMU_STS_INVALID_PARAM_LIST;

	if (param_list[8])
		/* We only support Format Type 0 */
		return TCMU_STS_INVALID_PARAM_LIST;

	if ((cdb[1] & 0x08 || !(param_list[1] & 0x20)) &&
	    get_unaligned_be16(&param_list[4])  != state->num_lbas)
		/* Number of Blocks doesn't match */
		return TCMU_STS_INVALID_PARAM_LIST;

	if ((((uint32_t)param_list[9] << 16) +
	     get_unaligned_be16(&param_list[10])) != state->block_size)
		/* Block Size is wrong */
		return TCMU_STS_INVALID_PARAM_LIST;

	pthread_mutex_lock(&state->state_mtx);
	/* Note that while our caller already checked this flag, the
	 * check was made outside the lock.  We need to check it again
	 * now that we have the lock.
	 */
	if (state->flags & FBO_FORMATTING) {
		pthread_mutex_unlock(&state->state_mtx);
		tcmu_set_sense_key_specific_info(sense, state->format_progress);
		return TCMU_STS_FRMT_IN_PROGRESS;
	}
	state->format_progress = 0;
	state->flags |= FBO_FORMATTING;
	pthread_mutex_unlock(&state->state_mtx);

	if (param_list[1] & 0x02) {
		/* Immediate Bit set */
		pthread_create(&thr, NULL, fbo_async_format, dev);

		return TCMU_STS_OK;
	}

	return fbo_do_format(dev, sense);
}

static int fbo_emulate_read_format_capacities(struct tcmu_device *dev,
					      uint8_t *cdb, struct iovec *iovec,
					      size_t iov_cnt, uint8_t *sense)
{
	struct fbo_state *state = tcmu_get_dev_private(dev);
	int used_len;
	uint8_t buf[20];

	memset(buf, 0, sizeof(buf));

	put_unaligned_be32(state->num_lbas, &buf[4]);
	buf[8] = 0x02;
	buf[9] = (state->block_size >> 16) & 0xff;
	put_unaligned_be16(state->block_size & 0xffff, &buf[10]);
	if (state->flags & FBO_READ_ONLY) {
		used_len = 12;
	}
	else {
		memcpy(&buf[12], &buf[4], 8);
		buf[16] = 0;
		used_len = 20;
	}
	buf[3] = used_len - 4;

	tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, used_len);

	return TCMU_STS_OK;
}

/*
 * Return scsi status or TCMU_STS_NOT_HANDLED
 */
static int fbo_handle_cmd(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	uint8_t *cdb = cmd->cdb;
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
	uint8_t *sense = cmd->sense_buf;
	struct fbo_state *state = tcmu_get_dev_private(dev);
	bool do_verify = false;
	int ret;

	/* Check for format in progress */
	/* Certain commands can be executed even if a format is in progress */
	if (state->flags & FBO_FORMATTING &&
	    cdb[0] != INQUIRY &&
	    cdb[0] != REQUEST_SENSE &&
	    cdb[0] != GET_CONFIGURATION &&
	    cdb[0] != GPCMD_GET_EVENT_STATUS_NOTIFICATION) {
		tcmu_set_sense_key_specific_info(sense, state->format_progress);
		ret = TCMU_STS_FRMT_IN_PROGRESS;
		cmd->done(dev, cmd, ret);
		return 0;
	}

	switch(cdb[0]) {
	case TEST_UNIT_READY:
		ret = tcmu_emulate_test_unit_ready(cdb, iovec, iov_cnt);
		break;
	case REQUEST_SENSE:
		ret = fbo_emulate_request_sense(dev, cdb, iovec, iov_cnt, sense);
		break;
	case FORMAT_UNIT:
		ret = fbo_emulate_format_unit(dev, cdb, iovec, iov_cnt, sense);
		break;
	case READ_6:
	case READ_10:
	case READ_12:
		ret = fbo_read(dev, cdb, iovec, iov_cnt, sense);
		break;
	case WRITE_VERIFY:
		do_verify = true;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
		ret = fbo_write(dev, cdb, iovec, iov_cnt, sense, do_verify);
		break;
	case INQUIRY:
		ret = fbo_emulate_inquiry(cdb, iovec, iov_cnt, sense);
		break;
	case MODE_SELECT:
	case MODE_SELECT_10:
		ret = fbo_emulate_mode_select(cdb, iovec, iov_cnt, sense);
		break;
	case MODE_SENSE:
	case MODE_SENSE_10:
		ret = fbo_emulate_mode_sense(cdb, iovec, iov_cnt, sense);
		break;
	case START_STOP:
		ret = tcmu_emulate_start_stop(dev, cdb);
		break;
	case ALLOW_MEDIUM_REMOVAL:
		ret = fbo_emulate_allow_medium_removal(dev, cdb, sense);
		break;
	case READ_FORMAT_CAPACITIES:
		ret = fbo_emulate_read_format_capacities(dev, cdb, iovec,
							 iov_cnt, sense);
		break;
	case READ_CAPACITY:
		if ((cdb[1] & 0x01) || (cdb[8] & 0x01))
			/* Reserved bits for MM logical units */
			return TCMU_STS_INVALID_CDB;
		else
			ret = tcmu_emulate_read_capacity_10(state->num_lbas,
							    state->block_size,
							    cdb, iovec,
							    iov_cnt);
		break;
	case VERIFY:
		ret = fbo_verify(dev, cdb, iovec, iov_cnt, sense);
		break;
	case SYNCHRONIZE_CACHE:
		ret = fbo_synchronize_cache(dev, cdb, sense);
		break;
	case READ_TOC:
		ret = fbo_emulate_read_toc(dev, cdb, iovec, iov_cnt, sense);
		break;
	case GET_CONFIGURATION:
		ret = fbo_emulate_get_configuration(dev, cdb, iovec, iov_cnt,
						    sense);
		break;
	case GPCMD_GET_EVENT_STATUS_NOTIFICATION:
		ret = fbo_emulate_get_event_status_notification(dev, cdb,
								iovec, iov_cnt,
								sense);
		break;
	case READ_DISC_INFORMATION:
		ret = fbo_emulate_read_disc_information(dev, cdb, iovec,
							iov_cnt, sense);
		break;
	case READ_DVD_STRUCTURE:
		ret = fbo_emulate_read_dvd_structure(dev, cdb, iovec, iov_cnt,
						     sense);
		break;
	case MECHANISM_STATUS:
		ret = fbo_emulate_mechanism_status(dev, cdb, iovec, iov_cnt,
						   sense);
		break;
	default:
		ret = TCMU_STS_NOT_HANDLED;
	}

	cmd->done(dev, cmd, ret);
	return 0;
}

static const char fbo_cfg_desc[] =
	"The path to the file to use as a backstore.";

static struct tcmulib_backstore_handler fbo_handler = {
	.cfg_desc = fbo_cfg_desc,

	.open = fbo_open,
	.close = fbo_close,
	.name = "File-backed optical Handler",
	.subtype = "fbo",
	.handle_cmd = fbo_handle_cmd,
	.nr_threads = 1,
};

/* Entry point must be named "handler_init". */
int handler_init(void)
{
	return tcmulib_register_backstore_handler(&fbo_handler);
}

