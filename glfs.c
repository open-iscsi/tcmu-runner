/*
 * Copyright 2015, Red Hat, Inc.
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

#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <scsi/scsi.h>
#include <glusterfs/api/glfs.h>

#include "tcmu-runner.h"

#define ALLOWED_BSOFLAGS (O_SYNC | O_DIRECT | O_RDWR | O_LARGEFILE)

#define GLUSTER_PORT 24007

struct glfs_state {
	char *name;
	glfs_t *fs;
	glfs_fd_t *gfd;
	char *servername;
	char *volname;
	char *pathname;

	unsigned long long num_lbas;
	unsigned int block_size;

	/* write caching supported */
	bool wce;

	/* logical block provisioning (UNMAP) supported */
	bool tpu;
	/* logical block provisioning (WRITE_SAME) supported */
	bool tpws;
};

/*
 * Break image string into server, volume, and path components and set
 * gfsp members. Returns -1 on failure.
 */
static int parse_imagepath(char *image, struct glfs_state *gfsp)
{
	char *origp = strdup(image);
	char *p, *sep;

	if (!origp)
		goto fail;;

	p = origp;
	sep = strchr(p, '@');
	if (!sep)
		goto fail;

	*sep = '\0';
	gfsp->servername = strdup(p);
	if (!gfsp->servername)
		goto fail;

	p = sep + 1;
	sep = strchr(p, '/');
	if (!sep)
		goto fail;

	gfsp->volname = strdup(sep + 1);
	if (!gfsp->volname)
		goto fail;

	/* p points to path\0 */
	*sep = '\0';
	gfsp->pathname = strdup(p);
	if (!gfsp->pathname)
		goto fail;

	free(origp);

	return 0;

fail:
	free(gfsp->volname);
	gfsp->volname = NULL;
	free(gfsp->servername);
	gfsp->servername = NULL;
	free(origp);

	return -1;
}

#define FETCH_ATTRIBUTE(dev, r_value, name)			\
do { 								\
	int attribute = tcmu_get_attribute(dev, name); 		\
	if (attribute == -1) {					\
		printf("Could not get %s setting\n", #name);	\
		goto fail;					\
	} else {						\
		(r_value) = (attribute) ? true: false;		\
	}							\
} while(0)							\


static int tcmu_glfs_open(struct tcmu_device *dev)
{
	struct glfs_state *gfsp;
	int ret = 0;
	char *config;
	long long size;
	struct stat st;

	gfsp = calloc(1, sizeof(*gfsp));
	if (!gfsp)
		return -1;

	dev->hm_private = gfsp;

	FETCH_ATTRIBUTE(dev, gfsp->block_size, "hw_block_size");
	FETCH_ATTRIBUTE(dev, gfsp->wce, "emulate_write_cache");
	FETCH_ATTRIBUTE(dev, gfsp->tpu, "emulate_tpu");
	FETCH_ATTRIBUTE(dev, gfsp->tpws, "emulate_tpws");

	size = tcmu_get_device_size(dev);
	if (size == -1) {
		printf("Could not get device size\n");
		goto fail;
	}

	gfsp->num_lbas = size / gfsp->block_size;

	config = strchr(dev->cfgstring, '/');
	if (!config) {
		printf("no configuration found in cfgstring\n");
		goto fail;
	}
	config += 1; /* get past '/' */

	if (parse_imagepath(config, gfsp) == -1) {
		printf("servername, volname, or pathname not set: %s %s %s\n",
		       gfsp->servername, gfsp->volname, gfsp->pathname);
		goto fail;
	}

	gfsp->fs = glfs_new(gfsp->volname);
	if (!gfsp->fs)
		goto fail;

	ret = glfs_set_volfile_server(gfsp->fs, "tcp", gfsp->servername,
				      GLUSTER_PORT);

	ret = glfs_init(gfsp->fs);
	if (ret)
		goto fail;

	gfsp->gfd = glfs_open(gfsp->fs, gfsp->pathname, ALLOWED_BSOFLAGS);
	if (!gfsp->gfd)
		goto fail;

	ret = glfs_lstat(gfsp->fs, gfsp->pathname, &st);
	if (ret)
		goto fail;

	if (st.st_size != tcmu_get_device_size(dev)) {
		printf("device size and backing size disagree: "
		       "device %lld backing %lld",
		       tcmu_get_device_size(dev),
		       (long long) st.st_size);
		goto fail;
	}

	return 0;

fail:
	if (gfsp->gfd)
		glfs_close(gfsp->gfd);
	if (gfsp->fs)
		glfs_fini(gfsp->fs);
	free(gfsp->volname);
	free(gfsp->pathname);
	free(gfsp->servername);
	free(gfsp);

	return -EIO;
}

static void tcmu_glfs_close(struct tcmu_device *dev)
{
	struct glfs_state *gfsp = dev->hm_private;

	glfs_close(gfsp->gfd);
	glfs_fini(gfsp->fs);
	free(gfsp->volname);
	free(gfsp->pathname);
	free(gfsp->servername);
	free(gfsp);
}

static int set_medium_error(uint8_t *sense)
{
	tcmu_set_sense_data(sense, MEDIUM_ERROR, ASC_READ_ERROR, NULL);
	return SAM_STAT_CHECK_CONDITION;
}

/*
 * Return scsi status or TCMU_NOT_HANDLED
 */
int tcmu_glfs_handle_cmd(
	struct tcmu_device *dev,
	uint8_t *cdb,
	struct iovec *iovec,
	size_t iov_cnt,
	uint8_t *sense)
{
	struct glfs_state *state = dev->hm_private;
	uint8_t cmd;

	glfs_fd_t *gfd = state->gfd;
	int ret;
	uint32_t length;
	int result = SAM_STAT_GOOD;
	char *tmpbuf;
	uint64_t offset = state->block_size * tcmu_get_lba(cdb);
	uint32_t tl     = state->block_size * tcmu_get_xfer_length(cdb);
	int do_verify = 0;
	uint32_t cmp_offset;
	ret = length = 0;

	cmd = cdb[0];

	switch (cmd) {
	case COMPARE_AND_WRITE:
		/* Blocks are transferred twice, first the set that
		 * we compare to the existing data, and second the set
		 * to write if the compare was successful.
		 */
		length = tl / 2;

		tmpbuf = malloc(length);
		if (!tmpbuf) {
			tcmu_set_sense_data(sense, HARDWARE_ERROR,
					    ASC_INTERNAL_TARGET_FAILURE, NULL);
			result = SAM_STAT_CHECK_CONDITION;
			break;
		}

		ret = glfs_pread(gfd, tmpbuf, length, offset, SEEK_SET);

		if (ret != length) {
			result = set_medium_error(sense);
			free(tmpbuf);
			break;
		}

		cmp_offset = tcmu_compare_with_iovec(tmpbuf, iovec, length);
		if (cmp_offset != -1) {
			tcmu_set_sense_data(sense, MISCOMPARE,
					    ASC_MISCOMPARE_DURING_VERIFY_OPERATION,
					    &cmp_offset);
			result = SAM_STAT_CHECK_CONDITION;
			free(tmpbuf);
			break;
		}

		free(tmpbuf);

		tcmu_seek_in_iovec(iovec, length);
		goto write;
	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16:
		if (cdb[1] & 0x2) {
			tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					    ASC_INVALID_FIELD_IN_CDB, NULL);
			result = SAM_STAT_CHECK_CONDITION;
		} else {
			glfs_fdatasync(gfd);
		}
		break;
	case WRITE_VERIFY:
	case WRITE_VERIFY_12:
	case WRITE_VERIFY_16:
		do_verify = 1;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		length = tcmu_get_xfer_length(cdb);
write:
		ret = glfs_pwritev(gfd, iovec, iov_cnt, offset, ALLOWED_BSOFLAGS);

		if (ret == length) {
			/* If FUA or !WCE then sync */
			if (((cmd != WRITE_6) && (cdb[1] & 0x8))
			    || !state->wce)
				glfs_fdatasync(gfd);
		} else
			result = set_medium_error(sense);

		if (!do_verify)
			break;

		tmpbuf = malloc(length);
		if (!tmpbuf) {
			tcmu_set_sense_data(sense, HARDWARE_ERROR,
					    ASC_INTERNAL_TARGET_FAILURE, NULL);
			result = SAM_STAT_CHECK_CONDITION;
			break;
		}

		ret = glfs_pread(gfd, tmpbuf, length, offset, ALLOWED_BSOFLAGS);

		if (ret != length) {
			result = set_medium_error(sense);
			break;
		}

		cmp_offset = tcmu_compare_with_iovec(tmpbuf, iovec, length);
		if (cmp_offset != -1) {
			tcmu_set_sense_data(sense, MISCOMPARE,
					    ASC_MISCOMPARE_DURING_VERIFY_OPERATION,
					    &cmp_offset);
			result = SAM_STAT_CHECK_CONDITION;
		}

		free(tmpbuf);
		break;

	case WRITE_SAME:
	case WRITE_SAME_16:
		if (!state->tpws) {
			tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					    ASC_INVALID_FIELD_IN_CDB, NULL);
			result = SAM_STAT_CHECK_CONDITION;
			break;
		}

		/* WRITE_SAME used to punch hole in file */
		if (cdb[1] & 0x08) {
			ret = glfs_discard(gfd, offset, tl);
			if (ret != 0) {
				printf("Failed WRITE_SAME command\n");
				tcmu_set_sense_data(sense, HARDWARE_ERROR,
						    ASC_INTERNAL_TARGET_FAILURE, NULL);
				result = SAM_STAT_CHECK_CONDITION;
			}
			break;
		}
		while (tl > 0) {
			size_t blocksize = state->block_size;
			uint32_t val32;
			uint64_t val64;

			assert(iovec->iov_len >= 8);

			switch (cdb[1] & 0x06) {
			case 0x02: /* PBDATA==0 LBDATA==1 */
				val32 = htobe32(offset);
				memcpy(iovec->iov_base, &val32, 4);
				break;
			case 0x04: /* PBDATA==1 LBDATA==0 */
				/* physical sector format */
				/* hey this is wrong val! But how to fix? */
				val64 = htobe64(offset);
				memcpy(iovec->iov_base, &val64, 8);
				break;
			default:
				/* FIXME */
				printf("PBDATA and LBDATA set!!!\n");
			}

			ret = glfs_pwritev(gfd, iovec, blocksize,
					offset, ALLOWED_BSOFLAGS);

			if (ret != blocksize)
				result = set_medium_error(sense);

			offset += blocksize;
			tl     -= blocksize;
		}
		break;
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		length = tcmu_iovec_length(iovec, iov_cnt);
		ret = glfs_preadv(gfd, iovec, iov_cnt, offset, SEEK_SET);

		if (ret != length) {
			printf("Error on read %x %x", ret, length);
			result = set_medium_error(sense);
		}
		break;
	case UNMAP:
		if (!state->tpu) {
			tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					    ASC_INVALID_FIELD_IN_CDB, NULL);
			result = SAM_STAT_CHECK_CONDITION;
			break;
		}

		/* TODO: implement UNMAP */
		tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
				    ASC_INVALID_FIELD_IN_CDB, NULL);
		result = SAM_STAT_CHECK_CONDITION;

		break;
	default:
		result = TCMU_NOT_HANDLED;
		break;
	}

	printf("io done %p %x %d %u\n", cdb, cmd, result, length);

	if (result != SAM_STAT_GOOD) {
		printf("io error %p %x %x %d %d %llu\n",
		       cdb, result, cmd, ret, length, (unsigned long long)offset);
	}

	return result;
}

static struct config_option opts[] = {
	{
		.name = "server",
		.desc = "The name of the Gluster server"
	},
	{
		.name = "volume",
		.desc = "The name of the volume on the server"
	},
	{
		.name = "path",
		.desc = "The name of the path to the backing file in the volume"
	},
	{NULL, NULL },
};

struct tcmu_handler glfs_handler = {
	.name = "Gluster glfs handler",
	.subtype = "glfs",
	.cfg_options = opts,

	.open = tcmu_glfs_open,
	.close = tcmu_glfs_close,
	.handle_cmd = tcmu_glfs_handle_cmd,
};

/* Entry point must be named "handler_init". */
void handler_init(void)
{
	tcmu_register_handler(&glfs_handler);
}
