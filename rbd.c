/*
 * Copyright 2016, China Mobile, Inc. 
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
#include <inttypes.h>
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
#include <errno.h>

#include "tcmu-runner.h"
#include "libtcmu.h"

#include <rbd/librbd.h>

/* rbd_aio_discard added in 0.1.2 */
#if LIBRBD_VERSION_CODE >= LIBRBD_VERSION(0, 1, 2)
#define LIBRBD_SUPPORTS_DISCARD
#else
#undef LIBRBD_SUPPORTS_DISCARD
#endif

#define OBJ_MAX_SIZE (1UL << OBJ_DEFAULT_OBJ_ORDER)

#define RBD_MAX_CONF_NAME_SIZE 128
#define RBD_MAX_CONF_VAL_SIZE 512
#define RBD_MAX_CONF_SIZE 1024
#define RBD_MAX_POOL_NAME_SIZE 128
#define RBD_MAX_SNAP_NAME_SIZE 128
#define RBD_MAX_SNAPS 100

struct tcmu_rbd_state {
	rados_t cluster;
	rados_ioctx_t io_ctx;
	rbd_image_t image;
	char name[RBD_MAX_IMAGE_NAME_SIZE];
	char *snap;
	uint64_t num_lbas;
	unsigned int block_size;
};

enum {
	RBD_AIO_READ,
	RBD_AIO_WRITE,
	RBD_AIO_DISCARD,
	RBD_AIO_FLUSH,
};

struct rbd_aio_cb {
	struct tcmu_device *dev;
	struct tcmulib_cmd *tcmulib_cmd;
	int64_t ret;
	char *bounce;
	int rbd_aio_cmd;
	int error;
	int64_t length;
};

static int rbd_next_token(char *dst, int dst_len, char *src, char delim,
			     const char *name, char **p)
{
	int l;
	char *end;

	*p = NULL;

	if (delim != '\0') {
	        for (end = src; *end; ++end) {
			if (*end == delim) {
				break;
			}
			if (*end == '\\' && end[1] != '\0') {
				end++;
			}
		}
		if (*end == delim) {
			*p = end + 1;
			*end = '\0';
		}
	}
	l = strlen(src);
	if (l >= dst_len) {
		errp("%s too long\n", name);
		return -EINVAL;
	} else if (l == 0) {
		errp("%s too short\n", name);
		return -EINVAL;
	}

	strncpy(dst, src, dst_len);

	return 0;
}

static void rbd_unescape(char *src)
{
	char *p;

	for (p = src; *src; ++src, ++p) {
		if (*src == '\\' && src[1] != '\0') {
			src++;
		}
		*p = *src;
	}
	*p = '\0';
}

static int rbd_parsename(const char *config,
			      char *pool, int pool_len,
			      char *snap, int snap_len,
			      char *name, int name_len,
			      char *conf, int conf_len)
{
	char *p, *buf;
	int ret;

	buf = strdup(config);
	p = buf;
	*snap = '\0';
	*conf = '\0';

	ret = rbd_next_token(pool, pool_len, p, '/', "pool name", &p);
	if (ret < 0 || !p) {
		ret = -EINVAL;
		goto done;
	}
	rbd_unescape(pool);

	if (strchr(p, '@')) {
		ret = rbd_next_token(name, name_len, p, '@', "object name",
					&p);
		if (ret < 0) {
			goto done;
		}
		ret = rbd_next_token(snap, snap_len, p, ':', "snap name",
					&p);
		rbd_unescape(snap);
	} else {
		ret = rbd_next_token(name, name_len, p, ':', "object name",
					&p);
	}
	rbd_unescape(name);
	if (ret < 0 || !p) {
		goto done;
	}

	ret = rbd_next_token(conf, conf_len, p, '\0', "configuration", &p);

done:
	free(buf);
	return ret;
}

static char *rbd_parse_clientname(const char *conf, char *clientname)
{
	const char *p = conf;

	while (*p) {
		int len;
		const char *end = strchr(p, ':');

		if (end) {
			len = end - p;
		} else {
			len = strlen(p);
		}

		if (strncmp(p, "id=", 3) == 0) {
			len -= 3;
			strncpy(clientname, p + 3, len);
			clientname[len] = '\0';
			return clientname;
		}
		if (end == NULL) {
			break;
		}
		p = end + 1;
	}
	return NULL;
}

static int rbd_set_conf(rados_t cluster, const char *conf,
			bool only_read_conf_file)
{
	char *p, *buf;
	char name[RBD_MAX_CONF_NAME_SIZE];
	char value[RBD_MAX_CONF_VAL_SIZE];
	int ret = 0;

	buf = strdup(conf);
	p = buf;

	while (p) {
		ret = rbd_next_token(name, sizeof(name), p,
				   '=', "conf option name", &p);
		if (ret < 0) {
			break;
		}
		rbd_unescape(name);

		if (!p) {
			errp("conf option %s has no value\n", name);
			ret = -EINVAL;
			break;
		}

		ret = rbd_next_token(value, sizeof(value), p, ':',
				   "conf option value", &p);
		if (ret < 0) {
			break;
		}
		rbd_unescape(value);

		if (strcmp(name, "conf") == 0) {
			/* read the conf file alone, so it doesn't override more
			   specific settings for a particular device */
			if (only_read_conf_file) {
				ret = rados_conf_read_file(cluster, value);
				if (ret < 0) {
					errp("error reading conf file %s\n",
					     value);
					break;
				}
			}
		} else if (strcmp(name, "id") == 0) {
			/* ignore, this is parsed by tmcu_rbd_parse_clientname() */
		} else if (!only_read_conf_file) {
			ret = rados_conf_set(cluster, name, value);
			if (ret < 0) {
				errp("invalid conf option %s", name);
				ret = -EINVAL;
				break;
			}
		}
	}

	free(buf);
	return ret;
}

static bool tcmu_rbd_check_config(const char *cfgstring, char **reason)
{
	char pool[RBD_MAX_POOL_NAME_SIZE];
	char snap_buf[RBD_MAX_SNAP_NAME_SIZE];
	char conf[RBD_MAX_CONF_SIZE];
	char clientname_buf[RBD_MAX_CONF_SIZE];
	char *clientname;
	const char *config;
	int r;
	bool result = true;
	struct tcmu_rbd_state *state;

	state = calloc(1, sizeof(*state));
	if (!state) {
		if (asprintf(reason, "no memory to init rbd_state") == -1)
			*reason = NULL;
		return false;
	}

	config = strchr(cfgstring, '/');
	if (!config) {
		if (asprintf(reason, "no configuration found in cfgstring %s", config) == -1)
			*reason = NULL;
		result = false;
		goto free_state;
	}
	config += 1; /* get past '/' */

	if (rbd_parsename(config, pool, sizeof(pool),
			       snap_buf, sizeof(snap_buf),
			       state->name, sizeof(state->name),
			       conf, sizeof(conf)) < 0) {
		if (asprintf(reason, "parse config failed %s", config) == -1)
			*reason = NULL;
		result = false;
		goto free_state;
	}

	clientname = rbd_parse_clientname(conf, clientname_buf);
	r = rados_create(&state->cluster, clientname);
	if (r < 0) {
		if (asprintf(reason, "error initializing %m") == -1)
			*reason = NULL;
		result = false;
	}

	state->snap = NULL;
	if (snap_buf[0] != '\0') {
		state->snap = strdup(snap_buf);
	}

	if (strstr(conf, "conf=") == NULL) {
		/* try default location, but ignore failure */
		if(rados_conf_read_file(state->cluster, NULL) < 0) {
			if (asprintf(reason, "error read default conf %m") == -1)
				*reason = NULL;
			result = false;
			goto rados_shutdown;
		}
	} else if (conf[0] != '\0') {
		r = rbd_set_conf(state->cluster, conf, true);
		if (asprintf(reason, "error set conf %s %m", conf) == -1)
			*reason = NULL;
		result = false;
		goto rados_shutdown;
	}

	if (conf[0] != '\0') {
		r = rbd_set_conf(state->cluster, conf, false);
		if (r < 0) {
			if (asprintf(reason, "error read default conf %m") == -1)
				*reason = NULL;
			result = false;
			goto rados_shutdown;
		}
	}

	rados_conf_set(state->cluster, "rbd_cache", "false");

	r = rados_connect(state->cluster);
	if (r < 0) {
		if (asprintf(reason, "error connect to rados %m") == -1)
			*reason = NULL;
		result = false;
		goto rados_shutdown;
	}

	r = rados_ioctx_create(state->cluster, pool, &state->io_ctx);
	if (r < 0) {
		if (asprintf(reason, "error opening pool %s", pool) == -1)
			*reason = NULL;
		result = false;
		goto rados_destroy;
	}

	r = rbd_open(state->io_ctx, state->name, &state->image, state->snap);  //open?
	if (r < 0) {
		if (asprintf(reason, "error reading header from %s", state->name) == -1)
			*reason = NULL;
		result = false;
		goto rados_destroy;
	}

rados_destroy:
	rados_ioctx_destroy(state->io_ctx);
rados_shutdown:
	rados_shutdown(state->cluster);
	free(state->snap);
free_state:
	free(state);
	return result;
}


static int tcmu_rbd_open(struct tcmu_device *dev)
{

	char pool[RBD_MAX_POOL_NAME_SIZE];
	char snap_buf[RBD_MAX_SNAP_NAME_SIZE];
	char conf[RBD_MAX_CONF_SIZE];
	char clientname_buf[RBD_MAX_CONF_SIZE];
	char *clientname;
	const char *config;
	struct tcmu_rbd_state *state;
	uint64_t size, rbd_size;
	int r;

	state = calloc(1, sizeof(*state));
	if (!state)
		return -ENOMEM;

	tcmu_set_dev_private(dev, state);

	config = strchr(tcmu_get_dev_cfgstring(dev), '/');
	dbgp("tcmu_rbd_open config %s\n", config);

	if (!config) {
		errp("no configuration found in cfgstring\n");
		r = -EINVAL;
		goto free_state;
	}
	config += 1; /* get past '/' */

	state->block_size = tcmu_get_attribute(dev, "hw_block_size");
	if (state->block_size == -1) {
		errp("Could not get hw_block_size\n");
		r = -EINVAL;
		goto free_state;
	}

	size = tcmu_get_device_size(dev);
	if (size == -1) {
		errp("Could not get device size\n");
		goto free_state;
	}
        state->num_lbas = size / state->block_size;

	if (rbd_parsename(config, pool, sizeof(pool),
			       snap_buf, sizeof(snap_buf),
			       state->name, sizeof(state->name),
			       conf, sizeof(conf)) < 0) {
		r = -EINVAL;
		goto free_state;
	}

	dbgp("rbd conf %s\n", conf);
	clientname = rbd_parse_clientname(conf, clientname_buf);

	dbgp("rbd client %s\n", clientname);
	r = rados_create(&state->cluster, clientname);
	if (r < 0) {
		errp("error initializing\n");
		goto free_state;
	}

	state->snap = NULL;
	if (snap_buf[0] != '\0') {
		state->snap = strdup(snap_buf);
		dbgp("rbd snap %s\n",state->snap);
	}

	if (strstr(conf, "conf=") == NULL) {
		/* try default location, but ignore failure */
		rados_conf_read_file(state->cluster, NULL);
	} else if (conf[0] != '\0') {
		r = rbd_set_conf(state->cluster, conf, true);
		if (r < 0) {
		       goto rados_shutdown;
	        }
	}

	if (conf[0] != '\0') {
		r = rbd_set_conf(state->cluster, conf, false);
		if (r < 0) {
			goto rados_shutdown;
		}
	}

	// set rbd_cache false
	rados_conf_set(state->cluster, "rbd_cache", "false");

	r = rados_connect(state->cluster);
	if (r < 0) {
		errp("error connecting\n");
		goto rados_shutdown;
	}

	r = rados_ioctx_create(state->cluster, pool, &state->io_ctx);
	if (r < 0) {
		errp("error opening pool %s\n", pool);
		goto rados_destroy;
	}

	r = rbd_open(state->io_ctx, state->name, &state->image, state->snap);
	if (r < 0) {
		errp("error reading header from %s\n", state->name);
		goto rados_destroy;
	}

	r = rbd_get_size(state->image, &rbd_size);
	if(r < 0) {
		errp("error get rbd_size %s\n", state->name);
		goto rados_destroy;
	}
	dbgp("rbd size %lld", rbd_size);

	if(size != rbd_size) {
		errp("device size and backing size disagree: "
		       "device %lld backing %lld\n",
		       size,
		       rbd_size);
		r = -EIO;
		goto rbd_close;
	}

	return 0;

rbd_close:
	rbd_close(state->image);
rados_destroy:
	rados_ioctx_destroy(state->io_ctx);
rados_shutdown:
	rados_shutdown(state->cluster);
	free(state->snap);
free_state:
	free(state);
	return r;
}

static void tcmu_rbd_close(struct tcmu_device *dev)
{
	struct tcmu_rbd_state *state = tcmu_get_dev_private(dev);

	rbd_close(state->image);
	rados_ioctx_destroy(state->io_ctx);
	free(state->snap);
	rados_shutdown(state->cluster);
	free(state);
}

static void rbd_finish_aio(rbd_completion_t complete, struct rbd_aio_cb *acb)
{
	struct tcmu_device *dev = acb->dev;
	struct tcmulib_cmd *cmd = acb->tcmulib_cmd;
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
	int64_t r;
	int tcmu_r;

	r = acb->ret = rbd_aio_get_return_value(complete);
	rbd_aio_release(complete);

	if (acb->rbd_aio_cmd != RBD_AIO_READ) {
		if (r < 0) {
			acb->ret = r;
			acb->error = 1;
		} else if (!acb->error) {
			acb->ret = acb->length;
		}
	} else {
		if (r < 0) {
			memset(acb->bounce, 0, acb->length);
			acb->ret = r;
			acb->error = 1;
		} else if (r < acb->length) {
			memset(acb->bounce+ r, 0, acb->length - r);
			if (!acb->error) {
				acb->ret = acb->length;
			}
		} else if (!acb->error) {
			acb->ret = r;
		}
	}

	if (acb->rbd_aio_cmd == RBD_AIO_READ) {
		tcmu_memcpy_into_iovec(iovec, iov_cnt, acb->bounce,
				       acb->length);
	}

	if (acb->bounce) {
		free(acb->bounce);
	}
	free(acb);

	if (!acb->error) {
		tcmu_r = SAM_STAT_GOOD;
	} else {
		tcmu_r = tcmu_set_sense_data(cmd->sense_buf, MEDIUM_ERROR,
					     ASC_READ_ERROR, NULL);
	}
	tcmulib_command_complete(dev, cmd, tcmu_r);
	tcmulib_processing_complete(dev);
}

static int rbd_aio_discard_wrapper(rbd_image_t image, uint64_t offset,
				   uint64_t length, rbd_completion_t complete)
{
#ifdef LIBRBD_SUPPORTS_DISCARD
	return rbd_aio_discard(image, offset, length, complete);
#else
	return -ENOTSUP;
#endif
}

static int rbd_aio_flush_wrapper(rbd_image_t image, rbd_completion_t complete)
{
#ifdef LIBRBD_SUPPORTS_AIO_FLUSH
	return rbd_aio_flush(image, complete);
#else
	return -ENOTSUP;
#endif
}

static int tcmu_rbd_start_aio(struct tcmu_device *dev,
			      struct tcmulib_cmd *cmd, uint64_t offset,
			      uint64_t length, int rbd_aio_cmd)
{
	struct tcmu_rbd_state *state = tcmu_get_dev_private(dev);
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
	struct rbd_aio_cb *acb;
	rbd_completion_t complete;
	char *buf;
	int r;

	acb = calloc(1, sizeof(*acb));
	if (!acb) {
		errp("Could not allocate acb\n");
		return -ENOMEM;
	}
	acb->rbd_aio_cmd = rbd_aio_cmd;
	acb->tcmulib_cmd = cmd;
	acb->length = length;
	acb->dev = dev;
	if (rbd_aio_cmd == RBD_AIO_DISCARD || rbd_aio_cmd == RBD_AIO_FLUSH) {
		acb->bounce = NULL;
	} else {
		acb->bounce = malloc(length);
		if (!acb->bounce) {
			errp("Could not allocate %d buf of length " PRIu64 "\n",
			      rbd_aio_cmd, length);
			r = -ENOMEM;
			goto free_acb;
		}
	}
	buf = acb->bounce;

	if (rbd_aio_cmd == RBD_AIO_WRITE) {
		tcmu_memcpy_from_iovec(acb->bounce, length, iovec, iov_cnt);
	}

	r = rbd_aio_create_completion(acb, (rbd_callback_t) rbd_finish_aio,
				       &complete);
	if (r < 0) {
		goto free_bounce;
	}

	switch (rbd_aio_cmd) {
	case RBD_AIO_WRITE:
		r = rbd_aio_write(state->image, offset, length, buf, complete);
		break;
	case RBD_AIO_READ:
		r = rbd_aio_read(state->image, offset, length, buf, complete);
		break;
	case RBD_AIO_DISCARD:
		r = rbd_aio_discard_wrapper(state->image, offset, length,
					    complete);
		break;
	case RBD_AIO_FLUSH:
		r = rbd_aio_flush_wrapper(state->image, complete);
		break;
	default:
		r = -EINVAL;
	}

	if (r < 0) {
		goto release_aio;
	}

    return 0;

release_aio:
	rbd_aio_release(complete);
free_bounce:
	if (buf)
		free(buf);
free_acb:
	free(acb);
	return r;
}

static int tcmu_rbd_unmap(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			  uint64_t length, struct iovec *iovec, size_t iov_cnt)
{
	struct tcmu_rbd_state *state = tcmu_get_dev_private(dev);
	char *buf, *curr;
	int r = 0;
	uint64_t unmap_len, offset;

	buf = calloc(1, length);
	if (!buf) {
		errp("Could not allocate unmap buf of length " PRIu64 "\n",
		     length);
		return -ENOMEM;
	}

	tcmu_memcpy_from_iovec(buf, length, iovec, iov_cnt);
	length -= 8;

	curr = buf;
	while (length >= 16) {
		offset = be64toh(*(uint64_t *)&curr[0]);
		unmap_len = be32toh(*(uint32_t *)&curr[8]);

		if (offset + unmap_len > state->num_lbas) {
			r = -ERANGE;
			goto free_buf;
		}

		r = tcmu_rbd_start_aio(dev, cmd, offset * state->block_size,
				       unmap_len * state->block_size,
				       RBD_AIO_DISCARD);
		length -= 16;
		curr += 16;
	}

free_buf:
	free(buf);
	return r;
}

static int set_medium_error(uint8_t *sense)
{
	return tcmu_set_sense_data(sense, MEDIUM_ERROR, ASC_READ_ERROR, NULL);
}

static int rbd_compare_and_write(struct tcmu_device *dev,
			      struct tcmulib_cmd *cmd, uint64_t offset,
			      uint64_t length, struct iovec *iovec,uint8_t *sense) {
	struct tcmu_rbd_state *state = tcmu_get_dev_private(dev);
	uint64_t tmplen;
	char *tmpbuf;
	int ret;
	int result = TCMU_ASYNC_HANDLED;
	uint32_t cmp_offset;

	tmplen = length / 2;

	tmpbuf = malloc(tmplen);
	if (!tmpbuf) {
		result = tcmu_set_sense_data(sense, HARDWARE_ERROR,
					     ASC_INTERNAL_TARGET_FAILURE, NULL);
		goto out;
	}

	ret = rbd_read(state->image, offset, tmplen, tmpbuf);
	if (ret != tmplen) {
		result = set_medium_error(sense);
		goto out;
	}

	cmp_offset = tcmu_compare_with_iovec(tmpbuf, iovec, tmplen);
	if (cmp_offset != -1) {
		result = tcmu_set_sense_data(sense, MISCOMPARE,
					     ASC_MISCOMPARE_DURING_VERIFY_OPERATION,
					     &cmp_offset);
		goto out;
	}

	free(tmpbuf);

	tcmu_seek_in_iovec(iovec, tmplen);

	ret = tcmu_rbd_start_aio(dev, cmd, offset, tmplen, RBD_AIO_WRITE);

	if (ret < 0) {
		errp("Error on write %x\n", tmplen);
		result = set_medium_error(sense);
	}
out:
	if(tmpbuf)
		free(tmpbuf);
	return result;
}

static int tcmu_rbd_handle_cmd(struct tcmu_device *dev,
			       struct tcmulib_cmd *tcmulib_cmd)
{
	uint8_t *cdb = tcmulib_cmd->cdb;
	uint8_t *sense = tcmulib_cmd->sense_buf;
	struct tcmu_rbd_state *state = tcmu_get_dev_private(dev);
	struct iovec *iovec = tcmulib_cmd->iovec;
	size_t iov_cnt = tcmulib_cmd->iov_cnt;
	uint8_t cmd;
	int r = SAM_STAT_GOOD;
	uint64_t offset = state->block_size * tcmu_get_lba(cdb);
	uint64_t length	= state->block_size * tcmu_get_xfer_length(cdb);

        cmd = cdb[0];

	dbgp("tcmu_rbd_handle_cmd cmd %x offset %12lld, length %12lld, block_size %3d\n", cmd,offset, length, state->block_size);

        switch (cmd) {
        case INQUIRY:
                return tcmu_emulate_inquiry(dev, cdb, iovec, iov_cnt, sense);
        case TEST_UNIT_READY:
		return tcmu_emulate_test_unit_ready(cdb, iovec, iov_cnt, sense);
	case SERVICE_ACTION_IN_16:
		if (cdb[1] == READ_CAPACITY_16)
			return tcmu_emulate_read_capacity_16(state->num_lbas,
						state->block_size,
						cdb, iovec, iov_cnt, sense);
		else
			return TCMU_NOT_HANDLED;
	case MODE_SENSE:
	case MODE_SENSE_10:
		return tcmu_emulate_mode_sense(cdb, iovec, iov_cnt, sense);
	case MODE_SELECT:
	case MODE_SELECT_10:
		return tcmu_emulate_mode_select(cdb, iovec, iov_cnt, sense);
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		r = tcmu_rbd_start_aio(dev, tcmulib_cmd, offset, length,
				       RBD_AIO_READ);
		break;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		r = tcmu_rbd_start_aio(dev, tcmulib_cmd, offset, length,
				       RBD_AIO_WRITE);
		break;
	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16:
		if (cdb[1] & 0x2)
			return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
						   ASC_INVALID_FIELD_IN_CDB,
						   NULL);
		r = tcmu_rbd_start_aio(dev, tcmulib_cmd, offset, length,
				       RBD_AIO_FLUSH);
		break;
	case COMPARE_AND_WRITE:
		return rbd_compare_and_write(dev, tcmulib_cmd, offset, length, iovec, sense);
	case UNMAP:
		if (length == 0) {
			return SAM_STAT_GOOD;
		}

		if (length < 8 || (length > 8 && length < 24)) {
			return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
						ASC_PARAMETER_LIST_LENGTH_ERROR,
						NULL);
		}
		r = tcmu_rbd_unmap(dev, tcmulib_cmd, length, iovec, iov_cnt);
		break;
	default:
		dbgp("unhandled cmd %x\n", cmd);
		return TCMU_NOT_HANDLED;
	}

	switch (r) {
	case -EINVAL:
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					ASC_INVALID_FIELD_IN_PARAMETER_LIST,
					NULL);
	case -ERANGE:
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					ASC_LBA_OUT_OF_RANGE, NULL);
	case -ENOMEM:
		/* ??? */
		return SAM_STAT_TASK_SET_FULL;
	default:
		if (r < 0) {
			return tcmu_set_sense_data(sense, MEDIUM_ERROR,
						   ASC_READ_ERROR, NULL);
		}
		/* Success. Fall through */
	}

	return TCMU_ASYNC_HANDLED;
}

/*
 * When specifying the image filename use:
 *
 * rbd/poolname/devicename[@snapshotname][:option1=value1[:option2=value2...]]
 *
 * poolname must be the name of an existing rados pool.
 *
 * devicename is the name of the rbd image.
 *
 * Each option given is used to configure rados, and may be any valid
 * Ceph option, "id", or "conf".
 *
 * The "id" option indicates what user we should authenticate as to
 * the Ceph cluster.  If it is excluded we will use the Ceph default
 * (normally 'admin').
 *
 * The "conf" option specifies a Ceph configuration file to read.  If
 * it is not specified, we will read from the default Ceph locations
 * (e.g., /etc/ceph/ceph.conf).  To avoid reading _any_ configuration
 * file, specify conf=/dev/NULL.
 *
 * Configuration values containing :, @, or = can be escaped with a
 * leading "\".
 */
static const char tcmu_rbd_cfg_desc[] =
	"RBD config string is of the form:\n"
	"poolname/devicename[@snapshotname][:option1=value1[:option2=value2...]\n"
	"where:\n"
	"poolname:	Existing RADOS pool\n"
	"devicename:	Name of the RBD image\n"
	"option:	Ceph conf or id option\n";

struct tcmur_handler tcmu_rbd_handler = {
        .name		= "Ceph RBD handler",
        .subtype	= "rbd",
        .cfg_desc	= tcmu_rbd_cfg_desc,
        .check_config	= tcmu_rbd_check_config,
        .open		= tcmu_rbd_open,
        .close		= tcmu_rbd_close,
        .handle_cmd	= tcmu_rbd_handle_cmd,
};

void handler_init(void)
{
        tcmur_register_handler(&tcmu_rbd_handler);
}
