/*
 * Copyright (c) 2015 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
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
#include <inttypes.h>
#include <scsi/scsi.h>
#include <pthread.h>
#include <glusterfs/api/glfs.h>
#include "darray.h"

#include "tcmu-runner.h"
#include "libtcmu.h"
#include "tcmur_device.h"
#include "tcmur_cmd_handler.h"
#include "version.h"

#define ALLOWED_BSOFLAGS (O_DIRECT | O_RDWR | O_LARGEFILE)

#define GLUSTER_PORT "24007"
#define TCMU_GLFS_LOG_FILENAME "tcmu-runner-glfs.log"  /* MAX 32 CHAR */
#define TCMU_GLFS_DEBUG_LEVEL  7

/* cache protection */
pthread_mutex_t glfs_lock;

#if GFAPI_VERSION766
#define GF_ENFORCE_MANDATORY_LOCK "trusted.glusterfs.enforce-mandatory-lock"
#endif

typedef enum gluster_transport {
	GLUSTER_TRANSPORT_TCP,
	GLUSTER_TRANSPORT_UNIX,
	GLUSTER_TRANSPORT_RDMA,
	GLUSTER_TRANSPORT__MAX,
} gluster_transport;

typedef struct unix_sockaddr {
	char *socket;
} unix_sockaddr;

typedef struct inet_sockaddr {
	char *addr;
	char *port;
} inet_sockaddr;

typedef struct gluster_hostdef {
	gluster_transport type;
	union { /* union tag is @type */
		unix_sockaddr uds;
		inet_sockaddr inet;
	} u;
} gluster_hostdef;

typedef struct gluster_server {
	char *volname;     /* volume name*/
	char *path;        /* path of file in the volume */
	gluster_hostdef *server; /* gluster server definition */
} gluster_server;

struct glfs_state {
	glfs_t *fs;
	glfs_fd_t *gfd;
	gluster_server *hosts;
	bool no_fencing;

	/*
	 * Current tcmu helper API reports WCE=1, but doesn't
	 * implement inquiry VPD 0xb2, so clients will not know UNMAP
	 * or WRITE_SAME are supported. TODO: fix this
	 */
};

typedef struct glfs_cbk_cookie {
	struct tcmu_device *dev;
	struct tcmur_cmd *tcmur_cmd;
	size_t length;
	enum {
		TCMU_GLFS_READ  = 1,
		TCMU_GLFS_WRITE = 2,
		TCMU_GLFS_FLUSH = 3,
		TCMU_GLFS_DISCARD = 4,
		TCMU_GLFS_WRITESAME = 5
	} op;
} glfs_cbk_cookie;

struct gluster_cacheconn {
	char *volname;
	gluster_hostdef *server;
	glfs_t *fs;
	darray(char *) cfgstring;
} gluster_cacheconn;

static darray(struct gluster_cacheconn *) glfs_cache = darray_new();

const char *const gluster_transport_lookup[] = {
	[GLUSTER_TRANSPORT_TCP] = "tcp",
	[GLUSTER_TRANSPORT_UNIX] = "unix",
	[GLUSTER_TRANSPORT_RDMA] = "rdma",
	[GLUSTER_TRANSPORT__MAX] = NULL,
};

static void gluster_free_host(gluster_hostdef *host)
{
	if(!host)
		return;

	switch (host->type) {
	case GLUSTER_TRANSPORT_UNIX:
		free(host->u.uds.socket);
		break;
	case GLUSTER_TRANSPORT_TCP:
	case GLUSTER_TRANSPORT_RDMA:
		free(host->u.inet.addr);
		free(host->u.inet.port);
		break;
	case GLUSTER_TRANSPORT__MAX:
		break;
	}
}

static bool
gluster_compare_hosts(gluster_hostdef *src_server, gluster_hostdef *dst_server)
{
	if (src_server->type != dst_server->type)
		return false;

	switch (src_server->type) {
	case GLUSTER_TRANSPORT_UNIX:
		if (!strcmp(src_server->u.uds.socket, dst_server->u.uds.socket))
			return true;
		break;
	case GLUSTER_TRANSPORT_TCP:
	case GLUSTER_TRANSPORT_RDMA:
		if (!strcmp(src_server->u.inet.addr, dst_server->u.inet.addr)
				&&
			!strcmp(src_server->u.inet.port, dst_server->u.inet.port))
			return true;
		break;
	case GLUSTER_TRANSPORT__MAX:
		break;
	}

	return false;
}

static int gluster_cache_add(gluster_server *dst, glfs_t *fs, char* cfgstring)
{
	struct gluster_cacheconn *entry;
	char* cfg_copy = NULL;

	entry = calloc(1, sizeof(gluster_cacheconn));
	if (!entry)
		goto error;

	entry->volname = strdup(dst->volname);

	entry->server = calloc(1, sizeof(gluster_hostdef));
	if (!entry->server)
		goto free_entry;

	entry->server->type = dst->server->type;

	if (entry->server->type == GLUSTER_TRANSPORT_UNIX) {
		entry->server->u.uds.socket = strdup(dst->server->u.uds.socket);
	} else {
		entry->server->u.inet.addr = strdup(dst->server->u.inet.addr);
		entry->server->u.inet.port = strdup(dst->server->u.inet.port);
	}

	entry->fs = fs;

	cfg_copy = strdup(cfgstring);
	darray_init(entry->cfgstring);
	darray_append(entry->cfgstring, cfg_copy);

	darray_append(glfs_cache, entry);

	return 0;

free_entry:
	if (entry->volname)
		free(entry->volname);
	free(entry);
error:
	return -1;
}

static bool tcmu_glfs_update_logdir(void)
{
	struct gluster_cacheconn **entry;
	char logfilepath[PATH_MAX];
	int ret;

	darray_foreach(entry, glfs_cache) {
		ret = tcmu_make_absolute_logfile(logfilepath, TCMU_GLFS_LOG_FILENAME);
		if (ret < 0) {
			tcmu_err("tcmu_make_absolute_logfile failed: %d\n", ret);
			return false;
		}

		if (glfs_set_logging((*entry)->fs, logfilepath, TCMU_GLFS_DEBUG_LEVEL)) {
			tcmu_err("glfs_set_logging() on %s failed[%s]",
				 (*entry)->volname, strerror(errno));
			return false;
		}
	}

	return true;
}

static glfs_t* gluster_cache_query(gluster_server *dst, char *cfgstring)
{
	struct gluster_cacheconn **entry;
	char** config;
	char* cfg_copy = NULL;
	bool cfgmatch = false;

	darray_foreach(entry, glfs_cache) {
		if (strcmp((*entry)->volname, dst->volname))
			continue;
		if (gluster_compare_hosts((*entry)->server, dst->server)) {

			darray_foreach(config, (*entry)->cfgstring) {
				if (!strcmp(*config, cfgstring)) {
					cfgmatch = true;
					break;
				}
			}
			if (!cfgmatch) {
				cfg_copy = strdup(cfgstring);
				darray_append((*entry)->cfgstring, cfg_copy);
			}
			return (*entry)->fs;
		}
	}

	return NULL;
}

static void gluster_cache_refresh(glfs_t *fs, const char *cfgstring)
{
	struct gluster_cacheconn **entry;
	char** config;
	size_t i = 0;
	size_t j = 0;

	if (!fs)
		return;

	darray_foreach(entry, glfs_cache) {
		if ((*entry)->fs == fs) {
			if (cfgstring) {
				darray_foreach(config, (*entry)->cfgstring) {
					if (!strcmp(*config, cfgstring)) {
						free(*config);
						darray_remove((*entry)->cfgstring, j);
						break;
					}
					j++;
				}
			}

			if (darray_size((*entry)->cfgstring))
				return;

			free((*entry)->volname);
			glfs_fini((*entry)->fs);
			(*entry)->fs = NULL;
			gluster_free_host((*entry)->server);
			free((*entry)->server);
			(*entry)->server = NULL;
			free((*entry));

			darray_remove(glfs_cache, i);
			return;
		} else {
			i++;
		}
	}
}

static void gluster_thread_cleanup(void *arg)
{
	pthread_mutex_unlock(arg);
}

static int gluster_cache_query_or_add(struct tcmu_device *dev,
                                      glfs_t **fs, gluster_server *entry,
                                      char *config, bool *init)
{
	int ret = -1;

	pthread_cleanup_push(gluster_thread_cleanup, &glfs_lock);
	pthread_mutex_lock(&glfs_lock);

	*fs = gluster_cache_query(entry, config);
	if (*fs) {
		*init = false;
		ret = 0;
		goto out;
	}

	*fs = glfs_new(entry->volname);
	if (!*fs) {
		tcmu_dev_err(dev, "glfs_new(vol=%s) failed: %m\n", entry->volname);
		goto out;
	}

	ret = gluster_cache_add(entry, *fs, config);
	if (ret) {
		tcmu_dev_err(dev, "gluster_cache_add(vol=%s, config=%s) failed: %m\n",
		             entry->volname, config);
		glfs_fini(*fs);
		*fs = NULL;
		goto out;
	}

out:
	pthread_mutex_unlock(&glfs_lock);
	pthread_cleanup_pop(0);

	return ret;
}

static void gluster_free_server(gluster_server **hosts)
{
	if (!*hosts)
		return;
	free((*hosts)->volname);
	free((*hosts)->path);

	gluster_free_host((*hosts)->server);
	free((*hosts)->server);
	(*hosts)->server = NULL;
	free(*hosts);
	*hosts = NULL;
}

/*
 * Break image string into server, volume, and path components.
 * Returns -1 on failure.
 */
static int parse_imagepath(char *cfgstring, gluster_server **hosts)
{
	gluster_server *entry = NULL;
	char *origp = strdup(cfgstring);
	char *p, *sep;

	if (!origp)
		goto fail;

	/* part before '@' is the volume name */
	p = origp;
	sep = strchr(p, '@');
	if (!sep)
		goto fail;

	*hosts = calloc(1, sizeof(gluster_server));
	if (!hosts)
		goto fail;
	entry = *hosts;

	entry->server = calloc(1, sizeof(gluster_hostdef));
	if (!entry->server)
		goto fail;

	*sep = '\0';
	entry->volname = strdup(p);
	if (!entry->volname)
		goto fail;

	/* part between '@' and 1st '/' is the server name */
	p = sep + 1;
	sep = strchr(p, '/');
	if (!sep)
		goto fail;

	*sep = '\0';
	entry->server->type = GLUSTER_TRANSPORT_TCP; /* FIXME: Get type dynamically */
	entry->server->u.inet.addr = strdup(p);
	if (!entry->server->u.inet.addr)
		goto fail;
	entry->server->u.inet.port = strdup(GLUSTER_PORT); /* FIXME: Get port dynamically */

	/* The rest is the path name */
	p = sep + 1;
	entry->path = strdup(p);
	if (!entry->path)
		goto fail;

	if (entry->server->type == GLUSTER_TRANSPORT_UNIX) {
		if (!strlen(entry->server->u.uds.socket) ||
		    !strlen(entry->volname) || !strlen(entry->path))
			goto fail;
	} else {
		if (!strlen(entry->server->u.inet.addr) ||
		    !strlen(entry->volname) || !strlen(entry->path))
			goto fail;
	}

	free(origp);

	return 0;

fail:
	gluster_free_server(hosts);
	free(origp);

	return -1;
}

static glfs_t* tcmu_create_glfs_object(struct tcmu_device *dev,
                                       char *config, gluster_server **hosts)
{
	gluster_server *entry = NULL;
	char logfilepath[PATH_MAX];
	glfs_t *fs =  NULL;
	int ret = -1;
	bool init = true;

	if (parse_imagepath(config, hosts) == -1) {
		tcmu_dev_err(dev, "hostaddr, volname, or path missing in %s\n",
		             config);
		goto fail;
	}
	entry = *hosts;

	ret = gluster_cache_query_or_add(dev, &fs, entry, config, &init);
	if (ret) {
		tcmu_dev_err(dev, "gluster_cache_query_or_add(vol=%s, config=%s) failed\n",
		             entry->volname, config);
		goto fail;
	}

	if (!init)
		return fs;

	ret = glfs_set_volfile_server(fs,
				gluster_transport_lookup[entry->server->type],
				entry->server->u.inet.addr,
				atoi(entry->server->u.inet.port));
	if (ret) {
		tcmu_dev_err(dev, "glfs_set_volfile_server(vol=%s, addr=%s) failed: %m\n",
		             entry->volname, entry->server->u.inet.addr);
		goto unref;
	}

	ret = tcmu_make_absolute_logfile(logfilepath, TCMU_GLFS_LOG_FILENAME);
	if (ret < 0) {
		tcmu_dev_err(dev, "tcmu_make_absolute_logfile failed: %d\n", ret);
		goto unref;
	}

	ret = glfs_set_logging(fs, logfilepath, TCMU_GLFS_DEBUG_LEVEL);
	if (ret < 0) {
		tcmu_dev_err(dev, "glfs_set_logging(vol=%s, path=%s) failed: %m\n",
		             entry->volname, logfilepath);
		goto unref;
	}

	ret = glfs_init(fs);
	if (ret) {
		tcmu_dev_err(dev, "glfs_init(vol=%s) failed: %m\n", entry->volname);
		goto unref;
	}

	return fs;

unref:
	gluster_cache_refresh(fs, config);

fail:
	gluster_free_server(hosts);
	return NULL;
}

static char* tcmu_get_path( struct tcmu_device *dev)
{
	char *config;

	config = strchr(tcmu_dev_get_cfgstring(dev), '/');
	if (!config) {
		tcmu_dev_err(dev, "no configuration found in cfgstring\n");
		return NULL;
	}
	config += 1; /* get past '/' */

	return config;
}

static int tcmu_glfs_open(struct tcmu_device *dev, bool reopen)
{
	struct glfs_state *gfsp;
	char *config;
	struct stat st;
	int ret = -EIO;
	long long dev_size;
	uint32_t block_size = tcmu_dev_get_block_size(dev);

	gfsp = calloc(1, sizeof(*gfsp));
	if (!gfsp)
		return -ENOMEM;

	tcmur_dev_set_private(dev, gfsp);
	tcmu_dev_set_write_cache_enabled(dev, 1);

	config = tcmu_get_path(dev);
	if (!config)
		goto fail;

	gfsp->fs = tcmu_create_glfs_object(dev, config, &gfsp->hosts);
	if (!gfsp->fs) {
		tcmu_dev_err(dev, "tcmu_create_glfs_object(config=%s) failed\n", config);
		goto fail;
	}

	gfsp->gfd = glfs_open(gfsp->fs, gfsp->hosts->path, ALLOWED_BSOFLAGS);
	if (!gfsp->gfd) {
		tcmu_dev_err(dev, "glfs_open(vol=%s, file=%s) failed: %m\n",
		             gfsp->hosts->volname, gfsp->hosts->path);
		goto unref;
	}

#if GFAPI_VERSION766
	ret = glfs_fsetxattr(gfsp->gfd, GF_ENFORCE_MANDATORY_LOCK, "set", 4, 0);
	if (ret) {
		if (errno == EINVAL) {
			gfsp->no_fencing = true;
		} else {
			tcmu_dev_err(dev,"glfs_fsetxattr failed: %m\n");
			goto close;
		}
	}
#endif

	ret = glfs_lstat(gfsp->fs, gfsp->hosts->path, &st);
	if (ret) {
		tcmu_dev_warn(dev, "glfs_lstat failed: %m\n");
		goto close;
	}

	dev_size = tcmu_dev_get_num_lbas(dev) * block_size;
	if (st.st_size != dev_size) {
		/*
		 * The glfs allows the backend file size not to align
		 * to the block_size. But the dev_size here in tcmu-runner
		 * will round down and align it to the block_size.
		 */
		if (round_down(st.st_size, block_size) == dev_size)
			goto out;

		if (reopen)
			goto out;

		tcmu_dev_warn(dev,
			      "device size (%lld) and backing file size (%lld) not matching, updating it to kernel\n",
			      (long long)dev_size, (long long) st.st_size);

		/* Update the device size in kernel. */
		ret = tcmur_dev_update_size(dev, st.st_size);
		if (ret)
			goto close;

		tcmu_dev_info(dev, "loaded with size (%lld)\n", (long long) st.st_size);
	}

out:
	return 0;
close:
	glfs_close(gfsp->gfd);
unref:
	gluster_cache_refresh(gfsp->fs, tcmu_get_path(dev));
	gluster_free_server(&gfsp->hosts);
fail:
	free(gfsp);

	return ret;
}

static void tcmu_glfs_close(struct tcmu_device *dev)
{
	struct glfs_state *gfsp = tcmur_dev_get_private(dev);

	glfs_close(gfsp->gfd);
	gluster_cache_refresh(gfsp->fs, tcmu_get_path(dev));
	gluster_free_server(&gfsp->hosts);
	free(gfsp);
}

#if GFAPI_VERSION760
static void glfs_async_cbk(glfs_fd_t *fd, ssize_t ret,
			   struct glfs_stat *prestat,
			   struct glfs_stat *poststat,
			   void *data)
#else
static void glfs_async_cbk(glfs_fd_t *fd, ssize_t ret, void *data)
#endif
{
	glfs_cbk_cookie *cookie = data;
	struct tcmu_device *dev = cookie->dev;
	struct tcmur_cmd *tcmur_cmd = cookie->tcmur_cmd;
#if GFAPI_VERSION766
	struct glfs_state *gfsp = tcmur_dev_get_private(dev);
#endif
	size_t length = cookie->length;
	int err = -errno;

	if (ret < 0) {
		switch (err) {
		case -ETIMEDOUT:
			/*
			 * TIMEDOUT is a scenario where the fop can
			 * not reach the server for 30 minutes.
			 */
			tcmu_dev_err(dev, "Timing out cmd after 30 minutes.\n");

			tcmu_notify_cmd_timed_out(dev, true);
			ret = TCMU_STS_TIMEOUT;
			break;
#if GFAPI_VERSION766
		case -EAGAIN:
		case -EBUSY:
		case -ENOTCONN:
			/*
			 * The lock maybe preemted and then any IO to
			 * land on the file without a lock will be
			 * rejected with EBUSY.
			 *
			 * And if local is disconnected, we should get
			 * ENOTCONN for further requests. But if the
			 * connection is reestablished and at the same
			 * time another client has taken the lock we
			 * will get EBUSY too.
			 */
			if (!gfsp->no_fencing) {
				tcmu_dev_dbg(dev, "failed with errno %d.\n", err);
				tcmu_notify_lock_lost(dev);
				ret = TCMU_STS_BUSY;
				break;
			}
#endif
		default:
			tcmu_dev_dbg(dev, "failed with errno %d.\n", err);
			ret = TCMU_STS_HW_ERR;
		}
	} else if (ret != length) {
		tcmu_dev_dbg(dev, "ret(%zu) != length(%zu).\n", ret, length);

		/* Read/write/flush failed */
		switch (cookie->op) {
		case TCMU_GLFS_READ:
			/* ENOENT for READ operation means EOF,
			 * see glusterfs commit 9fe5c6d3
			 */
			if (err == -ENOENT) {
				ret = TCMU_STS_OK;
				break;
			}
			ret = TCMU_STS_RD_ERR;
			break;
		case TCMU_GLFS_WRITE:
		case TCMU_GLFS_FLUSH:
		case TCMU_GLFS_DISCARD:
		case TCMU_GLFS_WRITESAME:
			ret = TCMU_STS_WR_ERR;
			break;
		}
	} else {
		ret = TCMU_STS_OK;
	}

	tcmur_cmd_complete(dev, tcmur_cmd, ret);
	free(cookie);
}

static int tcmu_glfs_read(struct tcmu_device *dev,
                          struct tcmur_cmd *tcmur_cmd,
                          struct iovec *iov, size_t iov_cnt,
                          size_t length, off_t offset)
{
	struct glfs_state *state = tcmur_dev_get_private(dev);
	glfs_cbk_cookie *cookie;

	cookie = calloc(1, sizeof(*cookie));
	if (!cookie) {
		tcmu_dev_err(dev, "Could not allocate cookie: %m\n");
		goto out;
	}
	cookie->dev = dev;
	cookie->tcmur_cmd = tcmur_cmd;
	cookie->length = length;
	cookie->op = TCMU_GLFS_READ;

	if (glfs_preadv_async(state->gfd, iov, iov_cnt, offset, SEEK_SET,
	                      glfs_async_cbk, cookie) < 0) {
		tcmu_dev_err(dev, "glfs_preadv_async(vol=%s, file=%s) failed: %m\n",
		             state->hosts->volname, state->hosts->path);
		goto out;
	}

	return TCMU_STS_OK;

out:
	free(cookie);
	return TCMU_STS_NO_RESOURCE;
}

static int tcmu_glfs_write(struct tcmu_device *dev,
                           struct tcmur_cmd *tcmur_cmd,
                           struct iovec *iov, size_t iov_cnt,
                           size_t length, off_t offset)
{
	struct glfs_state *state = tcmur_dev_get_private(dev);
	glfs_cbk_cookie *cookie;

	cookie = calloc(1, sizeof(*cookie));
	if (!cookie) {
		tcmu_dev_err(dev, "Could not allocate cookie: %m\n");
		goto out;
	}
	cookie->dev = dev;
	cookie->tcmur_cmd = tcmur_cmd;
	cookie->length = length;
	cookie->op = TCMU_GLFS_WRITE;

	if (glfs_pwritev_async(state->gfd, iov, iov_cnt, offset,
	                       ALLOWED_BSOFLAGS, glfs_async_cbk, cookie) < 0) {
		tcmu_dev_err(dev, "glfs_pwritev_async(vol=%s, file=%s) failed: %m\n",
		             state->hosts->volname, state->hosts->path);
		goto out;
	}

	return TCMU_STS_OK;

out:
	free(cookie);
	return TCMU_STS_NO_RESOURCE;
}

static int tcmu_glfs_reconfig(struct tcmu_device *dev,
                              struct tcmulib_cfg_info *cfg)
{
	struct glfs_state *gfsp = tcmur_dev_get_private(dev);
	struct stat st;
	int ret = -EIO;

	switch (cfg->type) {
	case TCMULIB_CFG_DEV_SIZE:
		ret = glfs_lstat(gfsp->fs, gfsp->hosts->path, &st);
		if (ret) {
			tcmu_dev_warn(dev, "glfs_lstat failed: %m\n");
			tcmu_notify_conn_lost(dev);

			/* Let the targetcli command return success */
			ret = 0;
		} else if (st.st_size != cfg->data.dev_size) {
			/*
			 * Currently we cannot update the size to kernel here,
			 * because it will be overrided by kernel with the old
			 * value after it gets the genl reply.
			 */
			tcmu_dev_warn(dev,
				      "device size (%lld) and backing file size (%lld) not matching, and ignoring it\n",
				      (long long)cfg->data.dev_size, (long long) st.st_size);
			return -EINVAL;
		}
		return ret;
	case TCMULIB_CFG_DEV_CFGSTR:
	case TCMULIB_CFG_WRITE_CACHE:
	default:
		return -EOPNOTSUPP;
	}
}

static int tcmu_glfs_flush(struct tcmu_device *dev,
                           struct tcmur_cmd *tcmur_cmd)
{
	struct glfs_state *state = tcmur_dev_get_private(dev);
	glfs_cbk_cookie *cookie;

	cookie = calloc(1, sizeof(*cookie));
	if (!cookie) {
		tcmu_dev_err(dev, "Could not allocate cookie: %m\n");
		goto out;
	}
	cookie->dev = dev;
	cookie->tcmur_cmd = tcmur_cmd;
	cookie->length = 0;
	cookie->op = TCMU_GLFS_FLUSH;

	if (glfs_fdatasync_async(state->gfd, glfs_async_cbk, cookie) < 0) {
		tcmu_dev_err(dev, "glfs_fdatasync_async(vol=%s, file=%s) failed: %m\n",
		             state->hosts->volname, state->hosts->path);
		goto out;
	}

	return TCMU_STS_OK;

out:
	free(cookie);
	return TCMU_STS_NO_RESOURCE;
}

static int tcmu_glfs_discard(struct tcmu_device *dev,
			     struct tcmur_cmd *tcmur_cmd,
                             uint64_t offset, uint64_t length)
{
	struct glfs_state *state = tcmur_dev_get_private(dev);
	glfs_cbk_cookie *cookie;
	ssize_t ret;

	cookie = calloc(1, sizeof(*cookie));
	if (!cookie) {
		tcmu_dev_err(dev, "Could not allocate cookie: %m\n");
		goto out;
	}
	cookie->dev = dev;
	cookie->tcmur_cmd = tcmur_cmd;
	cookie->length = 0;
	cookie->op = TCMU_GLFS_DISCARD;

	ret = glfs_discard_async(state->gfd, offset, length, glfs_async_cbk, cookie);
	if (ret < 0) {
		tcmu_dev_err(dev, "glfs_discard_async(vol=%s, file=%s) failed: %m\n",
		             state->hosts->volname, state->hosts->path);
		goto out;
	}

	return TCMU_STS_OK;

out:
	free(cookie);
	return TCMU_STS_NO_RESOURCE;
}

static int tcmu_glfs_writesame(struct tcmu_device *dev,
			       struct tcmur_cmd *tcmur_cmd,
			       uint64_t offset, uint64_t length,
			       struct iovec *iov, size_t iov_cnt)
{
	struct glfs_state *state = tcmur_dev_get_private(dev);
	glfs_cbk_cookie *cookie;
	ssize_t ret;

	if (!tcmu_iovec_zeroed(iov, iov_cnt)) {
		tcmu_dev_warn(dev,
			      "Received none zeroed data, will fall back to writesame emulator instead.\n");
		return TCMU_STS_NOT_HANDLED;
	}

	cookie = calloc(1, sizeof(*cookie));
	if (!cookie) {
		tcmu_dev_err(dev, "Could not allocate cookie: %m\n");
		goto out;
	}
	cookie->dev = dev;
	cookie->tcmur_cmd = tcmur_cmd;
	cookie->length = 0;
	cookie->op = TCMU_GLFS_WRITESAME;

	ret = glfs_zerofill_async(state->gfd, offset, length, glfs_async_cbk, cookie);
	if (ret < 0) {
		tcmu_dev_err(dev, "glfs_zerofill_async(vol=%s, file=%s) failed: %m\n",
		             state->hosts->volname, state->hosts->path);
		goto out;
	}

	return TCMU_STS_OK;

out:
	free(cookie);
	return TCMU_STS_NO_RESOURCE;
}

/*
 * Return scsi status or TCMU_STS_NOT_HANDLED
 */
static int tcmu_glfs_handle_cmd(struct tcmu_device *dev,
				struct tcmur_cmd *tcmur_cmd)
{
	struct tcmulib_cmd *cmd = tcmur_cmd->lib_cmd;
	uint8_t *cdb = cmd->cdb;
	int ret;

	switch(cdb[0]) {
	case WRITE_SAME:
	case WRITE_SAME_16:
		ret = tcmur_handle_writesame(dev, tcmur_cmd,
					     tcmu_glfs_writesame);
		break;
	default:
		ret = TCMU_STS_NOT_HANDLED;
	}

	return ret;
}

#if GFAPI_VERSION766
static int tcmu_glfs_to_sts(int rc)
{
	switch (rc) {
	case 0:
		return TCMU_STS_OK;
	case -ENOTCONN:
		return TCMU_STS_FENCED;
	default:
		return TCMU_STS_HW_ERR;
	}
}

static int tcmu_glfs_lock(struct tcmu_device *dev, uint16_t tag)
{
	struct glfs_state *state = tcmur_dev_get_private(dev);
	struct flock lock;
	int ret;

	if (state->no_fencing)
		return 0;

	lock.l_type = F_WRLCK | F_RDLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	ret = glfs_file_lock(state->gfd, F_SETLK, &lock, GLFS_LK_MANDATORY);
	if (ret)
		tcmu_dev_err(dev, "glfs_file_lock failed: %m\n");

	return tcmu_glfs_to_sts(ret);
}

static int tcmu_glfs_unlock(struct tcmu_device *dev)
{
	struct glfs_state *state = tcmur_dev_get_private(dev);
	struct flock lock;
	int ret;

	if (state->no_fencing)
		return 0;

	lock.l_type = F_UNLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	ret = glfs_file_lock(state->gfd, F_SETLK, &lock, GLFS_LK_MANDATORY);
	if (ret)
		tcmu_dev_err(dev, "glfs_file_lock failed: %m\n");

	return tcmu_glfs_to_sts(ret);
}
#endif

/*
 * For backstore creation
 *
 * Specify volume, hostname and filepath e.g,
 *
 * $ targetcli /backstores/user:glfs create $blockname $size \
 *   $volume@$hostname/$filepath
 *
 * volume: must be the name of an existing Gluster volume.
 * hostname: the hostname or the IP address
 * filepath: is the path of the backing file in Gluster volume.
 */
static const char glfs_cfg_desc[] =
	"glfs config string is of the form:\n"
	"\"$volume@$hostname/$filepath\"\n"
	"where:\n"
	"  volume:    The volume on the Gluster server\n"
	"  hostname:  The server's hostname\n"
	"  filepath:  The path of the backing file";

struct tcmur_handler glfs_handler = {
	.name           = "Gluster glfs handler",
	.subtype        = "glfs",
	.cfg_desc       = glfs_cfg_desc,

	.open           = tcmu_glfs_open,
	.close          = tcmu_glfs_close,
	.read           = tcmu_glfs_read,
	.write          = tcmu_glfs_write,
	.reconfig       = tcmu_glfs_reconfig,
	.flush          = tcmu_glfs_flush,
	.unmap          = tcmu_glfs_discard,
	.handle_cmd     = tcmu_glfs_handle_cmd,

	.update_logdir  = tcmu_glfs_update_logdir,

#if GFAPI_VERSION766
	.lock           = tcmu_glfs_lock,
	.unlock         = tcmu_glfs_unlock,
#endif
};

/* Entry point must be named "handler_init". */
int handler_init(void)
{
	int ret;

	ret = pthread_mutex_init(&glfs_lock, NULL);
	if (ret != 0)
		return -1;

	ret = tcmur_register_handler(&glfs_handler);
	if (ret != 0)
		pthread_mutex_destroy(&glfs_lock);

	return ret;
}
