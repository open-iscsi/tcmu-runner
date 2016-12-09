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
#include "darray.h"

#include "tcmu-runner.h"

#define ALLOWED_BSOFLAGS (O_SYNC | O_DIRECT | O_RDWR | O_LARGEFILE)

#define GLUSTER_PORT "24007"

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

	/*
	 * Current tcmu helper API reports WCE=1, but doesn't
	 * implement inquiry VPD 0xb2, so clients will not know UNMAP
	 * or WRITE_SAME are supported. TODO: fix this
	 */
};

struct gluster_cacheconn {
    char *volname;
	gluster_hostdef *server;
	glfs_t *fs;
	darray(char *) cfgstring;
} gluster_cacheconn;

static darray(struct gluster_cacheconn) cache = darray_new();


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
	struct gluster_cacheconn *entry = NULL;
	char* cfg_copy = NULL;

	entry = calloc(1, sizeof(gluster_cacheconn));
	if (!entry)
		goto error;

	entry->volname = strdup(dst->volname);

	entry->server = calloc(1, sizeof(gluster_hostdef));
	if (!entry)
		goto error;

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

	darray_append(cache, *entry);

	return 0;

 error:
	return -1;
}

static glfs_t* gluster_cache_query(gluster_server *dst, char *cfgstring)
{
	struct gluster_cacheconn *entry = NULL;
	char** config;
	char* cfg_copy = NULL;
	bool cfgmatch = false;

	darray_foreach(entry, cache) {
		if (strcmp(entry->volname, dst->volname))
			continue;
		if (gluster_compare_hosts(entry->server, dst->server)) {

			darray_foreach(config, entry->cfgstring) {
				if (!strcmp(*config, cfgstring)) {
					cfgmatch = true;
					break;
				}
			}
			if (!cfgmatch) {
				cfg_copy = strdup(cfgstring);
				darray_append(entry->cfgstring, cfg_copy);
			}
			return entry->fs;
		}
	}

	return NULL;
}

static void gluster_cache_refresh(glfs_t *fs, const char *cfgstring)
{
	struct gluster_cacheconn *entry = NULL;
	char** config;
	size_t i = 0;
	size_t j = 0;

	if (!fs)
		return;

	darray_foreach(entry, cache) {
		if (entry->fs == fs) {
			if (cfgstring) {
				darray_foreach(config, entry->cfgstring) {
					if (!strcmp(*config, cfgstring)) {
						free(*config);
						darray_remove(entry->cfgstring, j);
						break;
					}
					j++;
				}
			}

			if (darray_size(entry->cfgstring))
				return;

			free(entry->volname);
			glfs_fini(entry->fs);
			entry->fs = NULL;
			gluster_free_host(entry->server);
			free(entry->server);
			entry->server = NULL;
			free(entry);

			darray_remove(cache, i);
			return;
		} else {
			i++;
		}
	}
}

static void gluster_free_server(gluster_server *hosts)
{
	if (!hosts)
		return;
	free(hosts->volname);
	free(hosts->path);

	gluster_free_host(hosts->server);
	free(hosts->server);
	hosts->server = NULL;
	free(hosts);
	hosts = NULL;
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
		return -ENOMEM;
	entry = *hosts;

	entry->server = calloc(1, sizeof(gluster_hostdef));
	if (!entry->server)
		return -ENOMEM;

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
	gluster_free_server(entry);
	free(origp);

	return -1;
}

static glfs_t* tcmu_create_glfs_object(char *config, gluster_server **hosts)
{
	gluster_server *entry = NULL;
    glfs_t *fs =  NULL;
    int ret = -1;

	if (parse_imagepath(config, hosts) == -1) {
		errp("hostaddr, volname, or path missing\n");
		goto fail;
	}
	entry = *hosts;

	fs = gluster_cache_query(entry, config);
	if (fs)
		return fs;

	fs = glfs_new(entry->volname);
	if (!fs) {
		errp("glfs_new failed\n");
		goto fail;
	}

	ret = gluster_cache_add(entry, fs, config);
	if (ret) {
		errp("gluster_cache_add failed: %m\n");
		goto fail;
	}

	ret = glfs_set_volfile_server(fs,
				gluster_transport_lookup[entry->server->type],
				entry->server->u.inet.addr,
				atoi(entry->server->u.inet.port));
	if (ret) {
		errp("glfs_set_volfile_server failed: %m\n");
		goto unref;
	}


	ret = glfs_init(fs);
	if (ret) {
		errp("glfs_init failed: %m\n");
		goto unref;
	}

    return fs;

 unref:
	gluster_cache_refresh(fs, config);

 fail:
	gluster_free_server(entry);

    return NULL;
}

static char* tcmu_get_path( struct tcmu_device *dev)
{
	char *config;

	config = strchr(tcmu_get_dev_cfgstring(dev), '/');
	if (!config) {
		errp("no configuration found in cfgstring\n");
		return NULL;
	}
	config += 1; /* get past '/' */

	return config;
}


static bool glfs_check_config(const char *cfgstring, char **reason)
{
	char *path;
	glfs_t *fs = NULL;
	glfs_fd_t *gfd = NULL;
	gluster_server *hosts; /* gluster server defination */
	bool result = true;

	path = strchr(cfgstring, '/');
	if (!path) {
		if (asprintf(reason, "No path found") == -1)
			*reason = NULL;
		result = false;
		goto done;
	}
	path += 1; /* get past '/' */

	fs = tcmu_create_glfs_object(path, &hosts);
	if (!fs) {
		errp("tcmu_create_glfs_object failed\n");
		goto done;
	}

	gfd = glfs_open(fs, hosts->path, ALLOWED_BSOFLAGS);
	if (!gfd) {
		if (asprintf(reason, "glfs_open failed: %m") == -1)
			*reason = NULL;
		result = false;
		goto unref;
	}

	if (glfs_access(fs, hosts->path, R_OK|W_OK) == -1) {
		if (asprintf(reason, "glfs_access file not present, or not writable") == -1)
			*reason = NULL;
		result = false;
		goto unref;
	}

	goto done;

unref:
	gluster_cache_refresh(fs, path);

done:
	if (gfd)
		glfs_close(gfd);
	gluster_free_server(hosts);

	return result;
}

static int tcmu_glfs_open(struct tcmu_device *dev)
{
	struct glfs_state *gfsp;
	int ret = 0;
	char *config;
	struct stat st;
	int block_size;
	int64_t size;

	gfsp = calloc(1, sizeof(*gfsp));
	if (!gfsp)
		return -ENOMEM;

	tcmu_set_dev_private(dev, gfsp);

	block_size = tcmu_get_attribute(dev, "hw_block_size");
	if (block_size < 0) {
		errp("Could not get hw_block_size setting\n");
		goto fail;
	}
	tcmu_set_dev_block_size(dev, block_size);

	size = tcmu_get_device_size(dev);
	if (size < 0) {
		errp("Could not get device size\n");
		goto fail;
	}
	tcmu_set_dev_num_lbas(dev, size / block_size);

	config = tcmu_get_path(dev);
	if (!config) {
		goto fail;
	}

	gfsp->fs = tcmu_create_glfs_object(config, &gfsp->hosts);
	if (!gfsp->fs) {
		errp("tcmu_create_glfs_object failed\n");
		goto fail;
	}

	gfsp->gfd = glfs_open(gfsp->fs, gfsp->hosts->path, ALLOWED_BSOFLAGS);
	if (!gfsp->gfd) {
		errp("glfs_open failed: %m\n");
		goto unref;
	}

	ret = glfs_lstat(gfsp->fs, gfsp->hosts->path, &st);
	if (ret) {
		errp("glfs_lstat failed: %m\n");
		goto unref;
	}

	if (st.st_size != tcmu_get_device_size(dev)) {
		errp("device size and backing size disagree: "
		       "device %lld backing %lld\n",
		       tcmu_get_device_size(dev),
		       (long long) st.st_size);
		goto unref;
	}

	return 0;

unref:
	gluster_cache_refresh(gfsp->fs, tcmu_get_path(dev));

fail:
	if (gfsp->gfd)
		glfs_close(gfsp->gfd);
	gluster_free_server(gfsp->hosts);
	free(gfsp);

	return -EIO;
}

static void tcmu_glfs_close(struct tcmu_device *dev)
{
	struct glfs_state *gfsp = tcmu_get_dev_private(dev);

	glfs_close(gfsp->gfd);
	gluster_cache_refresh(gfsp->fs, tcmu_get_path(dev));
	gluster_free_server(gfsp->hosts);
	free(gfsp);
}

static ssize_t tcmu_glfs_read(struct tcmu_device *dev, struct iovec *iov,
			      size_t iov_cnt, off_t offset)
{
        struct glfs_state *state = tcmu_get_dev_private(dev);

        return glfs_preadv(state->gfd, iov, iov_cnt, offset, SEEK_SET);
}

static ssize_t tcmu_glfs_write(struct tcmu_device *dev, struct iovec *iov,
			       size_t iov_cnt, off_t offset)
{
	struct glfs_state *state = tcmu_get_dev_private(dev);

        return glfs_pwritev(state->gfd, iov, iov_cnt, offset, ALLOWED_BSOFLAGS);
}

static int tcmu_glfs_flush(struct tcmu_device *dev)
{
	struct glfs_state *state = tcmu_get_dev_private(dev);

	return glfs_fdatasync(state->gfd);
}

static const char glfs_cfg_desc[] =
	"glfs config string is of the form:\n"
	"\"volume@hostname/filename\"\n"
	"where:\n"
	"  volume:    The volume on the Gluster server\n"
	"  hostname:  The server's hostname\n"
	"  filename:  The backing file";

struct tcmur_handler glfs_handler = {
	.name 		= "Gluster glfs handler",
	.subtype 	= "glfs",
	.cfg_desc	= glfs_cfg_desc,

	.check_config 	= glfs_check_config,

	.open 		= tcmu_glfs_open,
	.close 		= tcmu_glfs_close,
	.read 		= tcmu_glfs_read,
	.write		= tcmu_glfs_write,
	.flush		= tcmu_glfs_flush,
};

/* Entry point must be named "handler_init". */
int handler_init(void)
{
	return tcmur_register_handler(&glfs_handler);
}
