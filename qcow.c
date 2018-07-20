/*
 * Copyright (c) 2016 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */

/* Based on QEMU block/qcow{2}.c, which has this license: */

/*
 * Block driver for the QCOW format
 *
 * Original driver from QEMU
 * Copyright (c) 2004-2006 Fabrice Bellard
 *
 * Modified for tcmu-runner by Chris Leech
 * Copyright (c) 2015, Red Hat, Inc.
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
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <endian.h>
#include <limits.h>
#include <inttypes.h>
#include <libgen.h>
#include <alloca.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <scsi/scsi.h>
#include <assert.h>
#include <errno.h>

#include <zlib.h>
#if defined(HAVE_LINUX_FALLOC)
#include <linux/falloc.h>
#endif

#include "scsi_defs.h"
#include "libtcmu.h"
#include "qcow.h"
#include "qcow2.h"

/* Block Device abstraction to support multiple image types */

struct bdev_ops;
static struct bdev_ops qcow_ops;
static struct bdev_ops qcow2_ops;
static struct bdev_ops raw_ops;

struct bdev {
	char *config;
	void *private;
	struct bdev_ops *ops;

	/* from TCMU configfs configuration */
	int64_t size;
	uint32_t block_size;

	int fd;		/* image file descriptor */
};

struct bdev_ops {
	int (*probe) (struct bdev *dev, int dirfd, const char *pathname);
	int (*open) (struct bdev *dev, int dirfd, const char *pathname, int flags);
	void (*close) (struct bdev *dev);
	ssize_t (*preadv) (struct bdev *bdev, struct iovec *iov, int iovcnt, off_t offset);
	ssize_t (*pwritev) (struct bdev *bdev, struct iovec *iov, int iovcnt, off_t offset);
};

static int bdev_open(struct bdev *bdev, int dirfd, const char *pathname, int flags)
{
	struct bdev_ops *bdev_ops[] = {
		&qcow_ops,
		&qcow2_ops,
		&raw_ops,
		NULL,
	};
	struct bdev_ops **ops;

	for (ops = &bdev_ops[0]; *ops != NULL; ops++) {
		if ((*ops)->probe(bdev, dirfd, pathname) == 0) {
			if ((*ops)->open(bdev, dirfd, pathname, flags) == -1) {
				tcmu_err("image open failed: %s\n", pathname);
				goto err;
			}
			bdev->ops = *ops;
			return 0;
		}
	}
	tcmu_err("image format not recognized: %s\n", pathname);
err:
	return -1;
}

static int get_dirfd(int fd)
{
	char proc_path[64];
	char *img_path;
	char *dir;
	int dirfd;
	ssize_t len;

	/* more than enough room for "/proc/self/fd/<INT_MAX>\0" */
	snprintf(proc_path, 64, "/proc/self/fd/%d", fd);

	/* can't use lstat in /proc to get name length :( */
	img_path = malloc(PATH_MAX);
	len = readlink(proc_path, img_path, PATH_MAX);
	img_path[len] = '\0';

	dir = dirname(img_path);
	dirfd = open(dir, O_DIRECTORY | O_PATH);
	free(img_path);
	return dirfd;
}

/* QCOW version 1 */

static void qcow_header_bswap(struct qcow_header *be, struct qcow_header *dst)
{
	dst->magic = be32toh(be->magic);
	dst->version = be32toh(be->version);
	dst->backing_file_offset = be64toh(be->backing_file_offset);
	dst->backing_file_size = be32toh(be->backing_file_size);
	dst->mtime = be32toh(be->mtime);
	dst->size = be64toh(be->size);
	dst->cluster_bits = be->cluster_bits;
	dst->l2_bits = be->l2_bits;
	dst->padding = be16toh(be->padding);
	dst->crypt_method = be32toh(be->crypt_method);
	dst->l1_table_offset = be64toh(be->l1_table_offset);
}

static void qcow2_header_bswap(struct qcow2_header *be, struct qcow2_header *dst)
{
	dst->magic = be32toh(be->magic);
	dst->version = be32toh(be->version);
	dst->backing_file_offset = be64toh(be->backing_file_offset);
	dst->backing_file_size = be32toh(be->backing_file_size);
	dst->cluster_bits = be32toh(be->cluster_bits);
	dst->size = be64toh(be->size) /* in bytes */;
	dst->crypt_method = be32toh(be->crypt_method);
	dst->l1_size = be32toh(be->l1_size);
	dst->l1_table_offset = be64toh(be->l1_table_offset);
	dst->refcount_table_offset = be64toh(be->refcount_table_offset);
	dst->refcount_table_clusters = be32toh(be->refcount_table_clusters);
	dst->nb_snapshots = be32toh(be->nb_snapshots);
	dst->snapshots_offset = be64toh(be->snapshots_offset);
	if (dst->version == 2) {
		/* The following fields are only valid for version >= 3 */
		dst->incompatible_features = 0;
		dst->compatible_features = 0;
		dst->autoclear_features = 0;
		dst->refcount_order = 4;
		dst->header_length = 72;
	} else {
		dst->incompatible_features = be64toh(be->incompatible_features);
		dst->compatible_features = be64toh(be->compatible_features);
		dst->autoclear_features = be64toh(be->autoclear_features);
		dst->refcount_order = be32toh(be->refcount_order);
		dst->header_length = be32toh(be->header_length);
	}
}

#define RC_CACHE_SIZE L2_CACHE_SIZE

struct qcow_state
{
	int fd;
	uint64_t size;
	unsigned int cluster_bits;
	unsigned int cluster_size;
	unsigned int cluster_sectors;
	unsigned int l2_bits;
	unsigned int l2_size;
	uint64_t cluster_offset_mask;

	/* L1 table, load entire thing into RAM */
	unsigned int l1_size;
	uint64_t l1_table_offset;
	uint64_t *l1_table;

	/* L2 cache */
	uint64_t *l2_cache;
	uint64_t l2_cache_offsets[L2_CACHE_SIZE];
	int l2_cache_counts[L2_CACHE_SIZE];

	/* cluster decompression cache */
	uint8_t *cluster_cache;
	uint8_t *cluster_data;
	uint64_t cluster_cache_offset;

	struct bdev *backing_image;
	uint64_t cluster_compressed;
	uint64_t cluster_copied;
	uint64_t cluster_mask;

	/* qcow2 refcount top level table */
	uint64_t refcount_table_offset;
	uint32_t refcount_table_size;
	uint64_t *refcount_table;

	/* refcount block cache */
	unsigned int refcount_order;
	void *rc_cache;
	uint64_t rc_cache_offsets[RC_CACHE_SIZE];
	int rc_cache_counts[RC_CACHE_SIZE];

	uint64_t (*block_alloc) (struct qcow_state *s, size_t size);
	int (*set_refcount) (struct qcow_state *s, uint64_t cluster_offset, uint64_t value);

	uint64_t first_free_cluster;
};

static uint64_t qcow_block_alloc(struct qcow_state *s, size_t size);
static uint64_t qcow2_block_alloc(struct qcow_state *s, size_t size);
static int qcow_no_refcount(struct qcow_state *s, uint64_t cluster_offset, uint64_t value)
{
	return 0;
}
static int qcow2_set_refcount(struct qcow_state *s, uint64_t cluster_offset, uint64_t value);

static int qcow_probe(struct bdev *bdev, int dirfd, const char *pathname)
{
	int fd;
	struct {
	    uint32_t magic;
	    uint32_t version;
	} head;

	tcmu_dbg("%s\n", __func__);

	if (faccessat(dirfd, pathname, R_OK|W_OK, AT_EACCESS) == -1)
		return -1;
	if ((fd = openat(dirfd, pathname, O_RDONLY)) == -1)
		return -1;
	if (pread(fd, &head, sizeof(head), 0) == -1)
		goto err;
	if (be32toh(head.magic) != QCOW_MAGIC)
		goto err;
	if (be32toh(head.version) != 1)
		goto err;
	close(fd);
	return 0;
err:
	close(fd);
	return -1;
}

static int qcow2_probe(struct bdev *bdev, int dirfd, const char *pathname)
{
	int fd;
	struct {
	    uint32_t magic;
	    uint32_t version;
	} head;

	tcmu_dbg("%s\n", __func__);

	if (faccessat(dirfd, pathname, R_OK|W_OK, AT_EACCESS) == -1) {
		tcmu_err("faccessat failed dirfd %d, pathname %s, errno %d\n",
			 dirfd, pathname, errno);
		return -1;
	}
	if ((fd = openat(dirfd, pathname, O_RDONLY)) == -1) {
		tcmu_err("openat failed dirfd %d, pathname %s, errno %d\n",
			 dirfd, pathname, errno);
		return -1;
	}
	if (pread(fd, &head, sizeof(head), 0) == -1) {
		tcmu_err("pread failed dirfd %d, pathname %s, errno %d\n",
			 dirfd, pathname, errno);
		goto err;
	}
	if (be32toh(head.magic) != QCOW_MAGIC) {
		tcmu_warn("not qcow: will treat as raw: %s", pathname);
		goto err;
	}
	if (be32toh(head.version) < 2) {
		tcmu_err("version = %d, pathname %s\n", head.version, pathname);
		goto err;
	}
	close(fd);
	return 0;
err:
	close(fd);
	return -1;
}

static int qcow_validate_header(struct qcow_header *header)
{
	if (header->magic != QCOW_MAGIC) {
		tcmu_err("header is not QCOW\n");
		 return -1;
	}
	if (header->version != 1) {
		tcmu_err("version is %d, expected 1\n", header->version);
		 return -1;
	}
	if (header->cluster_bits < 9 || header->cluster_bits > 16) {
		tcmu_err("bad cluster_bits = %d\n", header->cluster_bits);
		 return -1;
	}
	if (header->l2_bits < (9 - 3) || header->l2_bits > (16 - 3)) {
		tcmu_err("bad l2_bits = %d\n", header->l2_bits);
		 return -1;
	}
	switch (header->crypt_method) {
		case QCOW_CRYPT_NONE:
			break;
		case QCOW_CRYPT_AES:
			tcmu_err("QCOW AES-CBC encryption has been deprecated\n");
			tcmu_err("Convert to unencrypted image using qemu-img\n");
			 return -1;
		default:
			tcmu_err("Invalid encryption value %d\n", header->crypt_method);
			 return -1;
	}
	return 0;
}

static int qcow2_validate_header(struct qcow2_header *header)
{
	/* TODO check other stuff ... L1, refcount, snapshots */
	if (header->magic != QCOW_MAGIC) {
		tcmu_err("header is not QCOW\n");
		 return -1;
	}
	if (header->version < 2) {
		tcmu_err("version is %d, expected 2 or 3\n", header->version);
		 return -1;
	}
	if (header->cluster_bits < 9 || header->cluster_bits > 16) {
		tcmu_err("bad cluster_bits = %d\n", header->cluster_bits);
		 return -1;
	}
	switch (header->crypt_method) {
		case QCOW2_CRYPT_NONE:
			break;
		case QCOW2_CRYPT_AES:
			tcmu_err("QCOW AES-CBC encryption has been deprecated\n");
			tcmu_err("Convert to unencrypted image using qemu-img\n");
			 return -1;
		default:
			tcmu_err("Invalid encryption value %d\n", header->crypt_method);
			 return -1;
	}
	return 0;
}

static int qcow_setup_backing_file(struct bdev *bdev, struct qcow_header *header)
{
	struct qcow_state *s = bdev->private;
	char *backing_file;
	uint64_t offset;
	size_t len;
	int dirfd;
	int ret;

	offset = header->backing_file_offset;
	len = header->backing_file_size;

	if (offset == 0 || len == 0)
		return 0;

	if (len >= PATH_MAX) {
		tcmu_err("Backing file name too long\n");
		return -1;
	}

	backing_file = alloca(len + 1);

	if (pread(bdev->fd, backing_file, len, header->backing_file_offset) != len) {
		tcmu_err("Error reading backing file name\n");
		return -1;
	}
	backing_file[len] = '\0';

	s->backing_image = calloc(1, sizeof(struct bdev));
	if (!s->backing_image)
		return -1;

	/* backing file settings copied from overlay */
	s->backing_image->size = bdev->size;
	s->backing_image->block_size = bdev->block_size;

	/* backing file pathname may be relative to the overlay image */
	dirfd = get_dirfd(bdev->fd);
	if (dirfd == -1)
		goto fail;
	ret = bdev_open(s->backing_image, dirfd, backing_file, O_RDONLY);
	close(dirfd);
	if (ret == -1)
		goto fail;
	return 0;
fail:
	free(s->backing_image);
	s->backing_image = NULL;
	return -1;
}

static int qcow2_setup_backing_file(struct bdev *bdev, struct qcow2_header *header)
{
	/* backing file info is at the same place in both headers,
	 * so we can cheat and use this for qcow2 also */
	return qcow_setup_backing_file(bdev, (struct qcow_header *) header);
}

static int qcow_image_open(struct bdev *bdev, int dirfd, const char *pathname, int flags)
{
	struct qcow_header buf;
	struct qcow_header header;
	struct qcow_state *s;
	uint64_t l1_size;
	unsigned int shift;
	ssize_t read;

	s = calloc(1, sizeof(struct qcow_state));
	if (!s)
		return -1;
	bdev->private = s;

	bdev->fd = openat(dirfd, pathname, flags);
	s->fd = bdev->fd;
	if (bdev->fd == -1) {
		tcmu_err("Failed to open file: %s\n", pathname);
		goto fail_nofd;
	}

	if (pread(bdev->fd, &buf, sizeof(buf), 0) != sizeof(buf)) {
		tcmu_err("Failed to read file: &s\n", pathname);
		goto fail;
	}

	qcow_header_bswap(&buf, &header);
	if (qcow_validate_header(&header) < 0)
		goto fail;

	if (bdev->size != header.size) {
		tcmu_err("size misconfigured, TCMU says %" PRId64
				" but image says %" PRId64 "\n",
				bdev->size, header.size);
		goto fail;
	}
	s->size = bdev->size;
	if (bdev->block_size != 512) {
		tcmu_err("block_size misconfigured, TCMU says %" PRId32
				" but qcow only supports 512\n",
				bdev->block_size);
		goto fail;
	}

	s->cluster_bits = header.cluster_bits;
	s->cluster_size = 1 << s->cluster_bits;
	s->cluster_sectors = 1 << (s->cluster_bits - 9);
	s->l2_bits = header.l2_bits;
	s->l2_size = 1 << s->l2_bits;
	s->cluster_offset_mask = (1LL << (63 - s->cluster_bits)) - 1;

	shift = s->cluster_bits + s->l2_bits;
	if (header.size > UINT64_MAX - (1LL << shift)) {
		tcmu_err("Image size too big\n");
		goto fail;
	}
	l1_size = (header.size + (1LL << shift) - 1) >> shift;
	if (l1_size > INT_MAX / sizeof(uint64_t)) {
		tcmu_err("Image size too big\n");
		goto fail;
	}
	if (round_up(header.size, bdev->block_size) != header.size) {
		tcmu_err("Image size is not an integer multiple"
				 " of the block size\n");
		goto fail;
	}	
	s->l1_size = l1_size;
	s->l1_table_offset = header.l1_table_offset;

	s->l1_table = calloc(s->l1_size, sizeof(uint64_t));
	if (!s->l1_table) {
		tcmu_err("Failed to allocate L1 table\n");
		goto fail;
	}
	read = pread(bdev->fd, s->l1_table, s->l1_size * sizeof(uint64_t), s->l1_table_offset);
	if (read != s->l1_size * sizeof(uint64_t)) {
		tcmu_err("Failed to read L1 table\n");
		goto fail;
	}

	s->l2_cache = calloc(L2_CACHE_SIZE, s->l2_size * sizeof(uint64_t));
	if (s->l2_cache == NULL) {
		tcmu_err("Failed to allocate L2 cache\n");
		goto fail;
	}

	/* cluster decompression cache */
	s->cluster_cache = calloc(1, s->cluster_size);
	s->cluster_data = calloc(1, s->cluster_size);
	s->cluster_cache_offset = -1;
	if (!s->cluster_cache || !s->cluster_data) {
		tcmu_err("Failed to allocate cluster decompression space\n");
		goto fail;
	}

	if (qcow_setup_backing_file(bdev, &header) == -1)
		goto fail;

	s->cluster_compressed = QCOW_OFLAG_COMPRESSED;
	s->cluster_mask = ~QCOW_OFLAG_COMPRESSED;

	s->block_alloc = qcow_block_alloc;
	s->set_refcount = qcow_no_refcount;
	tcmu_dbg("%d: %s\n", bdev->fd, pathname);
	return 0;
fail:
	close(bdev->fd);
	free(s->cluster_cache);
	free(s->cluster_data);
	free(s->l2_cache);
	free(s->l1_table);
fail_nofd:
	free(s);
	return -1;
}

static int qcow2_image_open(struct bdev *bdev, int dirfd, const char *pathname, int flags)
{
	struct qcow2_header buf;
	struct qcow2_header header;
	struct qcow_state *s;
	uint64_t l1_size;
	unsigned int shift;
	ssize_t read;

	s = calloc(1, sizeof(struct qcow_state));
	if (!s)
		return -1;
	bdev->private = s;

	bdev->fd = openat(dirfd, pathname, flags);
	s->fd = bdev->fd;
	if (bdev->fd == -1) {
		tcmu_err("Failed to open file: %s\n", pathname);
		goto fail_nofd;
	}

	if (pread(bdev->fd, &buf, sizeof(buf), 0) != sizeof(buf)) {
		tcmu_err("Failed to read file: %s\n", pathname);
		goto fail;
	}

	qcow2_header_bswap(&buf, &header);
	if (qcow2_validate_header(&header) < 0)
		goto fail;

	if (bdev->size != header.size) {
		tcmu_err("size misconfigured, TCMU says %" PRId64
				" but image says %" PRId64 "\n",
				bdev->size, header.size);
		goto fail;
	}
	s->size = bdev->size;
	if (bdev->block_size != 512) {
		tcmu_err("block_size misconfigured, TCMU says %" PRId32
				" but qcow only supports 512\n",
				bdev->block_size);
		goto fail;
	}

	s->cluster_bits = header.cluster_bits;
	s->cluster_size = 1 << s->cluster_bits;
	s->cluster_sectors = 1 << (s->cluster_bits - 9);
	s->l2_bits = s->cluster_bits - 3;	// L2 table is always 1 cluster in size (8 (2^3) byte entries)
	s->l2_size = 1 << s->l2_bits;
	s->cluster_offset_mask = (1LL << (63 - s->cluster_bits)) - 1;

	shift = s->cluster_bits + s->l2_bits;
	if (header.size > UINT64_MAX - (1LL << shift)) {
		tcmu_err("Image size too big\n");
		goto fail;
	}
	l1_size = (header.size + (1LL << shift) - 1) >> shift;
	if (l1_size > INT_MAX / sizeof(uint64_t)) {
		tcmu_err("Image size too big\n");
		goto fail;
	}
	if (round_up(header.size, bdev->block_size) != header.size) {
		tcmu_err("Image size is not an integer multiple"
				 " of the block size\n");
		goto fail;
	}		
	s->l1_size = l1_size;
	// why did they add this to qcow2 ?
	if (header.l1_size != s->l1_size) {
		tcmu_err("L1 size is incorrect\n");
		goto fail;
	}
	s->l1_table_offset = header.l1_table_offset;

	s->l1_table = calloc(s->l1_size, sizeof(uint64_t));
	if (!s->l1_table) {
		tcmu_err("Failed to allocate L1 table\n");
		goto fail;
	}
	read = pread(bdev->fd, s->l1_table, s->l1_size * sizeof(uint64_t), s->l1_table_offset);
	if (read != s->l1_size * sizeof(uint64_t)) {
		tcmu_err("Failed to read L1 table\n");
		goto fail;
	}

	s->l2_cache = calloc(L2_CACHE_SIZE, s->l2_size * sizeof(uint64_t));
	if (s->l2_cache == NULL) {
		tcmu_err("Failed to allocate L2 cache\n");
		goto fail;
	}
	tcmu_dbg("s->l2_cache = %p\n", s->l2_cache);

	/* cluster decompression cache */
	s->cluster_cache = calloc(1, s->cluster_size);
	s->cluster_data = calloc(1, s->cluster_size);
	s->cluster_cache_offset = -1;
	if (!s->cluster_cache || !s->cluster_data) {
		tcmu_err("Failed to allocate cluster decompression space\n");
		goto fail;
	}
	tcmu_dbg("s->cluster_cache = %p\n", s->cluster_cache);

	/* refcount table */
	s->refcount_table_offset = header.refcount_table_offset;
	s->refcount_table_size = header.refcount_table_clusters << (s->cluster_bits - 3);

	s->refcount_table = calloc(s->refcount_table_size, sizeof(uint64_t));
	if (!s->refcount_table) {
		tcmu_err("Failed to allocate refcount table\n");
		goto fail;
	}
	read = pread(bdev->fd, s->refcount_table, s->refcount_table_size * sizeof(uint64_t), s->refcount_table_offset);
	if (read != s->refcount_table_size * sizeof(uint64_t)) {
		tcmu_err("Failed to read refcount table\n");
		goto fail;
	}

	s->refcount_order = header.refcount_order;
	s->rc_cache = calloc(RC_CACHE_SIZE, s->cluster_size);
	if (s->rc_cache == NULL) {
		tcmu_err("Failed to allocate refcount cache\n");
		goto fail;
	}
	tcmu_dbg("s->rc_cache = %p\n", s->rc_cache);

	if (qcow2_setup_backing_file(bdev, &header) == -1)
		goto fail;

	s->cluster_compressed = QCOW2_OFLAG_COMPRESSED;
	s->cluster_copied =  QCOW2_OFLAG_COPIED;
	s->cluster_mask = ~(QCOW_OFLAG_COMPRESSED | QCOW2_OFLAG_COPIED | QCOW2_OFLAG_ZERO);

	s->block_alloc = qcow2_block_alloc;
	s->set_refcount = qcow2_set_refcount;
	tcmu_dbg("%d: %s\n", bdev->fd, pathname);
	return 0;
fail:
	close(bdev->fd);
	free(s->cluster_cache);
	free(s->cluster_data);
	free(s->rc_cache);
	free(s->refcount_table);
	free(s->l2_cache);
	free(s->l1_table);
fail_nofd:
	free(s);
	return -1;
}

static void qcow_image_close(struct bdev *bdev)
{
	struct qcow_state *s = bdev->private;

	if (s->backing_image) {
		s->backing_image->ops->close(s->backing_image);
		free(s->backing_image);
	}
	close(bdev->fd);
	free(s->cluster_cache);
	free(s->cluster_data);
	free(s->l1_table);
	free(s->l2_cache);
	free(s->refcount_table);
	free(s->rc_cache);
	free(s);
}

static uint64_t *l2_cache_lookup(struct qcow_state *s, uint64_t l2_offset)
{
	int i, j;
	int min_index = 0;
	int min_count = INT_MAX;
	uint64_t *l2_table;
	ssize_t read;

	/* l2 cache lookup */
	for (i = 0; i < L2_CACHE_SIZE; i++) {
		if (l2_offset == s->l2_cache_offsets[i]) {
			if (++s->l2_cache_counts[i] == INT_MAX) {
				for (j = 0; i < L2_CACHE_SIZE; j++) {
					s->l2_cache_counts[j] >>= 1;
				}
			}
			l2_table = s->l2_cache + (i << s->l2_bits);
			tcmu_dbg("%s: l2 hit %llx at index %d\n", __func__, l2_table, i);
			return l2_table;
		}
	}
	/* not found, evict least used entry */
	for (i = 0; i < L2_CACHE_SIZE; i++) {
		if (s->l2_cache_counts[i] < min_count) {
			min_count = s->l2_cache_counts[i];
			min_index = i;
		}
	}
	l2_table = s->l2_cache + (min_index << s->l2_bits);
	read = pread(s->fd, l2_table, s->l2_size * sizeof(uint64_t), l2_offset);
	if (read != s->l2_size * sizeof(uint64_t))
		return NULL;
	s->l2_cache_offsets[min_index] = l2_offset;
	s->l2_cache_counts[min_index] = 1;

	return l2_table;
}

static uint64_t qcow_cluster_alloc(struct qcow_state *s)
{
	tcmu_dbg("%s\n", __func__);
	return s->block_alloc(s, s->cluster_size);
}

/* qcow 1 simply grows the file as new clusters or L2 blocks are needed */
static uint64_t qcow_block_alloc(struct qcow_state *s, size_t size)
{
	uint64_t offset;
	off_t off;

	off = lseek(s->fd, 0, SEEK_END);
	if (off == -1)
		return 0;
	offset = (off + size - 1) & ~(size - 1);
	if (ftruncate(s->fd, offset + size) == -1)
		return 0;
	return offset;
}

static uint64_t l2_table_alloc(struct qcow_state *s)
{
	tcmu_dbg("%s\n", __func__);
	return s->block_alloc(s, s->l2_size * sizeof(uint64_t));
}

static int l1_table_update(struct qcow_state *s, unsigned int l1_index, uint64_t l2_offset)
{
	ssize_t ret;

	tcmu_dbg("%s: setting L1[%d] to %llx\n", __func__, l1_index, l2_offset);
	s->l1_table[l1_index] = htobe64(l2_offset);

	ret = pwrite(s->fd,
		&s->l1_table[l1_index],
		sizeof(uint64_t),
		s->l1_table_offset + (l1_index * sizeof(uint64_t)));

	if (ret != sizeof(uint64_t))
		tcmu_err("%s: error, L1 writeback failed (%zd)\n", __func__, ret);

	fdatasync(s->fd);
	return ret;
}

/* refcount table */

static uint64_t get_refcount(unsigned int order, void *rcblock, size_t index)
{
	switch (order) {
	case 0:
		return (((uint8_t *)rcblock)[index / 8] >> (index % 8)) & 0x1;
	case 1:
		return (((uint8_t *)rcblock)[index / 4] >> (2 * (index % 4))) & 0x3;
	case 2:
		return (((uint8_t *)rcblock)[index / 2] >> (4 * (index % 2))) & 0xf;
	case 3:
		return ((uint8_t *)rcblock)[index];
	case 4:
		return be16toh(((uint16_t *)rcblock)[index]);
	case 5:
		return be32toh(((uint32_t *)rcblock)[index]);
	case 6:
		return be64toh(((uint64_t *)rcblock)[index]);
	default:
		assert(0);
	}

	return 0;	/* NOT REACHED */
}

static void set_refcount(unsigned int order, void *rcblock, size_t index, uint64_t value)
{
	assert(!(value >> (1 << order)));

	switch (order) {
	case 0:
		((uint8_t *)rcblock)[index / 8] &= ~(0x1 << (index % 8));
		((uint8_t *)rcblock)[index / 8] |= value << (index % 8);
		break;
	case 1:
		((uint8_t *)rcblock)[index / 4] &= ~(0x3 << (2 * (index % 4)));
		((uint8_t *)rcblock)[index / 4] |= value << (2 * (index % 4));
		break;
	case 2:
		((uint8_t *)rcblock)[index / 2] &= ~(0xf << (4 * (index % 2)));
		((uint8_t *)rcblock)[index / 2] |= value << (4 * (index % 2));
		break;
	case 3:
		((uint8_t *)rcblock)[index] = value;
		break;
	case 4:
		((uint16_t *)rcblock)[index] = htobe16(value);
		break;
	case 5:
		((uint32_t *)rcblock)[index] = htobe32(value);
		break;
	case 6:
		((uint64_t *)rcblock)[index] = htobe64(value);
		break;
	default:
		assert(0);
	}
}

static void *rc_cache_lookup(struct qcow_state *s, uint64_t rc_offset)
{
	int i, j;
	int min_index = 0;
	int min_count = INT_MAX;
	void *rc_table;
	ssize_t read;

	/* rc cache lookup */
	for (i = 0; i < RC_CACHE_SIZE; i++) {
		if (rc_offset == s->rc_cache_offsets[i]) {
			if (++s->rc_cache_counts[i] == INT_MAX) {
				for (j = 0; i < RC_CACHE_SIZE; j++) {
					s->rc_cache_counts[j] >>= 1;
				}
			}
			rc_table = s->rc_cache + (i << s->cluster_bits);
			return rc_table;
		}
	}
	/* not found, evict least used entry */
	for (i = 0; i < RC_CACHE_SIZE; i++) {
		if (s->rc_cache_counts[i] < min_count) {
			min_count = s->rc_cache_counts[i];
			min_index = i;
		}
	}
	rc_table = s->rc_cache + (min_index << s->cluster_bits);
	read = pread(s->fd, rc_table, 1 << s->cluster_bits, rc_offset);
	if (read != 1 << s->cluster_bits)
		return NULL;
	s->rc_cache_offsets[min_index] = rc_offset;
	s->rc_cache_counts[min_index] = 1;

	return rc_table;
}

static uint64_t qcow2_get_refcount(struct qcow_state *s, int64_t cluster_offset)
{
	unsigned int refcount_bits;
	uint64_t rc_index;
	uint64_t refblock_offset;
	uint64_t refblock_index;
	void *refblock;
	uint64_t rc;

	refcount_bits = s->cluster_bits - s->refcount_order + 3;
	rc_index = cluster_offset >> (s->cluster_bits + refcount_bits);
	refblock_offset = be64toh(s->refcount_table[rc_index]);
	if (!refblock_offset)
		return 0;

	refblock = rc_cache_lookup(s, refblock_offset);
	if (!refblock)
		return 0;

	refblock_index = (cluster_offset >> s->cluster_bits) & ((1 << refcount_bits) - 1);
	rc = get_refcount(s->refcount_order, refblock, refblock_index);
	return rc;
}

static int rc_table_update(struct qcow_state *s, unsigned int rc_index, uint64_t refblock_offset)
{
	ssize_t ret;

	tcmu_dbg("%s: setting RC[%d] to %llx\n", __func__, rc_index, refblock_offset);
	s->refcount_table[rc_index] = htobe64(refblock_offset);

	ret = pwrite(s->fd,
		&s->refcount_table[rc_index],
		sizeof(uint64_t),
		s->refcount_table_offset + (rc_index * sizeof(uint64_t)));

	if (ret != sizeof(uint64_t))
		tcmu_err("%s: error, RC writeback failed (%zd)\n", __func__, ret);

	fdatasync(s->fd);
	return ret;
}

static int qcow2_set_refcount(struct qcow_state *s, uint64_t cluster_offset, uint64_t value)
{
	unsigned int refcount_bits;
	uint64_t rc_index;
	uint64_t refblock_offset;
	uint64_t refblock_index;
	void *refblock;
	ssize_t ret;

	refcount_bits = s->cluster_bits - s->refcount_order + 3;
	rc_index = cluster_offset >> (s->cluster_bits + refcount_bits);
	refblock_offset = be64toh(s->refcount_table[rc_index]);
	refblock_index = (cluster_offset >> s->cluster_bits) & ((1 << refcount_bits) - 1);

	tcmu_dbg("%s: rc[%d][%d] = %llx[%d] = %d\n", __func__, rc_index, refblock_index, refblock_offset, refblock_index, value);

	if (!refblock_offset) {
		if (!(refblock_offset = qcow_cluster_alloc(s))) {
			tcmu_err("refblock allocation failure\n");
			return -1;
		}
		rc_table_update(s, rc_index, refblock_offset);
		qcow2_set_refcount(s, refblock_offset, 1);
	}

	refblock = rc_cache_lookup(s, refblock_offset);
	if (!refblock) {
		tcmu_err("refblock cache failure\n");
		return -1;
	}

	set_refcount(s->refcount_order, refblock, refblock_index, value);

	/* for now this writes back the entire block */
	ret = pwrite(s->fd, refblock, s->cluster_size, refblock_offset);
	if (ret != s->cluster_size)
		tcmu_err("%s: error, refblock writeback failed (%zd)\n", __func__, ret);
	fdatasync(s->fd);
	return ret;
}

/* qcow 2 uses the refcount table to find free clusters */
static uint64_t qcow2_block_alloc(struct qcow_state *s, size_t size)
{
	uint64_t cluster;
	int ret;

	tcmu_dbg("  %s %zx\n", __func__, size);

	/* all allocations for qcow2 should be of the same size */
	assert(size == s->cluster_size);

	cluster = s->first_free_cluster;
	while (qcow2_get_refcount(s, cluster)) {
		cluster += s->cluster_size;
	}

	ret = fallocate(s->fd, FALLOC_FL_ZERO_RANGE, cluster, s->cluster_size);
	if (ret) {
		tcmu_err("fallocate failed: %m\n");
		return 0;
	}
	s->first_free_cluster = cluster + s->cluster_size;
	// this causes a nasty loop
	// qcow2_set_refcount(s, cluster, 1);
	tcmu_dbg("  allocating cluster %d\n", cluster / s->cluster_size);
	return cluster;
}

static int l2_table_update(struct qcow_state *s,
			   uint64_t *l2_table, uint64_t l2_table_offset,
			   unsigned int l2_index, uint64_t cluster_offset)
{
	ssize_t ret;

	tcmu_dbg("%s: setting %llx[%d] to %llx\n", __func__, l2_table_offset, l2_index, cluster_offset);
	l2_table[l2_index] = htobe64(cluster_offset);

	ret = pwrite(s->fd,
		&(l2_table[l2_index]),
		sizeof(uint64_t),
		l2_table_offset + (l2_index * sizeof(uint64_t)));

	if (ret != sizeof(uint64_t))
		tcmu_err("%s: error, L2 writeback failed (%zd)\n", __func__, ret);

	fdatasync(s->fd);
	return ret;
}

static int decompress_buffer(uint8_t *dst, size_t dst_size, const uint8_t *src, size_t src_size)
{
	ptrdiff_t out_len;
	int ret;

	z_stream strm = {
		.next_in = (uint8_t *)src,
		.avail_in = src_size,
		.next_out = dst,
		.avail_out = dst_size,
	};

	ret = inflateInit2(&strm, -12);
	if (ret != Z_OK)
		return -1;
	ret = inflate(&strm, Z_FINISH);
	out_len = strm.next_out - dst;
	if ((ret != Z_STREAM_END && ret != Z_BUF_ERROR) || out_len != dst_size) {
		inflateEnd(&strm);
		return -1;
	}
	inflateEnd(&strm);
	return 0;
}

static int decompress_cluster(struct qcow_state *s, uint64_t cluster_offset)
{
	uint64_t coffset;
	size_t csize;
	ssize_t ret;

	coffset = cluster_offset & s->cluster_offset_mask;
	if (s->cluster_cache_offset != coffset) {
		csize = cluster_offset >> (63 - s->cluster_bits);
		csize &= (s->cluster_size -1);
		ret = pread(s->fd, s->cluster_data, csize, coffset);
		if (ret != csize)
			return -1;
		ret = decompress_buffer(s->cluster_cache, s->cluster_size, s->cluster_data, csize);
		if (ret < 0)
			return -1;
		s->cluster_cache_offset = coffset;
	}
	return 0;
}

/**
 * get_cluster_offset()
 * returns the file offset for the start of a cluster containing a sector
 * returns 0 if sector is not mapped in the image file
 * (0 is never a valid cluster offset, it's where the file header is)
 *
 * offset: virtual image sector offset
 * allocate: true if new cluster and L2 table allocations should happen (writes)
 */
static uint64_t get_cluster_offset(struct qcow_state *s, const uint64_t offset, bool allocate)
{
	unsigned int l1_index;
	unsigned int l2_index;
	uint64_t l2_offset;
	uint64_t *l2_table;
	uint64_t cluster_offset;

	tcmu_dbg("%s: %"PRIx64" %s\n", __func__, offset, allocate ? "write" : "read");

	l1_index = offset >> (s->l2_bits + s->cluster_bits);
	l2_offset = be64toh(s->l1_table[l1_index]) & s->cluster_mask;
	l2_index = (offset >> s->cluster_bits) & (s->l2_size - 1);
	// TODO, check refcount on L2 table and handle CoW for metadata updates
	tcmu_dbg("  l1_index = %d\n", l1_index);
	tcmu_dbg("  l2_offset = %"PRIx64"\n", l2_offset);
	tcmu_dbg("  l2_index = %d\n", l2_index);

	if (!l2_offset) {
		if (!allocate || !(l2_offset = l2_table_alloc(s)))
			return 0;
		l1_table_update(s, l1_index, l2_offset | s->cluster_copied);
		s->set_refcount(s, l2_offset, 1);
	}

	l2_table = l2_cache_lookup(s, l2_offset);
	if (!l2_table)
		return 0;

	cluster_offset = be64toh(l2_table[l2_index]); // & s->cluster_mask;
	tcmu_dbg("  l2_table @ %p\n", l2_table);
	tcmu_dbg("  cluster offset = %" PRIx64 "\n", cluster_offset);

	if (!cluster_offset) {
		/* sector not allocated in image file */
		if (!allocate || !(cluster_offset = qcow_cluster_alloc(s)))
			return 0;
		l2_table_update(s, l2_table, l2_offset, l2_index, cluster_offset | s->cluster_copied);
		s->set_refcount(s, cluster_offset, 1);
	} else if ((cluster_offset & s->cluster_compressed) && allocate) {
		tcmu_err("re-allocating compressed cluster for writing\n");
		/* reallocate a compressed cluster for writing */
		if (decompress_cluster(s, cluster_offset) < 0)
			return 0;
		if (!(cluster_offset = qcow_cluster_alloc(s)))
			return 0;
		if (pwrite(s->fd, s->cluster_cache, s->cluster_size, cluster_offset) != s->cluster_size)
			return 0;
		l2_table_update(s, l2_table, l2_offset, l2_index, cluster_offset | s->cluster_copied);
		s->set_refcount(s, cluster_offset, 1);
	} else if (!(cluster_offset & s->cluster_copied) && allocate) {
		uint64_t old_offset = cluster_offset & s->cluster_mask;
		// TODO what if this is compressed?
		uint8_t *cow_buffer;

		tcmu_err("re-allocating shared cluster for writing\n");
		/* refcount > 1 (the copied bit means refcount == 1)
		 * need to make a new copy if this is for a write */
		if (!(cow_buffer = malloc(s->cluster_size)))
			goto fail;
		if (!(cluster_offset = qcow_cluster_alloc(s)))
			goto fail;
		if (pread(s->fd, cow_buffer, s->cluster_size, old_offset) != s->cluster_size)
			goto fail;
		if (pwrite(s->fd, cow_buffer, s->cluster_size, cluster_offset) != s->cluster_size)
			goto fail;
		free(cow_buffer);
		l2_table_update(s, l2_table, l2_offset, l2_index, cluster_offset | s->cluster_copied);
		s->set_refcount(s, cluster_offset, 1);
		// TODO drop refcount on old cluster
		goto out;
	fail:
		tcmu_err("CoW failed\n");
		free(cow_buffer);
		return 0;
	}
out:
	return cluster_offset & ~(s->cluster_copied);
}

/* returns number of iovs initialized in seg */
static size_t iovec_segment(struct iovec *iov, struct iovec *seg, size_t off, size_t len)
{
	struct iovec *seg_start = seg;

	while (off) {
		if (off >= iov->iov_len) {
			off -= iov->iov_len;
			iov++;
		} else {
			seg->iov_base = iov->iov_base + off;
			seg->iov_len = min(iov->iov_len - off, len);
			off = 0;
			len -= seg->iov_len;
			iov++;
			seg++;
		}
	}
	while (len) {
		seg->iov_base = iov->iov_base;
		seg->iov_len = min(iov->iov_len, len);
		len -= seg->iov_len;
		iov++;
		seg++;
	}

	return seg - seg_start;
}

static void iovec_memset(struct iovec *iov, int iovcnt, int c, size_t len)
{
	while (len && iovcnt) {
		size_t n = min(iov->iov_len, len);
		memset(iov->iov_base, c, n);
		len -= n;
		iov++;
		iovcnt--;
	}
}

static ssize_t qcow_preadv(struct bdev *bdev, struct iovec *iov, int iovcnt, off_t offset)
{
	uint64_t cluster_offset;
	uint64_t sector_index;
	uint64_t sector_count;
	uint64_t sector_num, n;
	ssize_t read;

	struct qcow_state *s = bdev->private;

	struct iovec _iov[iovcnt];
	size_t _cnt;
	size_t _off = 0;

	size_t count = tcmu_iovec_length(iov, iovcnt);

	assert(!(count & 511));
	sector_count = count / 512;
	sector_num = offset >> 9;

	while (sector_count) {
		sector_index = sector_num & (s->cluster_sectors - 1);
		n = min(sector_count, (s->cluster_sectors - sector_index));

		_cnt = iovec_segment(iov, _iov, _off, n * 512);

		cluster_offset = get_cluster_offset(s, sector_num << 9, false);
		if (!cluster_offset) {
			if (!s->backing_image) {
				/* read unallocated sectors as 0s */
				iovec_memset(_iov, _cnt, 0, 512 * n);
			} else {
				/* pass through to backing file */
				read = s->backing_image->ops->preadv(s->backing_image,
								    _iov, _cnt,
								    (off_t) sector_num * 512);
				if (read != n * 512)
					break;
			}
		} else if (cluster_offset == QCOW2_OFLAG_ZERO) {
			/* cluster discarded, read as 0s */
			iovec_memset(_iov, _cnt, 0, 512 * n);
		} else if (cluster_offset & s->cluster_compressed) {
			if (decompress_cluster(s, cluster_offset) < 0) {
				tcmu_err("decompression failure\n");
				return -1;
			}
			tcmu_memcpy_into_iovec(_iov, _cnt, s->cluster_cache + sector_index * 512, 512 * n);
		} else {
			read = preadv(bdev->fd, _iov, _cnt, cluster_offset + (sector_index * 512));
			if (read != n * 512)
				break;
		}
		sector_count -= n;
		sector_num += n;
		_off += n * 512;
	}
	return _off ? _off : -1;
}

static ssize_t qcow_pwritev(struct bdev *bdev, struct iovec *iov, int iovcnt, off_t offset)
{
	uint64_t cluster_offset;
	uint64_t sector_index;
	uint64_t sector_count;
	uint64_t sector_num, n;
	ssize_t written;

	struct qcow_state *s = bdev->private;

	struct iovec _iov[iovcnt];
	size_t _cnt;
	size_t _off = 0;

	size_t count = tcmu_iovec_length(iov, iovcnt);

	assert(!(count & 511));
	sector_count = count / 512;
	sector_num = offset >> 9;

	if (sector_num >= s->size / 512) {
		return 0;
	}
	sector_count = min(sector_count, s->size / 512 - sector_num);

	while (sector_count) {
		sector_index = sector_num & (s->cluster_sectors - 1);
		n = min(sector_count, (s->cluster_sectors - sector_index));

		_cnt = iovec_segment(iov, _iov, _off, n * 512);

		cluster_offset = get_cluster_offset(s, sector_num << 9, true);
		if (!cluster_offset) {
			tcmu_err("cluster not allocated for writes\n");
			return -1;
		} else if (cluster_offset & QCOW_OFLAG_COMPRESSED) {
			/* compressed clusters should be copied and inflated in
			 * get_cluster_offset() with alloc=true */
			tcmu_err("cluster decompression CoW failure\n");
			return -1;
		} else {
			written = pwritev(bdev->fd, _iov, _cnt, cluster_offset + (sector_index * 512));
			if (written < 0)
				break;
		}
		sector_count -= n;
		sector_num += n;
		_off += n * 512;
	}
	return _off ? _off : -1;
}

static struct bdev_ops qcow_ops = {
	.probe = qcow_probe,
	.open = qcow_image_open,
	.close = qcow_image_close,
	.preadv = qcow_preadv,
	.pwritev = qcow_pwritev,
};

static struct bdev_ops qcow2_ops = {
	.probe = qcow2_probe,
	.open = qcow2_image_open,
	.close = qcow_image_close,
	.preadv = qcow_preadv,
	.pwritev = qcow_pwritev,
};

/* raw image support for backing files */

static int raw_probe(struct bdev *bdev, int dirfd, const char *pathname)
{
	struct stat st;

	tcmu_dbg("%s\n", __func__);

	if (faccessat(dirfd, pathname, R_OK, AT_EACCESS) == -1)
		return -1;
	if (fstatat(dirfd, pathname, &st, 0) == -1)
		return -1;
	/* raw file size must match expected device size */
	if (st.st_size != bdev->size)
		return -1;
	return 0;
}

static int raw_image_open(struct bdev *bdev, int dirfd, const char *pathname, int flags)
{
	bdev->fd = openat(dirfd, pathname, flags);
	tcmu_dbg("%d: %s\n", bdev->fd, pathname);
	return bdev->fd;
}

static void raw_image_close(struct bdev *bdev)
{
	close(bdev->fd);
}

static ssize_t raw_preadv(struct bdev *bdev, struct iovec *iov, int iovcnt, off_t offset)
{
	return preadv(bdev->fd, iov, iovcnt, offset);
}

static ssize_t raw_pwritev(struct bdev *bdev, struct iovec *iov, int iovcnt, off_t offset)
{
	return pwritev(bdev->fd, iov, iovcnt, offset);
}

static struct bdev_ops raw_ops = {
	.probe = raw_probe,
	.open = raw_image_open,
	.close = raw_image_close,
	.preadv = raw_preadv,
	.pwritev = raw_pwritev,
};

/* TCMU QCOW Handler */

static int qcow_open(struct tcmu_device *dev, bool reopen)
{
	struct bdev *bdev;
	char *config;

	bdev = calloc(1, sizeof(*bdev));
	if (!bdev)
		return -1;

	tcmu_set_dev_private(dev, bdev);

	bdev->block_size = tcmu_get_dev_block_size(dev);
	bdev->size = tcmu_get_dev_size(dev);
	if (bdev->size < 0) {
		tcmu_err("Could not get device size\n");
		goto err;
	}

	config = strchr(tcmu_get_dev_cfgstring(dev), '/');
	if (!config) {
		tcmu_err("no configuration found in cfgstring\n");
		goto err;
	}
	config += 1; /* get past '/' */

	tcmu_dbg("%s\n", tcmu_get_dev_cfgstring(dev));
	tcmu_dbg("%s\n", config);

	/*
	 * Force WCE=1 until we support reconfig for WCE
	 */
	tcmu_set_dev_write_cache_enabled(dev, 1);

	if (bdev_open(bdev, AT_FDCWD, config, O_RDWR) == -1)
		goto err;
	return 0;
err:
	free(bdev);
	return -1;
}

static void qcow_close(struct tcmu_device *dev)
{
	struct bdev *bdev = tcmu_get_dev_private(dev);

	bdev->ops->close(bdev);
	free(bdev);
}

static int qcow_read(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
		     struct iovec *iovec, size_t iov_cnt, size_t length,
		     off_t offset)
{
	struct bdev *bdev = tcmu_get_dev_private(dev);
	size_t remaining = length;
	ssize_t ret;

	while (remaining) {
		ret = bdev->ops->preadv(bdev, iovec, iov_cnt, offset);
		if (ret < 0) {
			tcmu_err("read failed: %m\n");
			ret = TCMU_STS_RD_ERR;
			goto done;
		}
		tcmu_seek_in_iovec(iovec, ret);
		offset += ret;
		remaining -= ret;
	}
	ret = TCMU_STS_OK;
done:
	cmd->done(dev, cmd, ret);
	return TCMU_STS_OK;
}

static int qcow_write(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
		      struct iovec *iovec, size_t iov_cnt, size_t length,
		      off_t offset)
{
	struct bdev *bdev = tcmu_get_dev_private(dev);
	size_t remaining = length;
	ssize_t ret;

	while (remaining) {
		ret = bdev->ops->pwritev(bdev, iovec, iov_cnt, offset);
		if (ret < 0) {
			tcmu_err("write failed: %m\n");
			ret = TCMU_STS_WR_ERR;
			goto done;
		}
		tcmu_seek_in_iovec(iovec, ret);
		offset += ret;
		remaining -= ret;
	}
	ret = TCMU_STS_OK;
done:
	cmd->done(dev, cmd, ret);
	return TCMU_STS_OK;
}

static int qcow_flush(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct bdev *bdev = tcmu_get_dev_private(dev);
	int ret;

	if (fsync(bdev->fd)) {
		tcmu_dev_err(dev, "sync failed\n");
		ret = TCMU_STS_WR_ERR;
		goto done;
	}
	ret = TCMU_STS_OK;
done:
	cmd->done(dev, cmd, ret);
	return TCMU_STS_OK;
}

static const char qcow_cfg_desc[] = "The path to the QEMU QCOW image file.";

static struct tcmulib_backstore_handler qcow_handler = {
	.name = "QEMU Copy-On-Write image file",
	.subtype = "qcow",
	.cfg_desc = qcow_cfg_desc,

	.open = qcow_open,
	.close = qcow_close,
	.write = qcow_write,
	.flush = qcow_flush,
	.read = qcow_read,
	.nr_threads = 1,
};

/* Entry point must be named "handler_init". */
int handler_init(void)
{
	return tcmulib_register_backstore_handler(&qcow_handler);
}
