/*
 * Copyright (c) 2014 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */

/*
 * This header defines structures private to libtcmu, and should not
 * be used by anyone else.
 */

#ifndef __LIBTCMU_PRIV_H
#define __LIBTCMU_PRIV_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/uio.h>
#include <gio/gio.h>
#include <pthread.h>

#include "scsi_defs.h"
#include "darray.h"
#include "ccan/list/list.h"
#include "libtcmu_aio.h"

#define KERN_IFACE_VER 2

// The full (private) declaration
struct tcmulib_context {
	darray(struct tcmulib_handler) handlers;

	/* Just keep ptrs b/c we hand these to clients */
	darray(struct tcmu_device*) devices;

	struct nl_sock *nl_sock;

	GDBusConnection *connection;
};

struct tcmu_device {
	int fd;

	struct tcmu_mailbox *map;
	size_t map_len;

	uint32_t cmd_tail;

	uint64_t num_lbas;
	uint32_t block_size;
	uint32_t max_xfer_len;
	uint32_t opt_unmap_gran;
	uint32_t unmap_gran_align;
	unsigned int write_cache_enabled:1;
	unsigned int solid_state_media:1;

	char dev_name[16]; /* e.g. "uio14" */
	char tcm_hba_name[16]; /* e.g. "user_8" */
	char tcm_dev_name[128]; /* e.g. "backup2" */
	char cfgstring[PATH_MAX];

	struct tcmulib_handler *handler;
	struct tcmulib_context *ctx;

	void *d_private; /* private ptr for the daemon */
	void *hm_private; /* private ptr for handler module */
};

#endif
