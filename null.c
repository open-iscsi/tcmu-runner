/*
 * Copyright 2017, Red Hat, Inc.
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
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <scsi/scsi.h>

#include "libtcmu.h"
#include "tcmu-runner.h"

static int null_open(struct tcmu_device *dev)
{
	return 0;
}

static void null_close(struct tcmu_device *dev)
{
	return;
}

static int null_read(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
		     struct iovec *iov, size_t iov_cnt, size_t length,
		     off_t offset)
{
	cmd->done(dev, cmd, SAM_STAT_GOOD);
	return 0;
}

static int null_write(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
		      struct iovec *iov, size_t iov_cnt, size_t length,
		      off_t offset)
{
	cmd->done(dev, cmd, SAM_STAT_GOOD);
	return 0;
}

static int null_flush(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	cmd->done(dev, cmd, SAM_STAT_GOOD);
	return 0;
}

static const char null_cfg_desc[] =
	"Nothing";

static struct tcmur_handler null_handler = {
	.cfg_desc	= null_cfg_desc,
	.name		= "NULL Handler",
	.subtype	= "null",

	.open		= null_open,
	.close		= null_close,

	.read		= null_read,
	.write		= null_write,
	.flush		= null_flush,
};

int handler_init(void)
{
	return tcmur_register_handler(&null_handler);
}
