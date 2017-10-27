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

/*
 * A daemon that supports a simplified interface for writing TCMU
 * handlers.
 */

#define _GNU_SOURCE
#define _BITS_UIO_H
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <assert.h>
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <glib.h>
#include <glib-unix.h>
#include <gio/gio.h>
#include <getopt.h>
#include <poll.h>
#include <scsi/scsi.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <libkmod.h>
#include <sys/utsname.h>
#include "target_core_user_local.h"
#include "darray.h"
#include "tcmu-runner.h"
#include "tcmur_aio.h"
#include "tcmur_device.h"
#include "tcmur_cmd_handler.h"
#include "libtcmu.h"
#include "tcmuhandler-generated.h"
#include "version.h"
#include "libtcmu_config.h"
#include "libtcmu_log.h"

static char *handler_path = DEFAULT_HANDLER_PATH;

static struct tcmu_config *tcmu_cfg;

darray(struct tcmur_handler *) g_runner_handlers = darray_new();

int tcmur_register_handler(struct tcmur_handler *handler)
{
	struct tcmur_handler *h;
	int i;

	for (i = 0; i < darray_size(g_runner_handlers); i++) {
		h = darray_item(g_runner_handlers, i);
		if (!strcmp(h->subtype, handler->subtype)) {
			tcmu_err("Handler %s has already been registered\n",
				 handler->subtype);
			return -1;
		}
	}

	darray_append(g_runner_handlers, handler);
	return 0;
}

static int tcmur_register_dbus_handler(struct tcmur_handler *handler)
{
	assert(handler->_is_dbus_handler == true);
	return tcmur_register_handler(handler);
}

bool tcmur_unregister_handler(struct tcmur_handler *handler)
{
	int i;
	for (i = 0; i < darray_size(g_runner_handlers); i++) {
		if (darray_item(g_runner_handlers, i) == handler) {
			darray_remove(g_runner_handlers, i);
			return true;
		}
	}
	return false;
}

static void free_dbus_handler(struct tcmur_handler *handler)
{
	g_free((char*)handler->opaque);
	g_free((char*)handler->subtype);
	g_free((char*)handler->cfg_desc);
	g_free(handler);
}

static bool tcmur_unregister_dbus_handler(struct tcmur_handler *handler)
{
	bool ret = false;
	assert(handler->_is_dbus_handler == true);

	ret = tcmur_unregister_handler(handler);

	if (ret == true) {
		free_dbus_handler(handler);
	}

	return ret;
}

static int is_handler(const struct dirent *dirent)
{
	if (strncmp(dirent->d_name, "handler_", 8))
		return 0;

	return 1;
}

static int open_handlers(void)
{
	struct dirent **dirent_list;
	int num_handlers;
	int num_good = 0;
	char *error;
	int i;

	num_handlers = scandir(handler_path, &dirent_list, is_handler, alphasort);

	if (num_handlers == -1)
		return -1;

	for (i = 0; i < num_handlers; i++) {
		char *path;
		void *handle;
		int (*handler_init)(void);
		int ret;

		ret = asprintf(&path, "%s/%s", handler_path, dirent_list[i]->d_name);
		if (ret == -1) {
			tcmu_err("ENOMEM\n");
			continue;
		}

		handle = dlopen(path, RTLD_NOW|RTLD_LOCAL);
		if (!handle) {
			tcmu_err("Could not open handler at %s: %s\n", path, dlerror());
			free(path);
			continue;
		}

		dlerror();
		handler_init = dlsym(handle, "handler_init");
		if ((error = dlerror())) {
			tcmu_err("dlsym failure on %s: (%s)\n", path, error);
			free(path);
			continue;
		}

		ret = handler_init();
		if (ret) {
			tcmu_err("handler init failed on path %s\n", path);
			free(path);
			continue;
		}

		free(path);

		if (ret == 0)
			num_good++;
	}

	for (i = 0; i < num_handlers; i++)
		free(dirent_list[i]);
	free(dirent_list);

	return num_good;
}

static gboolean sighandler(gpointer user_data)
{
	/*
	 * FIXME: this is broken if IO is running in runner when called.
	 * IO could be running in the handler or runner and we could free
	 * resources while in use.
	 */
	tcmulib_cleanup_all_cmdproc_threads();
	g_main_loop_quit((GMainLoop*)user_data);

	return G_SOURCE_CONTINUE;
}

gboolean tcmulib_callback(GIOChannel *source,
			  GIOCondition condition,
			  gpointer data)
{
	struct tcmulib_context *ctx = data;

	tcmulib_master_fd_ready(ctx);

	return TRUE;
}

static GDBusObjectManagerServer *manager = NULL;

static gboolean
on_check_config(TCMUService1 *interface,
		GDBusMethodInvocation *invocation,
		gchar *cfgstring,
		gpointer user_data)
{
	struct tcmur_handler *handler = user_data;
	char *reason = NULL;
	bool str_ok = true;

	if (handler->check_config)
		str_ok = handler->check_config(cfgstring, &reason);

	if (str_ok)
		reason = "success";

	g_dbus_method_invocation_return_value(invocation,
		    g_variant_new("(bs)", str_ok, reason ? : "unknown"));

	if (!str_ok)
		free(reason);

	return TRUE;
}

static void
dbus_export_handler(struct tcmur_handler *handler, GCallback check_config)
{
	GDBusObjectSkeleton *object;
	char obj_name[128];
	TCMUService1 *interface;

	snprintf(obj_name, sizeof(obj_name), "/org/kernel/TCMUService1/%s",
		 handler->subtype);
	object = g_dbus_object_skeleton_new(obj_name);
	interface = tcmuservice1_skeleton_new();
	g_dbus_object_skeleton_add_interface(object, G_DBUS_INTERFACE_SKELETON(interface));
	g_signal_connect(interface,
			 "handle-check-config",
			 check_config,
			 handler); /* user_data */
	tcmuservice1_set_config_desc(interface, handler->cfg_desc);
	g_dbus_object_manager_server_export(manager, G_DBUS_OBJECT_SKELETON(object));
	g_object_unref(object);
}

static bool
dbus_unexport_handler(struct tcmur_handler *handler)
{
	char obj_name[128];

	snprintf(obj_name, sizeof(obj_name), "/org/kernel/TCMUService1/%s",
		 handler->subtype);
	return g_dbus_object_manager_server_unexport(manager, obj_name) == TRUE;
}

struct dbus_info {
	guint watcher_id;
	/* The RegisterHandler invocation on
	 * org.kernel.TCMUService1.HandlerManager1 interface. */
	GDBusMethodInvocation *register_invocation;
	/* Connection to the handler's bus_name. */
	GDBusConnection *connection;
};

static int dbus_handler_open(struct tcmu_device *dev)
{
	return -1;
}

static void dbus_handler_close(struct tcmu_device *dev)
{
	/* nop */
}

static int dbus_handler_handle_cmd(struct tcmu_device *dev,
				   struct tcmulib_cmd *cmd)
{
	abort();
}

static gboolean
on_dbus_check_config(TCMUService1 *interface,
		     GDBusMethodInvocation *invocation,
		     gchar *cfgstring,
		     gpointer user_data)
{
	char *bus_name, *obj_name;
	struct tcmur_handler *handler = user_data;
	GDBusConnection *connection;
	GError *error = NULL;
	GVariant *result;

	bus_name = g_strdup_printf("org.kernel.TCMUService1.HandlerManager1.%s",
				   handler->subtype);
	obj_name = g_strdup_printf("/org/kernel/TCMUService1/HandlerManager1/%s",
				   handler->subtype);
	connection = g_dbus_method_invocation_get_connection(invocation);
	result = g_dbus_connection_call_sync(connection,
					     bus_name,
					     obj_name,
					     "org.kernel.TCMUService1",
					     "CheckConfig",
					     g_variant_new("(s)", cfgstring),
					     NULL, G_DBUS_CALL_FLAGS_NONE, -1,
					     NULL, &error);
	if (result)
		g_dbus_method_invocation_return_value(invocation, result);
	else
		g_dbus_method_invocation_return_value(invocation,
			g_variant_new("(bs)", FALSE, error->message));
	g_free(bus_name);
	g_free(obj_name);
	return TRUE;
}

static void
on_handler_appeared(GDBusConnection *connection,
		    const gchar     *name,
		    const gchar     *name_owner,
		    gpointer         user_data)
{
	struct tcmur_handler *handler = user_data;
	struct dbus_info *info = handler->opaque;

	if (info->register_invocation) {
		info->connection = connection;
		tcmur_register_dbus_handler(handler);
		dbus_export_handler(handler, G_CALLBACK(on_dbus_check_config));
		g_dbus_method_invocation_return_value(info->register_invocation,
			    g_variant_new("(bs)", TRUE, "succeeded"));
		info->register_invocation = NULL;
	}
}

static void
on_handler_vanished(GDBusConnection *connection,
		    const gchar     *name,
		    gpointer         user_data)
{
	struct tcmur_handler *handler = user_data;
	struct dbus_info *info = handler->opaque;

	if (info->register_invocation) {
		char *reason;
		reason = g_strdup_printf("Cannot find handler bus name: "
				"org.kernel.TCMUService1.HandlerManager1.%s",
				handler->subtype);
		g_dbus_method_invocation_return_value(info->register_invocation,
			    g_variant_new("(bs)", FALSE, reason));
		g_free(reason);
	}
	dbus_unexport_handler(handler);
	g_bus_unwatch_name(info->watcher_id);
	tcmur_unregister_dbus_handler(handler);
}

static gboolean
on_register_handler(TCMUService1HandlerManager1 *interface,
		    GDBusMethodInvocation *invocation,
		    gchar *subtype,
		    gchar *cfg_desc,
		    gpointer user_data)
{
	struct tcmur_handler *handler;
	struct dbus_info *info;
	char *bus_name;

	bus_name = g_strdup_printf("org.kernel.TCMUService1.HandlerManager1.%s",
				   subtype);

	handler               = g_new0(struct tcmur_handler, 1);
	handler->subtype      = g_strdup(subtype);
	handler->cfg_desc     = g_strdup(cfg_desc);
	handler->open         = dbus_handler_open;
	handler->close        = dbus_handler_close;
	handler->handle_cmd   = dbus_handler_handle_cmd;

	info = g_new0(struct dbus_info, 1);
	handler->opaque = info;
	handler->_is_dbus_handler = 1;
	info->register_invocation = invocation;
	info->watcher_id = g_bus_watch_name(G_BUS_TYPE_SYSTEM,
					    bus_name,
					    G_BUS_NAME_WATCHER_FLAGS_NONE,
					    on_handler_appeared,
					    on_handler_vanished,
					    handler,
					    NULL);
	if (info->watcher_id == 0) {
		// probably an invalid name, roll back and report an error
		free_dbus_handler(handler);

		g_dbus_method_invocation_return_value(invocation,
			g_variant_new("(bs)", FALSE,
				      "failed to watch for DBus handler name"));
	}
	g_free(bus_name);
	return TRUE;
}

void dbus_handler_manager1_init(GDBusConnection *connection)
{
	GError *error = NULL;
	TCMUService1HandlerManager1 *interface;
	gboolean ret;

	interface = tcmuservice1_handler_manager1_skeleton_new();
	ret = g_dbus_interface_skeleton_export(
			G_DBUS_INTERFACE_SKELETON(interface),
			connection,
			"/org/kernel/TCMUService1/HandlerManager1",
			&error);
	g_signal_connect(interface,
			 "handle-register-handler",
			 G_CALLBACK (on_register_handler),
			 NULL);
	if (!ret)
		tcmu_err("Handler manager export failed: %s\n",
		     error ? error->message : "unknown error");
	if (error)
		g_error_free(error);
}

static void dbus_bus_acquired(GDBusConnection *connection,
			      const gchar *name,
			      gpointer user_data)
{
	struct tcmur_handler **handler;

	tcmu_dbg("bus %s acquired\n", name);

	manager = g_dbus_object_manager_server_new("/org/kernel/TCMUService1");

	darray_foreach(handler, g_runner_handlers) {
		dbus_export_handler(*handler, G_CALLBACK(on_check_config));
	}

	dbus_handler_manager1_init(connection);
	g_dbus_object_manager_server_set_connection(manager, connection);
}

static void dbus_name_acquired(GDBusConnection *connection,
			      const gchar *name,
			      gpointer user_data)
{
	tcmu_dbg("name %s acquired\n", name);
}

static void dbus_name_lost(GDBusConnection *connection,
			   const gchar *name,
			   gpointer user_data)
{
	tcmu_dbg("name lost\n");
}

static int load_our_module(void)
{
	struct kmod_list *list = NULL, *itr;
	struct kmod_ctx *ctx;
	struct stat sb;
	struct utsname u;
	int ret;

	ctx = kmod_new(NULL, NULL);
	if (!ctx) {
		tcmu_err("kmod_new() failed: %m\n");
		return -1;
	}

	ret = kmod_module_new_from_lookup(ctx, "target_core_user", &list);
	if (ret < 0) {
		/* In some environments like containers, /lib/modules/`uname -r`
		 * will not exist, in such cases the load module job be taken
		 * care by admin, either by manual load or makesure it's builtin
		 */
		if (ENOENT == errno) {
			if (uname(&u) < 0) {
				tcmu_err("uname() failed: %m\n");
			} else {
				tcmu_info("no modules directory '/lib/modules/%s', checking module target_core_user entry in '/sys/modules/'\n",
					  u.release);
				ret = stat("/sys/module/target_core_user", &sb);
				if (!ret) {
					tcmu_dbg("Module target_core_user already loaded\n");
				} else {
					tcmu_err("stat() on '/sys/module/target_core_user' failed: %m\n");
				}
			}
		} else {
			tcmu_err("kmod_module_new_from_lookup() failed to lookup alias target_core_use %m\n");
		}

		kmod_unref(ctx);
		return ret;
	}

	if (!list) {
		tcmu_err("kmod_module_new_from_lookup() failed to find module target_core_user\n");
		kmod_unref(ctx);
		return -ENOENT;
	}

	kmod_list_foreach(itr, list) {
		int state, err;
		struct kmod_module *mod = kmod_module_get_module(itr);

		state = kmod_module_get_initstate(mod);
		switch (state) {
		case KMOD_MODULE_BUILTIN:
			tcmu_info("Module '%s' is builtin\n",
			          kmod_module_get_name(mod));
			break;

		case KMOD_MODULE_LIVE:
			tcmu_dbg("Module '%s' is already loaded\n",
			         kmod_module_get_name(mod));
			break;

		default:
			err = kmod_module_probe_insert_module(mod,
			                               KMOD_PROBE_APPLY_BLACKLIST,
			                               NULL, NULL, NULL, NULL);

			if (err == 0) {
				tcmu_info("Inserted module '%s'\n",
				          kmod_module_get_name(mod));
			} else if (err == KMOD_PROBE_APPLY_BLACKLIST) {
				tcmu_err("Module '%s' is blacklisted\n",
				         kmod_module_get_name(mod));
			} else {
				tcmu_err("Failed to insert '%s'\n",
				         kmod_module_get_name(mod));
			}
			ret = err;
		}
		kmod_module_unref(mod);
	}

	kmod_module_unref_list(list);
	kmod_unref(ctx);

	return ret;
}

/*
 * tcmur_stop_device - stop device for removal
 * @arg: tcmu_device to stop
 *
 * Stop internal tcmur device operations like lock and recovery and close
 * the device. Running IO must be stopped before calling this.
 */
static void tcmur_stop_device(void *arg)
{
	struct tcmu_device *dev = arg;
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	bool is_open = false;

	pthread_mutex_lock(&rdev->state_lock);
	/* check if this was already called due to thread cancelation */
	if (rdev->flags & TCMUR_DEV_FLAG_STOPPED) {
		pthread_mutex_unlock(&rdev->state_lock);
		return;
	}
	rdev->flags |= TCMUR_DEV_FLAG_STOPPING;
	pthread_mutex_unlock(&rdev->state_lock);

	/*
	 * The lock thread can fire off the recovery thread, so make sure
	 * it is done first.
	 */
	tcmu_cancel_lock_thread(dev);
	tcmu_cancel_recovery(dev);

	pthread_mutex_lock(&rdev->state_lock);
	if (rdev->flags & TCMUR_DEV_FLAG_IS_OPEN) {
		rdev->flags &= ~TCMUR_DEV_FLAG_IS_OPEN;
		is_open = true;
	}
	pthread_mutex_unlock(&rdev->state_lock);

	if (is_open)
		rhandler->close(dev);

	pthread_mutex_lock(&rdev->state_lock);
	rdev->flags |= TCMUR_DEV_FLAG_STOPPED;
	pthread_mutex_unlock(&rdev->state_lock);

	tcmu_dev_dbg(dev, "cmdproc cleanup done\n");
}

static void *tcmur_cmdproc_thread(void *arg)
{
	struct tcmu_device *dev = arg;
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	struct pollfd pfd;
	int ret;
	bool dev_stopping = false;

	pthread_cleanup_push(tcmur_stop_device, dev);

	while (1) {
		int completed = 0;
		struct tcmulib_cmd *cmd;

		tcmulib_processing_start(dev);

		while (!dev_stopping && (cmd = tcmulib_get_next_command(dev)) != NULL) {

			if (tcmu_get_log_level() == TCMU_LOG_DEBUG_SCSI_CMD)
				tcmu_cdb_debug_info(dev, cmd);

			if (tcmur_handler_is_passthrough_only(rhandler))
				ret = tcmur_cmd_passthrough_handler(dev, cmd);
			else
				ret = tcmur_generic_handle_cmd(dev, cmd);

			if (ret == TCMU_NOT_HANDLED)
				tcmu_dev_warn(dev, "Command 0x%x not supported\n", cmd->cdb[0]);

			/*
			 * command (processing) completion is called in the following
			 * scenarios:
			 *   - handle_cmd: synchronous handlers
			 *   - generic_handle_cmd: non tcmur handler calls (see generic_cmd())
			 *			   and on errors when calling tcmur handler.
			 */
			if (ret != TCMU_ASYNC_HANDLED) {
				completed = 1;
				tcmur_command_complete(dev, cmd, ret);
			}
		}

		if (completed)
			tcmulib_processing_complete(dev);

		pfd.fd = tcmu_get_dev_fd(dev);
		pfd.events = POLLIN;
		pfd.revents = 0;

		/* Use ppoll instead poll to avoid poll call reschedules during signal
		 * handling. If we were removing a device, then the uio device's memory
		 * could be freed, but the poll would be rescheduled and end up accessing
		 * the released device. */
		ret = ppoll(&pfd, 1, NULL, NULL);
		if (ret == -1) {
			tcmu_err("ppoll() returned %d\n", ret);
			break;
		}

		if (pfd.revents != POLLIN) {
			tcmu_err("ppoll received unexpected revent: 0x%x\n", pfd.revents);
			break;
		}

		/*
		 * LIO will wait for outstanding requests and prevent new ones
		 * from being sent to runner during device removal, but if the
		 * tcmu cmd_time_out has fired tcmu-runner may still be executing
		 * requests that LIO has completed. We only need to wait for replies
		 * for outstanding requests so throttle the cmdproc thread now.
		 */
		pthread_mutex_lock(&rdev->state_lock);
		if (rdev->flags & TCMUR_DEV_FLAG_STOPPING)
			dev_stopping = true;
		pthread_mutex_unlock(&rdev->state_lock);
	}

	/*
	 * If we are doing a clean shutdown via dev_removed the
	 * removing thread will call the cleanup function when
	 * it has stopped and flushed the device.
	 */
	pthread_cleanup_pop(0);
	return NULL;
}

static int dev_resize(struct tcmu_device *dev, struct tcmulib_cfg_info *cfg)
{
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);
	int ret;

	if (tcmu_get_dev_num_lbas(dev) * tcmu_get_dev_block_size(dev) ==
	    cfg->data.dev_size)
		return 0;

	ret = rhandler->reconfig(dev, cfg);
	if (ret)
		return ret;

	ret = tcmu_update_num_lbas(dev, cfg->data.dev_size);
	if (!ret)
		tcmur_set_pending_ua(dev, TCMUR_UA_DEV_SIZE_CHANGED);

	return ret;
}

static int dev_reconfig(struct tcmu_device *dev, struct tcmulib_cfg_info *cfg)
{
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);

	if (!rhandler->reconfig)
		return -EOPNOTSUPP;

	switch (cfg->type) {
	case TCMULIB_CFG_DEV_SIZE:
		return dev_resize(dev, cfg);
	default:
		return rhandler->reconfig(dev, cfg);
	}
}

static int dev_added(struct tcmu_device *dev)
{
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);
	struct tcmur_device *rdev;
	int32_t block_size, max_sectors;
	uint32_t max_xfer_length;
	int64_t dev_size;
	int ret;

	rdev = calloc(1, sizeof(*rdev));
	if (!rdev)
		return -ENOMEM;
	tcmu_set_daemon_dev_private(dev, rdev);
	list_node_init(&rdev->recovery_entry);
	rdev->dev = dev;

	ret = -EINVAL;
	block_size = tcmu_get_attribute(dev, "hw_block_size");
	if (block_size <= 0) {
		tcmu_dev_err(dev, "Could not get hw_block_size\n");
		goto free_rdev;
	}
	tcmu_set_dev_block_size(dev, block_size);

	dev_size = tcmu_get_device_size(dev);
	if (dev_size < 0) {
		tcmu_dev_err(dev, "Could not get device size\n");
		goto free_rdev;
	}
	tcmu_set_dev_num_lbas(dev, dev_size / block_size);

	max_sectors = tcmu_get_attribute(dev, "hw_max_sectors");
	if (max_sectors < 0)
		goto free_rdev;
	tcmu_set_dev_max_xfer_len(dev, max_sectors);

	tcmu_dev_dbg(dev, "Got block_size %ld, size in bytes %lld\n",
		     block_size, dev_size);

	ret = pthread_spin_init(&rdev->lock, 0);
	if (ret != 0)
		goto free_rdev;

	ret = pthread_mutex_init(&rdev->caw_lock, NULL);
	if (ret != 0)
		goto cleanup_dev_lock;

	ret = pthread_mutex_init(&rdev->format_lock, NULL);
	if (ret != 0)
		goto cleanup_caw_lock;

	ret = pthread_mutex_init(&rdev->state_lock, NULL);
	if (ret != 0)
		goto cleanup_format_lock;

	ret = setup_io_work_queue(dev);
	if (ret < 0)
		goto cleanup_state_lock;

	ret = setup_aio_tracking(rdev);
	if (ret < 0)
		goto cleanup_io_work_queue;

	ret = rhandler->open(dev);
	if (ret)
		goto cleanup_aio_tracking;
	rdev->flags |= TCMUR_DEV_FLAG_IS_OPEN;

	/*
	 * Set the optimal unmap granularity to max xfer len. Optimal unmap
	 * alignment starts at the begining of the device.
	 */
	max_xfer_length = tcmu_get_dev_max_xfer_len(dev);
	tcmu_set_dev_opt_unmap_gran(dev, max_xfer_length);
	tcmu_set_dev_unmap_gran_align(dev, 0);

	ret = tcmulib_start_cmdproc_thread(dev, tcmur_cmdproc_thread);
	if (ret < 0)
		goto close_dev;

	return 0;

close_dev:
	rhandler->close(dev);
cleanup_aio_tracking:
	cleanup_aio_tracking(rdev);
cleanup_io_work_queue:
	cleanup_io_work_queue(dev, true);
cleanup_state_lock:
	pthread_mutex_destroy(&rdev->state_lock);
cleanup_format_lock:
	pthread_mutex_destroy(&rdev->format_lock);
cleanup_caw_lock:
	pthread_mutex_destroy(&rdev->caw_lock);
cleanup_dev_lock:
	pthread_spin_destroy(&rdev->lock);
free_rdev:
	free(rdev);
	return ret;
}

static void dev_removed(struct tcmu_device *dev)
{
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	int ret;

	pthread_mutex_lock(&rdev->state_lock);
	rdev->flags |= TCMUR_DEV_FLAG_STOPPING;
	pthread_mutex_unlock(&rdev->state_lock);

	/*
	 * The order of cleaning up worker threads and calling ->removed()
	 * is important: for sync handlers, the worker thread needs to be
	 * terminated before removing the handler (i.e., calling handlers
	 * ->close() callout) in order to ensure that no handler callouts
	 * are getting invoked when shutting down the handler.
	 */
	cleanup_io_work_queue_threads(dev);

	if (aio_wait_for_empty_queue(rdev))
		tcmu_dev_err(dev, "could not flush queue.\n");
	tcmulib_cleanup_cmdproc_thread(dev);
	tcmur_stop_device(dev);

	cleanup_io_work_queue(dev, false);
	cleanup_aio_tracking(rdev);

	ret = pthread_mutex_destroy(&rdev->state_lock);
	if (ret != 0)
		tcmu_err("could not cleanup state lock %d\n", ret);

	ret = pthread_mutex_destroy(&rdev->format_lock);
	if (ret != 0)
		tcmu_err("could not cleanup format lock %d\n", ret);

	ret = pthread_mutex_destroy(&rdev->caw_lock);
	if (ret != 0)
		tcmu_err("could not cleanup caw lock %d\n", ret);

	ret = pthread_spin_destroy(&rdev->lock);
	if (ret != 0)
		tcmu_err("could not cleanup mailbox lock %d\n", ret);

	free(rdev);
}

#define TCMUR_MIN_OPEN_FD 65536
#define TCMUR_MAX_OPEN_FD 1048576
static int tcmu_set_max_fd_limit(const int nr_files)
{
	struct rlimit old_rlim, new_rlim;
	int ret;

	ret = getrlimit(RLIMIT_NOFILE, &old_rlim);
	if (ret == -1) {
		tcmu_err("failed to get max open fd limit: %m\n");
		return ret;
	}

	if (old_rlim.rlim_cur < nr_files) {
		new_rlim.rlim_cur = nr_files;
		if (old_rlim.rlim_max < nr_files) {
			new_rlim.rlim_max = nr_files;
		} else {
			new_rlim.rlim_max = old_rlim.rlim_max;
		}

		ret = setrlimit(RLIMIT_NOFILE, &new_rlim);
		if (ret == -1) {
			tcmu_err("failed to set max open fd to [soft: %lld hard: %lld] %m\n",
				  (long long int)new_rlim.rlim_cur,
				  (long long int)new_rlim.rlim_max);
			return ret;
		}

		tcmu_info("max open fd set to [soft: %lld hard: %lld]\n",
	                  (long long int)new_rlim.rlim_cur,
			  (long long int)new_rlim.rlim_max);

		return 0;
	}

	tcmu_info("max open fd remain [soft: %lld hard: %lld]\n",
	          (long long int)old_rlim.rlim_cur,
		  (long long int)old_rlim.rlim_max);

	return 0;
}

static void usage(void) {
	printf("\nusage:\n");
	printf("\ttcmu-runner [options]\n");
	printf("\noptions:\n");
	printf("\t-h, --help: print this message and exit\n");
	printf("\t-V, --version: print version and exit\n");
	printf("\t-d, --debug: enable debug messages\n");
	printf("\t-f, --nofile: set maximum file number could be opened\n");
	printf("\t\tdefault will be as the systemd or the shell's limitation\n");
	printf("\t--handler-path: set path to search for handler modules\n");
	printf("\t\tdefault is %s\n", DEFAULT_HANDLER_PATH);
	printf("\t-l, --tcmu-log-dir: tcmu log dir\n");
	printf("\t\tdefault is %s\n", TCMU_LOG_DIR_DEFAULT);
	printf("\n");
}

static struct option long_options[] = {
	{"debug", no_argument, 0, 'd'},
	{"handler-path", required_argument, 0, 0},
	{"tcmu-log-dir", required_argument, 0, 'l'},
	{"nofile", required_argument, 0, 'f'},
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'V'},
	{0, 0, 0, 0},
};

int main(int argc, char **argv)
{
	darray(struct tcmulib_handler) handlers = darray_new();
	struct tcmulib_context *tcmulib_context;
	struct tcmur_handler **tmp_r_handler;
	GMainLoop *loop;
	GIOChannel *libtcmu_gio;
	guint reg_id;
	bool new_path = false;
	int ret;

	while (1) {
		int option_index = 0;
		int c, nr_files;

		c = getopt_long(argc, argv, "df:hl:V",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			if (option_index == 1) {
				handler_path = strdup(optarg);
				new_path = true;
			}
			break;
		case 'l':
			if (!tcmu_logdir_create(optarg))
				goto free_opt;
			break;
		case 'f':
			nr_files = atol(optarg);
			if (nr_files < TCMUR_MIN_OPEN_FD || nr_files > TCMUR_MAX_OPEN_FD) {
				tcmu_err("--nofile=%d should be in [%lu, %lu]\n", nr_files,
					(unsigned long)TCMUR_MIN_OPEN_FD,
					(unsigned long)TCMUR_MAX_OPEN_FD);
				goto free_opt;
			}

			ret = tcmu_set_max_fd_limit(nr_files);
			if (ret)
				goto free_opt;
			break;
		case 'd':
			tcmu_set_log_level(TCMU_CONF_LOG_DEBUG_SCSI_CMD);
			break;
		case 'V':
			tcmu_info("tcmu-runner %s\n", TCMUR_VERSION);
			goto free_opt;
		default:
		case 'h':
			usage();
			goto free_opt;
		}
	}

	if (!tcmu_logdir_getenv())
		goto free_opt;

	/*
	 * The order of setting up config and logger is important, because
	 * the log directory may be configured via the system config file
	 * which will be used in logger setting up.
	 */
	tcmu_cfg = tcmu_setup_config(NULL);
	if (!tcmu_cfg)
		goto free_opt;

	if (tcmu_setup_log())
		goto destroy_config;

	tcmu_dbg("handler path: %s\n", handler_path);

	ret = load_our_module();
	if (ret < 0) {
		tcmu_err("couldn't load module\n");
		goto destroy_log;
	}

	ret = open_handlers();
	if (ret < 0) {
		tcmu_err("couldn't open handlers\n");
		goto destroy_log;
	}
	tcmu_dbg("%d runner handlers found\n", ret);

	/*
	 * Convert from tcmu-runner's handler struct to libtcmu's
	 * handler struct, an array of which we pass in, below.
	 */
	darray_foreach(tmp_r_handler, g_runner_handlers) {
		struct tcmulib_handler tmp_handler;

		tmp_handler.name = (*tmp_r_handler)->name;
		tmp_handler.subtype = (*tmp_r_handler)->subtype;
		tmp_handler.cfg_desc = (*tmp_r_handler)->cfg_desc;
		tmp_handler.check_config = (*tmp_r_handler)->check_config;
		tmp_handler.reconfig = dev_reconfig;
		tmp_handler.added = dev_added;
		tmp_handler.removed = dev_removed;

		/*
		 * Can hand out a ref to an internal pointer to the
		 * darray b/c handlers will never be added or removed
		 * once open_handlers() is done.
		 */
		tmp_handler.hm_private = *tmp_r_handler;

		darray_append(handlers, tmp_handler);
	}

	tcmulib_context = tcmulib_initialize(handlers.item, handlers.size);
	if (!tcmulib_context) {
		tcmu_err("tcmulib_initialize failed\n");
		goto err_free_handlers;
	}

	loop = g_main_loop_new(NULL, FALSE);
	if (g_unix_signal_add(SIGINT, sighandler, loop) <= 0 ||
	    g_unix_signal_add(SIGTERM, sighandler, loop) <= 0) {
		tcmu_err("couldn't setup signal handlers\n");
		goto err_tcmulib_close;
	}

	darray_free(handlers);

	/* Set up event for libtcmu */
	libtcmu_gio = g_io_channel_unix_new(tcmulib_get_master_fd(tcmulib_context));
	g_io_add_watch(libtcmu_gio, G_IO_IN, tcmulib_callback, tcmulib_context);

	/* Set up DBus name, see callback */
	reg_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
				"org.kernel.TCMUService1",
				G_BUS_NAME_OWNER_FLAGS_NONE,
				dbus_bus_acquired,
				dbus_name_acquired, // name acquired
				dbus_name_lost, // name lost
				NULL, // user data
				NULL  // user date free func
		);

	g_main_loop_run(loop);

	tcmu_dbg("Exiting...\n");
	g_bus_unown_name(reg_id);
	g_main_loop_unref(loop);
	g_io_channel_shutdown(libtcmu_gio, TRUE, NULL);
	tcmulib_close(tcmulib_context);

	tcmu_destroy_config(tcmu_cfg);
	tcmu_destroy_log();

	return 0;

err_tcmulib_close:
	tcmulib_close(tcmulib_context);
err_free_handlers:
	darray_free(handlers);
destroy_log:
	tcmu_destroy_log();
destroy_config:
	tcmu_destroy_config(tcmu_cfg);
free_opt:
	if (new_path)
		free(handler_path);
	tcmu_logdir_destroy();

	exit(1);
}
