/*
 * Copyright (c) 2014 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
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
#include "libtcmu_aio.h"
#include "libtcmu_device.h"
#include "tcmur_cmd_handler.h"
#include "libtcmu.h"
#include "tcmuhandler-generated.h"
#include "version.h"
#include "libtcmu_config.h"
#include "libtcmu_log.h"
#include "libtcmu_scsi.h"
#include "libtcmu_alua.h"

# define TCMU_LOCK_FILE   "/var/run/lock/tcmu.lock"

static char *handler_path = DEFAULT_HANDLER_PATH;

static struct tcmu_config *tcmu_cfg;

static int tcmur_register_dbus_handler(struct tcmulib_backstore_handler *handler)
{
	assert(handler->_is_dbus_handler == true);
	return tcmulib_register_backstore_handler(handler);
}

static void free_dbus_handler(struct tcmulib_backstore_handler *handler)
{
	g_free((char*)handler->opaque);
	g_free((char*)handler->subtype);
	g_free((char*)handler->cfg_desc);
	g_free(handler);
}

static bool tcmur_unregister_dbus_handler(struct tcmulib_backstore_handler *handler)
{
	bool ret = false;
	assert(handler->_is_dbus_handler == true);

	ret = tcmulib_unregister_backstore_handler(handler);

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
	tcmu_dbg("Have received signal!\n");

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
	struct tcmulib_backstore_handler *handler = user_data;
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
dbus_export_handler(struct tcmulib_backstore_handler *handler, GCallback check_config)
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
dbus_unexport_handler(struct tcmulib_backstore_handler *handler)
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

static int dbus_handler_open(struct tcmu_device *dev, bool reopen)
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
	struct tcmulib_backstore_handler *handler = user_data;
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
	struct tcmulib_backstore_handler *handler = user_data;
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
	struct tcmulib_backstore_handler *handler = user_data;
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
	struct tcmulib_backstore_handler *handler;
	struct dbus_info *info;
	char *bus_name;

	bus_name = g_strdup_printf("org.kernel.TCMUService1.HandlerManager1.%s",
				   subtype);

	handler               = g_new0(struct tcmulib_backstore_handler, 1);
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
	struct tcmulib_backstore_handler *handler;
	int i = 0;

	tcmu_dbg("bus %s acquired\n", name);

	manager = g_dbus_object_manager_server_new("/org/kernel/TCMUService1");

	while ((handler = tcmulib_next_backstore_handler(&i))) {
		dbus_export_handler(handler, G_CALLBACK(on_check_config));
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

static int dev_handle_cmds(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct tcmulib_backstore_handler *rhandler = tcmu_get_runner_handler(dev);

	if (tcmulib_backstore_handler_is_passthrough_only(rhandler))
		return tcmur_cmd_passthrough_handler(dev, cmd);
	else
		return tcmur_generic_handle_cmd(dev, cmd);
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
	struct tcmulib_backstore_handler *tmp_r_handler;
	GMainLoop *loop;
	GIOChannel *libtcmu_gio;
	guint reg_id;
	bool new_path = false;
	struct flock lock_fd = {0, };
	int fd;
	int ret;
	int i = 0;

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
			if (!tcmu_logdir_create(optarg, false))
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

	fd = creat(TCMU_LOCK_FILE, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		tcmu_err("creat(%s) failed: [%m]\n", TCMU_LOCK_FILE);
		goto destroy_log;
	}

	lock_fd.l_type = F_WRLCK;
	if (fcntl(fd, F_SETLK, &lock_fd) == -1) {
		if (errno == EAGAIN) {
			tcmu_err("tcmu-runner is already running...\n");
		} else {
			tcmu_err("fcntl(F_SETLK) on lockfile %s failed: [%m]\n",
			         TCMU_LOCK_FILE);
		}
		goto close_fd;
	}

	ret = load_our_module();
	if (ret < 0) {
		tcmu_err("couldn't load module\n");
		goto close_fd;
	}

	tcmu_dbg("handler path: %s\n", handler_path);
	ret = open_handlers();
	if (ret < 0) {
		tcmu_err("couldn't open handlers\n");
		goto close_fd;
	}
	tcmu_dbg("%d runner handlers found\n", ret);

	/*
	 * Convert from tcmu-runner's handler struct to libtcmu's
	 * handler struct, an array of which we pass in, below.
	 */
	while ((tmp_r_handler = tcmulib_next_backstore_handler(&i))) {
		struct tcmulib_handler tmp_handler;

		memset(&tmp_handler, 0, sizeof(tmp_handler));
		tmp_handler.name = (tmp_r_handler)->name;
		tmp_handler.subtype = (tmp_r_handler)->subtype;
		tmp_handler.cfg_desc = (tmp_r_handler)->cfg_desc;
		tmp_handler.check_config = (tmp_r_handler)->check_config;
		tmp_handler.handle_cmds = dev_handle_cmds;

		/*
		 * Can hand out a ref to an internal pointer to the
		 * darray b/c handlers will never be added or removed
		 * once open_handlers() is done.
		 */
		tmp_handler.hm_private = tmp_r_handler;

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

	tcmu_info("Exiting...\n");
	g_bus_unown_name(reg_id);
	g_main_loop_unref(loop);
	g_io_channel_shutdown(libtcmu_gio, TRUE, NULL);
	g_object_unref(manager);
	tcmulib_close(tcmulib_context);

	lock_fd.l_type = F_UNLCK;
	if (fcntl(fd, F_SETLK, &lock_fd) == -1) {
		tcmu_err("fcntl(UNLCK) on lockfile %s failed: [%m]\n",
		         TCMU_LOCK_FILE);
	}
	close(fd);

	tcmu_destroy_config(tcmu_cfg);
	tcmu_destroy_log();

	return 0;

err_tcmulib_close:
	tcmulib_close(tcmulib_context);
err_free_handlers:
	darray_free(handlers);
close_fd:
	lock_fd.l_type = F_UNLCK;
	if (fcntl(fd, F_SETLK, &lock_fd) == -1) {
		tcmu_err("fcntl(UNLCK) on lockfile %s failed: [%m]\n",
		         TCMU_LOCK_FILE);
	}
	close(fd);
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
