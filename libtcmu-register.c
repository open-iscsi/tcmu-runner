/*
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <assert.h>

#include "libtcmu.h"
#include "libtcmu_log.h"
#include "libtcmu_priv.h"
#include "tcmuhandler-generated.h"

static bool
tcmulib_register_handler(struct tcmulib_context *ctx,
			 struct tcmulib_handler *handler)
{
	GError *error = NULL;
	gboolean succeeded;
	const gchar *reason;
	bool ret = true;

	GVariant *result = g_dbus_connection_call_sync(ctx->connection,
		"org.kernel.TCMUService1",
		"/org/kernel/TCMUService1/HandlerManager1",
		"org.kernel.TCMUService1.HandlerManager1",
		"RegisterHandler",
		g_variant_new("(ss)",
			      handler->subtype,
			      handler->cfg_desc),
		g_variant_type_new("(bs)"),
		G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (!result) {
		tcmu_err("Failed to call register method for '%s(%s)': %s",
			  handler->name,
			  handler->subtype,
			  error->message);
		return false;
	}
	g_variant_get(result, "(b&s)", &succeeded, &reason);
	if (!succeeded) {
		tcmu_err("Failed to register method for '%s(%s)': %s",
			  handler->name,
			  handler->subtype,
			  reason);
		ret = false;
	}
	g_variant_unref(result);
	return ret;
}

static void tcmulib_reg_fail(struct tcmulib_context *ctx)
{
	// TODO: Report failures back to process performing registration
}

static gboolean
tcmulib_check_config(TCMUService1 *interface,
		     GDBusMethodInvocation *invocation,
		     gchar *cfgstring,
		     gpointer user_data)
{
	struct tcmulib_handler *handler = user_data;
	char *reason = NULL;
	bool ok;

	ok = handler->check_config ?
		handler->check_config(cfgstring, &reason) :
		TRUE;
	g_dbus_method_invocation_return_value(invocation,
		g_variant_new("(bs)", ok, reason ? : (ok ? "OK" : "unknown")));
	free(reason);
	return TRUE;
}

static void
tcmulib_reg_bus_acquired(GDBusConnection *connection,
			 const gchar *name,
			 gpointer user_data)
{
	struct tcmulib_handler *handler = user_data;
	struct tcmulib_context *ctx = handler->ctx;
	char *obj_path;
	TCMUService1 *interface;
	GError *error = NULL;
	gboolean r;

	interface = tcmuservice1_skeleton_new();

	obj_path = g_strdup_printf("/org/kernel/TCMUService1/HandlerManager1/%s",
				   handler->subtype);

	g_signal_connect(interface,
			 "handle-check-config",
			 G_CALLBACK(tcmulib_check_config),
			 handler); /* user_data */

	/* Export our object with org.kernel.TCMUService1 interface. */
	r = g_dbus_interface_skeleton_export(
			G_DBUS_INTERFACE_SKELETON(interface),
			connection,
			obj_path,
			&error);
	g_free(obj_path);
	if (!r)
		tcmulib_reg_fail(ctx);
}

static void
tcmulib_reg_name_acquired(GDBusConnection *connection,
			  const gchar     *name,
			  gpointer         user_data)
{
	struct tcmulib_handler *handler = user_data;
	struct tcmulib_context *ctx = handler->ctx;

	handler->connection = connection;

	if (ctx->connection) {
		/* The primary service is already available.  Register immediately. */
		tcmulib_register_handler(ctx, handler);
	}
}

static void
tcmulib_reg_name_lost(GDBusConnection *connection,
		      const gchar     *name,
		      gpointer         user_data)
{
	struct tcmulib_handler *handler = user_data;
	handler->connection = NULL;
}

static void tcmulib_handler_own_bus(struct tcmulib_handler *handler)
{
	char *bus_name;
	bus_name = g_strdup_printf("org.kernel.TCMUService1.HandlerManager1.%s",
				   handler->subtype);
	g_bus_own_name(G_BUS_TYPE_SYSTEM,
		       bus_name,
		       G_BUS_NAME_OWNER_FLAGS_NONE,
		       tcmulib_reg_bus_acquired,
		       tcmulib_reg_name_acquired,
		       tcmulib_reg_name_lost,
		       handler, NULL);
	g_free(bus_name);
}

static void
tcmulib_reg_name_appeared(GDBusConnection *connection,
			  const gchar     *name,
			  const gchar     *name_owner,
			  gpointer         user_data)
{
	struct tcmulib_context *ctx = user_data;
	struct tcmulib_handler *handler;

	ctx->connection = connection;
	/* Primary TCMU service is now available. None of the handlers are
	   registered, so register all handlers that have acquired their bus name */
	darray_foreach(handler, ctx->handlers) {
		if (handler->connection) {
			tcmulib_register_handler(ctx, handler);
		}
	}
}

static void
tcmulib_reg_name_vanished(GDBusConnection *connection,
			  const gchar     *name,
			  gpointer         user_data)
{
	struct tcmulib_context *ctx = user_data;

	ctx->connection = NULL;
}

void tcmulib_register(struct tcmulib_context *ctx)
{
	struct tcmulib_handler *handler;

	/* Start acquiring buses for each subtype owned by this context. */
	darray_foreach(handler, ctx->handlers) {
		tcmulib_handler_own_bus(handler);
	}

	/* Start waiting for the primary service to become available */
	g_bus_watch_name(G_BUS_TYPE_SYSTEM,
			 "org.kernel.TCMUService1",
			 G_BUS_NAME_WATCHER_FLAGS_NONE,
			 tcmulib_reg_name_appeared,
			 tcmulib_reg_name_vanished,
			 ctx,
			 NULL);
}
