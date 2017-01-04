/*
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
	ctx->reg_count_down = 0;
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

	if (!ctx->reg_count_down || --ctx->reg_count_down)
		return;
	/* We've acquired all needed buses, now register each handler to
	 * org.kernel.TCMUService1.HandlerManager1. */
	darray_foreach(handler, ctx->handlers) {
		if (!tcmulib_register_handler(ctx, handler)) {
			tcmulib_reg_fail(ctx);
			break;
		}
	}
}

static void
tcmulib_reg_name_lost(GDBusConnection *connection,
		      const gchar     *name,
		      gpointer         user_data)
{
	struct tcmulib_handler *handler = user_data;

	tcmulib_reg_fail(handler->ctx);
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
	if (!ctx->reg_count_down)
		return;
	darray_foreach(handler, ctx->handlers) {
		/* XXX: Set this at initalize time. */
		handler->ctx = ctx;
		tcmulib_handler_own_bus(handler);
	}
}

static void
tcmulib_reg_name_vanished(GDBusConnection *connection,
			  const gchar     *name,
			  gpointer         user_data)
{
	tcmu_err("Failed to get bus %s\n", name);
}

void tcmulib_register(struct tcmulib_context *ctx)
{
	assert(!ctx->reg_count_down);
	ctx->reg_count_down = darray_size(ctx->handlers);
	if (!ctx->reg_count_down)
		return;
	g_bus_watch_name(G_BUS_TYPE_SYSTEM,
			 "org.kernel.TCMUService1",
			 G_BUS_NAME_WATCHER_FLAGS_NONE,
			 tcmulib_reg_name_appeared,
			 tcmulib_reg_name_vanished,
			 ctx,
			 NULL);

}
