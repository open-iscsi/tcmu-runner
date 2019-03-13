/*
 * Copyright (c) 2018 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */

#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <uv.h>
#include <errno.h>
#include <time.h>
#include <scsi/scsi.h>
#include <curl/curl.h>
#include <unistd.h>
#include <glib.h>
#include <libconfig.h>
#include "scsi_defs.h"
#include "libtcmu_common.h"
#include "tcmu-runner.h"
#include "tcmur_cmd_handler.h"
#include "libtcmu.h"
#include "tcmur_device.h"
#include "ccan/list/list.h"

// Http Response processing
#define AZ_RESPONSE_OK            206   // As returned from GET
#define AZ_RESPONSE_CREATED       201   // As returned from PUT
#define AZ_RESPONSE_ERR_ACCESS    403   // Access denied
#define AZ_RESPONSE_ERR_LEASE     412   // Lease broke
#define AZ_RESPONSE_ERR_NOT_FOUND 404   // Page blob deleted
#define AZ_RESPONSE_ERR_THROTTLE  503   // We are being throttling
#define AZ_RESPONSE_ERR_TIME_OUT  500   // Throttle but the server
					// side is misbehaving
#define AZ_RESPONSE_CONFLICT      429   // Conflict. Must be reqing
					// during transnient states
#define AZ_RESPONSE_BAD_RANGE     416   // Bad range (disk resized?)

#define az_is_catastrophe(azstatuscode) \
	((azstatuscode == AZ_RESPONSE_ERR_ACCESS  || \
	azstatuscode == AZ_RESPONSE_ERR_LEASE     || \
	azstatuscode == AZ_RESPONSE_ERR_NOT_FOUND || \
	azstatuscode == AZ_RESPONSE_BAD_RANGE) ? 1 : 0)

#define az_is_throttle(azstatuscode) \
	((azstatuscode == AZ_RESPONSE_ERR_THROTTLE || \
	azstatuscode == AZ_RESPONSE_ERR_TIME_OUT   || \
	azstatuscode == AZ_RESPONSE_CONFLICT) ? 1 : 0)

#define az_is_done(azstatuscode)\
	((azstatuscode == AZ_RESPONSE_OK || \
	azstatuscode == AZ_RESPONSE_CREATED) ? 1 : 0)

// Http headers
#define AZ_ACCOUNT_NAME_LEN	256
#define AZ_SAS_LEN		200
#define AZ_BLOB_URL_LEN		(512 + 63 + 1024)  // host + container + blob
#define AZ_LEASE_ID_LEN		64
#define AZ_FILE_LEN		256

struct curl_callback {
	char *buffer;
	size_t pos;
};

struct azblk_dev_config {
	char config_file[AZ_FILE_LEN];
	char sas[AZ_SAS_LEN];
	/* https://myaccount.blob.core.windows.net/mycontainer/myblob */
	char blob_url[AZ_BLOB_URL_LEN];
	char lease_id[AZ_LEASE_ID_LEN];
	int read_only;
	int use_lease;
	int use_sas;
};

struct azblk_dev {
	struct tcmu_device *dev;
	struct azblk_dev_config cfg;
	char *read_request_url;
	char *write_request_url;
	CURLM *curl_multi;
	uv_loop_t loop;
	uv_async_t stop_loop;
	uv_timer_t timeout;
	uv_async_t start_io_async;
	struct list_head start_io_queue;
	uv_mutex_t start_io_mutex;
	uv_thread_t thread;
};

enum azblk_io_type {
	AZBLK_WRITE = 0,
	AZBLK_READ,
	AZBLK_DISCARD
};

struct azblk_io_cb {
	struct azblk_dev *ddev;
	struct tcmulib_cmd *tcmulib_cmd;
	enum azblk_io_type type;
	struct curl_callback ctx;
	struct curl_slist *headers;
	CURL *curl_ezh;
	char *bounce_buffer;
	struct iovec *iov;
	size_t iov_cnt;
	size_t length;
	struct list_node entry;
};

static gint libcurl_global;

struct azblk_socket_context {
	uv_poll_t poll_handle;
	curl_socket_t sockfd;
	struct azblk_dev *ddev;
};


static void azblk_loop_cleanup(uv_handle_t *handle, void *data)
{
	uv_close(handle, NULL);
	tcmu_dbg("clean handle %p\n", handle);
}

static void azblk_stop_loop(uv_async_t *async_req)
{
	struct azblk_dev *ddev = (struct azblk_dev *)async_req->data;

	uv_mutex_lock(&ddev->start_io_mutex);
	if (!list_empty(&ddev->start_io_queue))
		tcmu_dev_warn(ddev->dev, "IO outstanding on device close\n");
	uv_mutex_unlock(&ddev->start_io_mutex);

	uv_stop(&ddev->loop);
}

static void azblk_kick_start(struct azblk_dev *ddev,
	 struct azblk_io_cb *io_cb)
{
	uv_mutex_lock(&ddev->start_io_mutex);
	list_add_tail(&ddev->start_io_queue, &io_cb->entry);
	uv_mutex_unlock(&ddev->start_io_mutex);
	uv_async_send(&ddev->start_io_async);
}

static void azblk_start_io(uv_async_t *async_req)
{
	struct azblk_dev *ddev = (struct azblk_dev *)async_req->data;
	struct list_head active_queue;
	int running_handles;
	struct azblk_io_cb *io_cb;

	list_head_init(&active_queue);

	uv_mutex_lock(&ddev->start_io_mutex);

	list_prepend_list(&active_queue, &ddev->start_io_queue);

	uv_mutex_unlock(&ddev->start_io_mutex);

	list_for_each(&active_queue, io_cb, entry) {
		list_del(&io_cb->entry);

		curl_multi_add_handle(ddev->curl_multi, io_cb->curl_ezh);

		curl_multi_socket_action(ddev->curl_multi,
					 CURL_SOCKET_TIMEOUT, 0,
					 &running_handles);
	}
}

static void azblk_multi_done(CURLM *curl_multi, CURLMsg *message)
{
	struct azblk_io_cb *io_cb;
	struct tcmu_device *dev;
	CURL *curl_ezh;
	long resp_code;
	int ret = TCMU_STS_OK;

	curl_ezh = message->easy_handle;
	curl_easy_getinfo(curl_ezh, CURLINFO_PRIVATE, (char **)&io_cb);
	dev = io_cb->ddev->dev;

	if (message->data.result != CURLE_OK) {
		if (io_cb->type == AZBLK_READ) {
			ret = TCMU_STS_RD_ERR;
			tcmu_dev_err(dev, "Curl GET error %s\n",
				     curl_easy_strerror(message->data.result));
		} else {
			ret = TCMU_STS_WR_ERR;
			tcmu_dev_err(dev, "Curl PUT error %s\n",
				     curl_easy_strerror(message->data.result));
		}
	goto done;
	}

	curl_easy_getinfo(curl_ezh, CURLINFO_RESPONSE_CODE, &resp_code);

	if (az_is_done(resp_code)) {
		if (io_cb->type == AZBLK_READ) {
			if (io_cb->iov_cnt > 1)
				tcmu_memcpy_into_iovec(io_cb->iov,
						       io_cb->iov_cnt,
						       io_cb->bounce_buffer,
						       io_cb->ctx.pos);
		}
	goto done;
	}

	ret = TCMU_STS_WR_ERR;

	if (io_cb->type == AZBLK_READ)
		ret = TCMU_STS_RD_ERR;

	tcmu_dev_err(dev, "Curl HTTP error %ld\n", resp_code);

	if (az_is_throttle(resp_code))
		ret = TCMU_STS_NO_RESOURCE;

done:
	curl_multi_remove_handle(curl_multi, curl_ezh);
	curl_slist_free_all(io_cb->headers);
	curl_easy_cleanup(curl_ezh);

	io_cb->tcmulib_cmd->done(dev, io_cb->tcmulib_cmd, ret);

	if (io_cb->iov_cnt > 1)
		free(io_cb->bounce_buffer);
	free(io_cb);
}

static void azblk_multi_check_completion(CURLM *curl_multi)
{
	int pending;
	CURLMsg *message;

	/* Do not use message data after calling curl_multi_remove_handle() and
	 * curl_easy_cleanup(). As per curl_multi_info_read() docs:
	 * "WARNING: The data the returned pointer points to will not survive
	 * calling curl_multi_cleanup, curl_multi_remove_handle or
	 * curl_easy_cleanup."
	 */

	while ((message = curl_multi_info_read(curl_multi, &pending))) {
		switch (message->msg) {
		case CURLMSG_DONE:
			azblk_multi_done(curl_multi, message);
			break;

		default:
			break;
		}
	}
}

static void azblk_timeout(uv_timer_t *req)
{
	struct azblk_dev *ddev = (CURLM *)req->data;
	int running_handles;

	curl_multi_socket_action(ddev->curl_multi, CURL_SOCKET_TIMEOUT, 0,
				 &running_handles);
	azblk_multi_check_completion(ddev->curl_multi);
}

static int azblk_start_timeout(CURLM *curl_multi, long timeout_ms, void *userp)
{
	struct azblk_dev *ddev = (struct azblk_dev *)userp;

	if (timeout_ms < 0) {
		uv_timer_stop(&ddev->timeout);
	} else {
		if (timeout_ms == 0)
			timeout_ms = 1; // 0 means directly call socket_action
					// but we'll do it in a bit
		ddev->timeout.data = ddev;
		uv_timer_start(&ddev->timeout, azblk_timeout, timeout_ms, 0);
	}
	return 0;
}

static struct azblk_socket_context *
	azblk_create_socket_context(curl_socket_t sockfd,
		struct azblk_dev *ddev)
{
	struct azblk_socket_context *context;

	context = (struct azblk_socket_context *)calloc(1, sizeof(*context));
	if (!context)
		return NULL;

	context->sockfd = sockfd;
	context->ddev = ddev;

	uv_poll_init_socket(&ddev->loop, &context->poll_handle, sockfd);
	context->poll_handle.data = context;

	return context;
}
static void azblk_close_socket(uv_handle_t *handle)
{
	// (struct azblk_socket_context *) handle->data;
	free(handle->data);
}

static void azblk_destroy_socket_context(struct azblk_socket_context *context)
{
	uv_close((uv_handle_t *) &context->poll_handle, azblk_close_socket);
}

static void azblk_curl_perform(uv_poll_t *req, int status, int events)
{
	struct azblk_socket_context *context;
	int running_handles;
	int flags = 0;

	context = (struct azblk_socket_context *)req->data;

	if (status < 0) {
		flags = CURL_CSELECT_ERR;
		tcmu_dev_err(context->ddev->dev, "CURL_CSELECT_ERR %s\n",
			     uv_err_name(status));
	}
	if (!status && events & UV_READABLE)
		flags |= CURL_CSELECT_IN;
	if (!status && events & UV_WRITABLE)
		flags |= CURL_CSELECT_OUT;

	curl_multi_socket_action(context->ddev->curl_multi, context->sockfd,
				 flags, &running_handles);

	azblk_multi_check_completion(context->ddev->curl_multi);
}

static int azblk_handle_socket(CURL *curl_ezh, curl_socket_t s, int action,
			       void *userp, void *socketp)
{
	struct azblk_socket_context *context;
	struct azblk_dev *ddev = (struct azblk_dev *)userp;

	if (action == CURL_POLL_IN
		|| action == CURL_POLL_OUT
			|| action == CURL_POLL_INOUT) {
		if (socketp)
			context = (struct azblk_socket_context *)socketp;
		else {
			context = azblk_create_socket_context(s, ddev);
			curl_multi_assign(ddev->curl_multi, s, (void *)context);
		}
	}

	switch (action) {
	case CURL_POLL_IN:
		uv_poll_start(&context->poll_handle, UV_READABLE,
			      azblk_curl_perform);
		break;
	case CURL_POLL_OUT:
		uv_poll_start(&context->poll_handle, UV_WRITABLE,
			      azblk_curl_perform);
		break;
	case CURL_POLL_INOUT:
		uv_poll_start(&context->poll_handle, UV_READABLE | UV_WRITABLE,
			      azblk_curl_perform);
		break;
	case CURL_POLL_REMOVE:
		if (socketp) {
			context = (struct azblk_socket_context *)socketp;

			uv_poll_stop(&context->poll_handle);
			azblk_destroy_socket_context(context);
			curl_multi_assign(ddev->curl_multi, s, NULL);
		}
		break;
	}

	return 0;
}

void azblk_dev_loop(void *arg)
{
	struct azblk_dev *ddev = (struct azblk_dev *)arg;
	int ret;

	ret = uv_run(&ddev->loop, UV_RUN_DEFAULT);

	uv_walk(&ddev->loop, azblk_loop_cleanup, NULL);

	uv_run(&ddev->loop, UV_RUN_DEFAULT);

	ret = uv_loop_close(&ddev->loop);
	if (ret == UV_EBUSY)
		tcmu_dev_warn(ddev->dev, "Not all libuv handles are closed\n");
}

static bool azblk_parse_config(struct azblk_dev *ddev)
{
	char *cfgstring;
	char *tcm_dev_name;
	config_setting_t *setting;
	config_t cfg;
	char *str;
	char *err_msg;
	int i, count;
	bool found_name = false;
	bool found_url = false;

	cfgstring = tcmu_dev_get_cfgstring(ddev->dev);
	if (strncmp(cfgstring, "azblk/", 6) != 0) {
		tcmu_dev_err(ddev->dev,
			     "Invalid cfgstring format: %s\n",
			     cfgstring);
		return false;
	}

	str = (char *)cfgstring + 6;

	if (strncmp(str, "none", 4) == 0)
		strcpy(ddev->cfg.config_file, "/etc/tcmu/azblk.conf");
	else
		strcpy(ddev->cfg.config_file, str);

	tcmu_info("Reading config file %s\n", ddev->cfg.config_file);

	config_init(&cfg);

	if (!config_read_file(&cfg, ddev->cfg.config_file)) {
		asprintf(&err_msg, "File: %s:%d - %s\n",
			 ddev->cfg.config_file, config_error_line(&cfg),
			 config_error_text(&cfg));
		goto error;
	}

	setting = config_lookup(&cfg, "device");
	if (!setting) {
		asprintf(&err_msg, "File %s is malformed\n",
			 ddev->cfg.config_file);
		goto error;
	}

	tcm_dev_name = tcmu_dev_get_tcm_dev_name(ddev->dev);

	count = config_setting_length(setting);

	for (i = 0; i < count; ++i) {
		const char *name, *sas, *lease, *url;
		int read_only, len;
		config_setting_t *device = config_setting_get_elem(setting, i);

		if (!(config_setting_lookup_string(device, "name", &name))) {
			asprintf(&err_msg,
				 "File %s: device name required\n",
				 ddev->cfg.config_file);
			goto error;
		}

		if (strcmp(name, tcm_dev_name) != 0)
			continue;

		found_name = true;

		if (config_setting_lookup_string(device, "sas", &sas)) {
			len = strlen(sas);
			if (len > (AZ_SAS_LEN - 1)) {
				asprintf(&err_msg,
					 "File %s: device %s sas must be less than %d characters\n",
					 ddev->cfg.config_file,
					 tcm_dev_name,
					 AZ_SAS_LEN);
				goto error;
			}
			strncpy(ddev->cfg.sas, sas, len);
			ddev->cfg.use_sas = 1;
		}

		if (config_setting_lookup_string(device, "url", &url)) {
			len = strlen(url);
			if (len > (AZ_BLOB_URL_LEN - 1)) {
				asprintf(&err_msg,
					 "File %s: device %s url must be less than %d characters\n",
					 ddev->cfg.config_file,
					 tcm_dev_name,
					 AZ_BLOB_URL_LEN);
				goto error;
			}
			strncpy(ddev->cfg.blob_url, url, len);
			found_url = true;
		} else {
			asprintf(&err_msg,
				 "File %s: device %s url required\n",
				 ddev->cfg.config_file,
				 tcm_dev_name);
			goto error;
		}

		if (config_setting_lookup_string(device, "lease", &lease)) {
			len = strlen(lease);
			if (len > (AZ_LEASE_ID_LEN - 1)) {
				asprintf(&err_msg,
					 "File %s: device %s lease must be less than %d characters\n",
					 ddev->cfg.config_file,
					 tcm_dev_name,
					 AZ_LEASE_ID_LEN);
				goto error;
			}
			strncpy(ddev->cfg.lease_id, lease, len);
			ddev->cfg.use_lease = 1;
		}

		if (config_setting_lookup_int(device, "readonly", &read_only))
			ddev->cfg.read_only = read_only;
	}

	if (!found_name) {
		asprintf(&err_msg,
			 "File %s: device %s not found\n",
			  ddev->cfg.config_file,
			  tcm_dev_name);
		goto error;
	}

	if (!found_url) {
		asprintf(&err_msg,
			 "File %s: device %s must include the blob url\n",
			  ddev->cfg.config_file,
			  tcm_dev_name);
		goto error;
	}

	tcmu_info("device name: %s\n", tcm_dev_name);
	tcmu_info("blob_url: %s\n", ddev->cfg.blob_url);
	tcmu_info("read_only: %d\n", ddev->cfg.read_only);

	config_destroy(&cfg);

	return true;

error:
	tcmu_dev_err(ddev->dev, err_msg);
	free(err_msg);
	config_destroy(&cfg);

	return false;
}

int get_UTC(char *buf, int size)
{
	time_t c_time;
	struct tm gm_time;

	c_time = time(NULL);
	gmtime_r(&c_time, &gm_time);
	strftime(buf, size, "%a, %d %b %Y %X GMT", &gm_time);

	return 0;
}

static int azblk_open(struct tcmu_device *dev, bool reopen)
{
	struct azblk_dev *ddev;
	int ret;

	ddev = calloc(1, sizeof(*ddev));

	if (!ddev)
		return -ENOMEM;

	tcmur_dev_set_private(dev, ddev);
	ddev->dev = dev;

	if (!azblk_parse_config(ddev)) {
		ret = -EINVAL;
		goto err;
	}

	tcmu_dev_set_write_cache_enabled(dev, 0);

	tcmu_dev_set_block_size(dev, 512); // tcmu-runner default

	if (!g_atomic_int_add(&libcurl_global, 1)) {
		ret = curl_global_init(CURL_GLOBAL_ALL);
		if (ret) {
			tcmu_dev_err(dev, "Could not global init curl.\n");
			return(-EIO);
			}
	}

	ddev->curl_multi = curl_multi_init();

	curl_multi_setopt(ddev->curl_multi, CURLMOPT_SOCKETFUNCTION,
			  azblk_handle_socket);
	curl_multi_setopt(ddev->curl_multi, CURLMOPT_TIMERFUNCTION,
			  azblk_start_timeout);
	curl_multi_setopt(ddev->curl_multi, CURLMOPT_TIMERDATA, ddev);
	curl_multi_setopt(ddev->curl_multi, CURLMOPT_SOCKETDATA, ddev);

	// blob calls

	// Get Page
	ret = asprintf(&ddev->read_request_url,
			ddev->cfg.use_sas ? "%s?%s" : "%s",
			ddev->cfg.blob_url, ddev->cfg.sas);
	if (ret < 0) {
		tcmu_dev_err(dev, "Could not allocate query buf.\n");
		ret = -ENOMEM;
		goto err;
	}

	tcmu_info("read request url %s\n", ddev->read_request_url);

	// Put Page
	ret = asprintf(&ddev->write_request_url,
			ddev->cfg.use_sas ? "%s?comp=page&%s" : "%s?comp=page",
			ddev->cfg.blob_url, ddev->cfg.sas);
	if (ret < 0) {
		tcmu_dev_err(dev, "Could not allocate query buf.\n");
		ret = -ENOMEM;
		goto err;
	}

	tcmu_info("write request url %s\n", ddev->write_request_url);

	uv_loop_init(&ddev->loop);

	uv_timer_init(&ddev->loop, &ddev->timeout);

	uv_async_init(&ddev->loop, &ddev->stop_loop, azblk_stop_loop);
	ddev->stop_loop.data = ddev;

	uv_async_init(&ddev->loop, &ddev->start_io_async, azblk_start_io);
	ddev->start_io_async.data = ddev;

	uv_mutex_init(&ddev->start_io_mutex);

	list_head_init(&ddev->start_io_queue);

	uv_thread_create(&ddev->thread, azblk_dev_loop, ddev);

	return 0;

err:

	if (g_atomic_int_dec_and_test(&libcurl_global))
		curl_global_cleanup();

	free(ddev->read_request_url);

	free(ddev->write_request_url);

	free(ddev);

	return ret;
}

static void azblk_close(struct tcmu_device *dev)
{
	struct azblk_dev *ddev = tcmur_dev_get_private(dev);

	uv_timer_stop(&ddev->timeout);

	uv_async_send(&ddev->stop_loop);

	uv_thread_join(&ddev->thread);

	curl_multi_cleanup(ddev->curl_multi);

	if (g_atomic_int_dec_and_test(&libcurl_global))
		curl_global_cleanup();

	uv_mutex_destroy(&ddev->start_io_mutex);

	free(ddev->read_request_url);

	free(ddev->write_request_url);

	free(ddev);
}

size_t get_callback(void *data, size_t size, size_t nmemb, void *userp)
{
	struct curl_callback *ctx = (struct curl_callback *)userp;
	size_t data_size = size * nmemb;

	memcpy(ctx->buffer + ctx->pos, data, data_size);

	ctx->pos += data_size;

	return data_size;
}


static int azblk_read(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
		     struct iovec *iov, size_t iov_cnt, size_t length,
		     off_t offset)
{
	struct azblk_dev *ddev = tcmur_dev_get_private(dev);
	struct azblk_io_cb *io_cb;
	char buf[128];
	int len;
	int ret;

	io_cb = calloc(1, sizeof(*io_cb));
	if (!io_cb) {
		tcmu_dev_err(dev, "Could not allocate io_cb.\n");
		return TCMU_STS_NO_RESOURCE;
	}

	io_cb->ddev = ddev;
	io_cb->type = AZBLK_READ;
	io_cb->tcmulib_cmd = cmd;
	io_cb->iov = iov;
	io_cb->iov_cnt = iov_cnt;
	io_cb->length = length;
	list_node_init(&io_cb->entry);

	if (iov_cnt == 1) {
		io_cb->bounce_buffer = iov->iov_base;
		io_cb->length = min(iov->iov_len, length);
	} else {
		io_cb->bounce_buffer = malloc(io_cb->length);
		if (!io_cb->bounce_buffer) {
			tcmu_dev_err(dev, "Failed to allocate bounce buffer.\n");
			ret = TCMU_STS_NO_RESOURCE;
			goto error;
		}
	}

	io_cb->curl_ezh = curl_easy_init();
	if (!io_cb->curl_ezh) {
		tcmu_dev_err(dev, "Failed to allocate easy handle.\n");
		ret = TCMU_STS_NO_RESOURCE;
		goto error;
	}

	curl_easy_setopt(io_cb->curl_ezh, CURLOPT_URL, ddev->read_request_url);
	curl_easy_setopt(io_cb->curl_ezh, CURLOPT_USERAGENT,
			 "tcmu-runner-azblk/1.0");

	io_cb->ctx.buffer = io_cb->bounce_buffer;
	io_cb->ctx.pos = 0;

	// Writes to the destination are broken into CURL_MAX_WRITE_SIZE chunks

	curl_easy_setopt(io_cb->curl_ezh, CURLOPT_WRITEFUNCTION,
			 get_callback);
	curl_easy_setopt(io_cb->curl_ezh, CURLOPT_WRITEDATA,
			 (void *)&io_cb->ctx);

	io_cb->headers = curl_slist_append(io_cb->headers,
					   "x-ms-version: 2018-03-28");

	if (ddev->cfg.use_lease && !ddev->cfg.read_only) {
		sprintf(buf, "x-ms-lease-id: %s", ddev->cfg.lease_id);
		io_cb->headers = curl_slist_append(io_cb->headers, buf);
	}

	sprintf(buf, "x-ms-range: bytes=%lu-%lu", offset,
		offset + (io_cb->length - 1));
	io_cb->headers = curl_slist_append(io_cb->headers, buf);

	len = sprintf(buf, "x-ms-date: ");
	get_UTC(buf + len, sizeof(buf) - len);
	io_cb->headers = curl_slist_append(io_cb->headers, buf);

	curl_easy_setopt(io_cb->curl_ezh, CURLOPT_HTTPHEADER, io_cb->headers);

	// Set context associated with this easy handle

	curl_easy_setopt(io_cb->curl_ezh, CURLOPT_PRIVATE, (void *)io_cb);

	azblk_kick_start(ddev, io_cb);

	return TCMU_STS_OK;
error:
	if (io_cb->curl_ezh) {
		curl_multi_remove_handle(ddev->curl_multi, io_cb->curl_ezh);
		curl_slist_free_all(io_cb->headers);
		curl_easy_cleanup(io_cb->curl_ezh);
	}

	if (iov_cnt > 1)
		free(io_cb->bounce_buffer);
	free(io_cb);

	return ret;
}

static int azblk_write(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
		       struct iovec *iov, size_t iov_cnt, size_t length,
		       off_t offset)
{
	struct azblk_dev *ddev = tcmur_dev_get_private(dev);
	int len;
	int ret;
	struct azblk_io_cb *io_cb;
	char buf[128];

	if (ddev->cfg.read_only)
		return TCMU_STS_INVALID_CMD;

	io_cb = calloc(1, sizeof(*io_cb));
	if (!io_cb) {
		tcmu_dev_err(dev, "Could not allocate io_cb.\n");
		return TCMU_STS_NO_RESOURCE;
	}

	io_cb->ddev = ddev;
	io_cb->type = AZBLK_WRITE;
	io_cb->tcmulib_cmd = cmd;
	io_cb->length = length;
	list_node_init(&io_cb->entry);

	if (iov_cnt == 1) {
		io_cb->bounce_buffer = iov->iov_base;
		io_cb->length = min(iov->iov_len, length);
	} else {
		io_cb->bounce_buffer = malloc(io_cb->length);
		if (!io_cb->bounce_buffer) {
			tcmu_dev_err(dev, "Failed to allocate bounce buffer.\n");
			ret = TCMU_STS_NO_RESOURCE;
			goto error;
		}
	}

	io_cb->curl_ezh = curl_easy_init();
	if (!io_cb->curl_ezh) {
		tcmu_dev_err(dev, "Failed to allocate easy handle.\n");
		ret = TCMU_STS_NO_RESOURCE;
		goto error;
	}

	if (iov_cnt > 1)
		tcmu_memcpy_from_iovec(io_cb->bounce_buffer, io_cb->length,
				       iov, iov_cnt);

	curl_easy_setopt(io_cb->curl_ezh, CURLOPT_URL, ddev->write_request_url);
	curl_easy_setopt(io_cb->curl_ezh, CURLOPT_CUSTOMREQUEST, "PUT");
	curl_easy_setopt(io_cb->curl_ezh, CURLOPT_POSTFIELDS,
			 io_cb->bounce_buffer);
	curl_easy_setopt(io_cb->curl_ezh, CURLOPT_POSTFIELDSIZE, io_cb->length);
	curl_easy_setopt(io_cb->curl_ezh, CURLOPT_USERAGENT,
				"tcmu-runner-azblk/1.0");

	io_cb->headers = curl_slist_append(io_cb->headers,
					   "x-ms-version: 2018-03-28");

	if (ddev->cfg.use_lease) {
		sprintf(buf, "x-ms-lease-id: %s", ddev->cfg.lease_id);
		io_cb->headers = curl_slist_append(io_cb->headers, buf);
	}

	io_cb->headers = curl_slist_append(io_cb->headers,
					   "x-ms-page-write: update");

	sprintf(buf, "Content-Length: %lu", io_cb->length);
	io_cb->headers = curl_slist_append(io_cb->headers, buf);

	io_cb->headers = curl_slist_append(io_cb->headers, "Expect:");

	io_cb->headers = curl_slist_append(io_cb->headers,
				"Content-Type: application/octet-stream");

	sprintf(buf, "x-ms-range: bytes=%lu-%lu", offset,
			 offset + (io_cb->length - 1));
	io_cb->headers = curl_slist_append(io_cb->headers, buf);

	len = sprintf(buf, "x-ms-date: ");
	get_UTC(buf + len, sizeof(buf) - len);
	io_cb->headers = curl_slist_append(io_cb->headers, buf);

	curl_easy_setopt(io_cb->curl_ezh, CURLOPT_HTTPHEADER, io_cb->headers);

	curl_easy_setopt(io_cb->curl_ezh, CURLOPT_PRIVATE, (void *)io_cb);

	azblk_kick_start(ddev, io_cb);

	return TCMU_STS_OK;

error:
	if (io_cb->curl_ezh) {
		curl_multi_remove_handle(ddev->curl_multi, io_cb->curl_ezh);
		curl_slist_free_all(io_cb->headers);
		curl_easy_cleanup(io_cb->curl_ezh);
	}

	if (iov_cnt > 1)
		free(io_cb->bounce_buffer);
	free(io_cb);

	return ret;
}

static int azblk_discard(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			 uint64_t offset, uint64_t length)
{
	struct azblk_dev *ddev = tcmur_dev_get_private(dev);
	struct azblk_io_cb *io_cb;
	char buf[128];
	int len;
	int ret;

	if (ddev->cfg.read_only)
		return TCMU_STS_INVALID_CMD;

	io_cb = calloc(1, sizeof(*io_cb));
	if (!io_cb) {
		tcmu_dev_err(dev, "Could not allocate io_cb.\n");
		return TCMU_STS_NO_RESOURCE;
	}

	io_cb->ddev = ddev;
	io_cb->type = AZBLK_DISCARD;
	io_cb->tcmulib_cmd = cmd;
	list_node_init(&io_cb->entry);

	io_cb->curl_ezh = curl_easy_init();
	if (!io_cb->curl_ezh) {
		tcmu_dev_err(dev, "Failed to allocate easy handle.\n");
		ret = TCMU_STS_NO_RESOURCE;
		goto error;
	}

	curl_easy_setopt(io_cb->curl_ezh, CURLOPT_URL, ddev->write_request_url);
	curl_easy_setopt(io_cb->curl_ezh, CURLOPT_CUSTOMREQUEST, "PUT");
	curl_easy_setopt(io_cb->curl_ezh, CURLOPT_USERAGENT,
			 "tcmu-runner-azblk/1.0");

	io_cb->headers = curl_slist_append(io_cb->headers,
					   "x-ms-version: 2018-03-28");

	if (ddev->cfg.use_lease) {
		sprintf(buf, "x-ms-lease-id: %s", ddev->cfg.lease_id);
		io_cb->headers = curl_slist_append(io_cb->headers, buf);
	}

	io_cb->headers = curl_slist_append(io_cb->headers, "Content-Length: 0");

	io_cb->headers = curl_slist_append(io_cb->headers,
					   "x-ms-page-write: clear");

	sprintf(buf, "x-ms-range: bytes=%lu-%lu", offset,
			offset + (length - 1));
	io_cb->headers = curl_slist_append(io_cb->headers, buf);

	len = sprintf(buf, "x-ms-date: ");
	get_UTC(buf + len, sizeof(buf) - len);
	io_cb->headers = curl_slist_append(io_cb->headers, buf);

	curl_easy_setopt(io_cb->curl_ezh, CURLOPT_HTTPHEADER, io_cb->headers);

	// Set context associated with this easy handle

	curl_easy_setopt(io_cb->curl_ezh, CURLOPT_PRIVATE, (void *)io_cb);

	azblk_kick_start(ddev, io_cb);

	return TCMU_STS_OK;

error:
	if (io_cb->curl_ezh) {
		curl_multi_remove_handle(ddev->curl_multi, io_cb->curl_ezh);
		curl_slist_free_all(io_cb->headers);
		curl_easy_cleanup(io_cb->curl_ezh);
	}

	free(io_cb);

	return ret;
}

// The size of the blob will be determined by the targetcli create command.

static const char azblk_cfg_desc[] =
	"azblk cfgstring indicates the name of the config file. Enter the full path name of\n"
	"the config file you wish to use or the word none if you wish to use the default file\n"
	"/etc/tcmu/azblk.conf\n"
	"Example:\n"
	"cfgstring=/etc/some_other_name.conf\n"
	"or\n"
	"cfgstring=none\n";

static struct tcmur_handler azblk_handler = {
	.cfg_desc = azblk_cfg_desc,
	.open = azblk_open,
	.close = azblk_close,
	.read = azblk_read,
	.write = azblk_write,
	.unmap = azblk_discard,
	.name = "Azblk Handler",
	.subtype = "azblk",
	.nr_threads = 0,
	// .reconfig = azblk_reconfig we will not support this
};

int handler_init(void)
{
	return tcmur_register_handler(&azblk_handler);
}
