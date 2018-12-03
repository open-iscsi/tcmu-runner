/*
 * Copyright 2016-2017 China Mobile, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <stdbool.h>

#include "darray.h"
#include "libtcmu_config.h"
#include "libtcmu_log.h"
#include "libtcmu_common.h"

#include "ccan/list/list.h"

typedef enum {
	TCMU_OPT_NONE = 0,
	TCMU_OPT_INT, /* type int */
	TCMU_OPT_STR, /* type string */
	TCMU_OPT_BOOL, /* type boolean */
	TCMU_OPT_MAX,
} tcmu_option_type;

struct tcmu_conf_option {
	struct list_node list;

	char *key;
	tcmu_option_type type;
	union {
		int opt_int;
		bool opt_bool;
		char *opt_str;
	};
};

/*
 * System config for TCMU, for now there are only 3 option types supported:
 * 1, The "int type" option, for example:
 *	log_level = 2
 *
 * 2, The "string type" option, for example:
 *	tcmu_str = "Tom"  --> Tom
 *    or
 *	tcmu_str = 'Tom'  --> Tom
 *    or
 *	tcmu_str = 'Tom is a "boy"' ---> Tom is a "boy"
 *    or
 *	tcmu_str = "'T' is short for Tom" --> 'T' is short for Tom
 *
 * 3, The "boolean type" option, for example:
 *	tcmu_bool
 *
 * ========================
 * How to add new options ?
 *
 * Using "log_level" as an example:
 *
 * 1, Add log_level member in:
 *	struct tcmu_config {
 *		int log_level;
 *	};
 *    in file libtcmu_config.h.
 *
 * 2, Add the following option in "tcmu.conf" file as default:
 *	log_level = 2
 *    or
 *	# log_level = 2
 *
 *    Note: the option name in config file must be the same as in
 *    tcmu_config.
 *
 * 3, You should add your own set method in:
 *	static void tcmu_conf_set_options(struct tcmu_config *cfg)
 *	{
 *		TCMU_PARSE_CFG_INT(cfg, log_level);
 *		TCMU_CONF_CHECK_LOG_LEVEL(log_level);
 *	}
 *
 * Note: For now, if the options have been changed in config file, the
 * system config reload thread daemon will try to update them for all the
 * tcmu-runner, consumer and tcmu-synthesizer daemons.
 */

static LIST_HEAD(tcmu_options);

static struct tcmu_conf_option * tcmu_get_option(const char *key)
{
	struct tcmu_conf_option *option;

	list_for_each(&tcmu_options, option, list) {
		if (!strcmp(option->key, key))
			return option;
	}

	return NULL;
}

/* The default value should be specified here,
 * so the next time when users comment out an
 * option in config file, here it will set the
 * default value back.
 */
#define TCMU_PARSE_CFG_INT(cfg, key, def) \
do { \
	struct tcmu_conf_option *option; \
	option = tcmu_get_option(#key); \
	if (option) { \
		cfg->key = option->opt_int; \
		option->opt_int = def; \
	} \
} while (0)

#define TCMU_PARSE_CFG_BOOL(cfg, key, def) \
do { \
	struct tcmu_conf_option *option; \
	option = tcmu_get_option(#key); \
	if (option) { \
		cfg->key = option->opt_bool; \
		option->opt_bool = def; \
	} \
} while (0)

#define TCMU_PARSE_CFG_STR(cfg, key, def) \
do { \
	struct tcmu_conf_option *option; \
	char buf[1024]; \
	option = tcmu_get_option(#key); \
	memset(cfg->key, 0, sizeof(cfg->key)); \
	if (option) { \
		snprintf(cfg->key, sizeof(cfg->key), option->opt_str); \
		if (option->opt_str) \
			free(option->opt_str); \
		sprintf(buf, "%s", def); \
		option->opt_str = strdup(buf); \
	} \
} while (0);

static void tcmu_conf_set_options(struct tcmu_config *cfg)
{
	/* set log_level option */
	TCMU_PARSE_CFG_INT(cfg, log_level, TCMU_CONF_LOG_INFO);
	tcmu_set_log_level(cfg->log_level);

	/* set log_dir path option */
	TCMU_PARSE_CFG_STR(cfg, log_dir, TCMU_LOG_DIR_DEFAULT);
	tcmu_resetup_log_file(cfg->log_dir);

	/* add your new config options */
}

#define TCMU_MAX_CFG_FILE_SIZE (2 * 1024 * 1024)
static int tcmu_read_config(int fd, char *buf, int count)
{
	ssize_t len;
	int save = errno;

	do {
		len = read(fd, buf, count);
	} while (errno == EAGAIN);

	errno = save;
	return len;
}

/* end of line */
#define __EOL(c) (((c) == '\n') || ((c) == '\r'))

#define TCMU_TO_LINE_END(x, y) \
	do { while ((x) < (y) && !__EOL(*(x))) { \
		(x)++; } \
	} while (0);

/* skip blank lines */
#define TCMU_SKIP_BLANK_LINES(x, y) \
	do { while ((x) < (y) && (isblank(*(x)) || __EOL(*(x)))) { \
		(x)++; } \
	} while (0);

/* skip comment line with '#' */
#define TCMU_SKIP_COMMENT_LINE(x, y) \
	do { while ((x) < (y) && !__EOL(*x)) { \
		(x)++; } \
	     (x)++; \
	} while (0);

/* skip comment lines with '#' */
#define TCMU_SKIP_COMMENT_LINES(x, y) \
	do { while ((x) < (y) && *(x) == '#') { \
		TCMU_SKIP_COMMENT_LINE((x), (y)); } \
	} while (0);

#define MAX_KEY_LEN 64
#define MAX_VAL_STR_LEN 256

static struct tcmu_conf_option *
tcmu_register_option(char *key, tcmu_option_type type)
{
	struct tcmu_conf_option *option;

	option = calloc(1, sizeof(*option));
	if (!option)
		return NULL;

	option->key = strdup(key);
	if (!option->key)
		goto free_option;
	option->type = type;
	list_node_init(&option->list);

	list_add_tail(&tcmu_options, &option->list);
	return option;

free_option:
	free(option);
	return NULL;
}

static void tcmu_parse_option(char **cur, const char *end)
{
	struct tcmu_conf_option *option;
	tcmu_option_type type;
	char *p = *cur, *q = *cur, *r, *s;

	while (isblank(*p))
		p++;

	TCMU_TO_LINE_END(q, end);
	*q = '\0';
	*cur = q + 1;

	/* parse the boolean type option */
	s = r = strchr(p, '=');
	if (!r) {
		/* boolean type option at file end or line end */
		r = p;
		while (!isblank(*r) && r < q)
			r++;
		*r = '\0';
		option = tcmu_get_option(p);
		if (!option)
			option = tcmu_register_option(p, TCMU_OPT_BOOL);

		if (option)
			option->opt_bool = true;

		return;
	}
	/* skip character '='  */
	s++;
	r--;
	while (isblank(*r))
		r--;
	r++;
	*r = '\0';

	option = tcmu_get_option(p);
	if (!option) {
		r = s;
		while (isblank(*r))
			r++;

		if (isdigit(*r))
			type = TCMU_OPT_INT;
		else
			type = TCMU_OPT_STR;

		option = tcmu_register_option(p, type);
		if (!option)
			return;
	}

	/* parse the int/string type options */
	switch (option->type) {
	case TCMU_OPT_INT:
		while (!isdigit(*s))
			s++;
		r = s;
		while (isdigit(*r))
			r++;
		*r= '\0';

		option->opt_int = atoi(s);
		break;
	case TCMU_OPT_STR:
		while (isblank(*s))
			s++;
		/* skip first " or ' if exist */
		if (*s == '"' || *s == '\'')
			s++;
		r = q - 1;
		while (isblank(*r))
			r--;
		/* skip last " or ' if exist */
		if (*r == '"' || *r == '\'')
			*r = '\0';

		if (option->opt_str)
			/* free if this is reconfig */
			free(option->opt_str);
		option->opt_str = strdup(s);
		break;
	default:
		tcmu_err("option type %d not supported!\n", option->type);
		break;
	}
}

static void tcmu_parse_options(struct tcmu_config *cfg, char *buf, int len)
{
	char *cur = buf, *end = buf + len;

	while (cur < end) {
		/* skip blanks lines */
		TCMU_SKIP_BLANK_LINES(cur, end);

		/* skip comments with '#' */
		TCMU_SKIP_COMMENT_LINES(cur, end);

		if (cur >= end)
			break;

		if (!isalpha(*cur))
			continue;

		/* parse the options from config file to tcmu_options[] */
		tcmu_parse_option(&cur, end);
	}

	/* parse the options from tcmu_options[] to struct tcmu_config */
	tcmu_conf_set_options(cfg);
}

static int tcmu_load_config(struct tcmu_config *cfg)
{
	int ret = -1;
	int fd, len;
	char *buf;

	buf = malloc(TCMU_MAX_CFG_FILE_SIZE);
	if (!buf)
		return -ENOMEM;

	fd = open(cfg->path, O_RDONLY);
	if (fd == -1) {
		tcmu_err("Failed to open file '%s', %m\n", cfg->path);
		goto free_buf;
	}

	len = tcmu_read_config(fd, buf, TCMU_MAX_CFG_FILE_SIZE);
	close(fd);
	if (len < 0) {
		tcmu_err("Failed to read file '%s'\n", cfg->path);
		goto free_buf;
	}

	buf[len] = '\0';

	tcmu_parse_options(cfg, buf, len);

	ret = 0;
free_buf:
	free(buf);
	return ret;
}

#define BUF_LEN 1024
static void *dyn_config_start(void *arg)
{
	struct tcmu_config *cfg = arg;
	int monitor, wd, len;
	char buf[BUF_LEN];
	char cfg_dir[PATH_MAX];
	char *p;

	monitor = inotify_init();
	if (monitor == -1) {
		tcmu_err("Failed to init inotify %m\n");
		return NULL;
	}

	snprintf(cfg_dir, PATH_MAX, cfg->path);
	p = strrchr(cfg_dir, '/');
	if (p) {
		*(p + 1) = '\0';
	} else {
		snprintf(cfg_dir, PATH_MAX, "/etc/tcmu/");
	}

	/* Editors (vim, nano ..) follow different approaches to save conf file.
	 * The two commonly followed techniques are to overwrite the existing
	 * file, or to write to a new file (.swp, .tmp ..) and move it to actual
	 * file name later. In the later case, the inotify fails, because the
	 * file it's been intended to watch no longer exists, as the new file
	 * is a different file with just a same name.
	 * To handle both the file save approaches mentioned above, it is better
	 * we watch the directory and filter for MODIFY events.
	 */
	wd = inotify_add_watch(monitor, cfg_dir, IN_MODIFY);
	if (wd == -1) {
		tcmu_err("Failed to add \"%s\" to inotify %m\n", cfg_dir);
		return NULL;
	}

	tcmu_info("Inotify is watching \"%s\", wd: %d, mask: IN_MODIFY\n",
		  cfg_dir, wd);


	while (1) {
		struct inotify_event *event;

		len = read(monitor, buf, BUF_LEN);
		if (len == -1) {
			tcmu_warn("Failed to read inotify: %m\n");
			continue;
		}

		for (p = buf; p < buf + len;
		     p += sizeof(struct inotify_event) + event->len) {
			event = (struct inotify_event *)p;

			tcmu_info("event->mask: 0x%x\n", event->mask);

			if (event->wd != wd)
				continue;

			/* Try to reload the config file */
			if (event->mask & IN_MODIFY)
				tcmu_load_config(cfg);
		}
	}

	return NULL;
}

struct tcmu_config *tcmu_parse_config(const char *path)
{
	struct tcmu_config *cfg;

	cfg = calloc(1, sizeof(*cfg));
	if (cfg == NULL) {
		tcmu_err("Alloc TCMU config failed!\n");
		return NULL;
	}

	if (!path)
		path = "/etc/tcmu/tcmu.conf"; /* the default config file */

	snprintf(cfg->path, PATH_MAX, path);
	if (tcmu_load_config(cfg)) {
		tcmu_err("Loading TCMU config failed!\n");
		goto free_cfg;
	}

	return cfg;

free_cfg:
	free(cfg);
	return NULL;
}

int tcmu_watch_config(struct tcmu_config *cfg)
{
	return pthread_create(&cfg->thread_id, NULL, dyn_config_start, cfg);
}

void tcmu_unwatch_config(struct tcmu_config *cfg)
{
	tcmu_thread_cancel(cfg->thread_id);
}

void tcmu_free_config(struct tcmu_config *cfg)
{
	struct tcmu_conf_option *option, *next;

	if (!cfg)
		return;

	list_for_each_safe(&tcmu_options, option, next, list) {
		list_del(&option->list);

		if (option->type == TCMU_OPT_STR)
			free(option->opt_str);
		free(option->key);
		free(option);
	}

	free(cfg);
}
