/*
 * Copyright 2016-2017 China Mobile, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <stdbool.h>

#include "darray.h"
#include "libtcmu_config.h"
#include "libtcmu_log.h"

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
 * tcmu-runner, consumer and tcmu-synthesizer daemons should be restarted.
 * And the dynamic reloading feature will be added later.
 */

static darray(struct tcmu_conf_option) tcmu_options = darray_new();

static struct tcmu_conf_option * tcmu_get_option(const char *key)
{
	struct tcmu_conf_option *option;

	darray_foreach(option, tcmu_options) {
		if (!strcmp(option->key, key))
			return option;
	}

	return NULL;
}

#define TCMU_PARSE_CFG_INT(cfg, key) \
do { \
	struct tcmu_conf_option *option; \
	option = tcmu_get_option(#key); \
	if (option) { \
		cfg->key = option->opt_int; \
	} \
} while (0)

#define TCMU_PARSE_CFG_BOOL(cfg, key) \
do { \
	struct tcmu_conf_option *option; \
	option = tcmu_get_option(#key); \
	if (option) { \
		cfg->key = option->opt_bool; \
	} \
} while (0)

#define TCMU_PARSE_CFG_STR(cfg, key) \
do { \
	struct tcmu_conf_option *option; \
	option = tcmu_get_option(#key); \
	if (option) { \
		cfg->key = strdup(option->opt_str); } \
} while (0);

#define TCMU_FREE_CFG_STR(cfg, key) \
do { \
	struct tcmu_conf_option *option; \
	cfg->key = NULL; \
	darray_foreach(option, tcmu_options) { \
		if (!strcmp(option->key, key)) { \
			free(option->opt_str); \
			break; \
		} \
	} \
} while (0);

#define TCMU_CONF_CHECK_LOG_LEVEL(key) \
do { \
	struct tcmu_conf_option *option; \
	option = tcmu_get_option(#key); \
	if (!option) \
		return; \
	if (option->opt_int > TCMU_CONF_LOG_LEVEL_MAX) { \
		option->opt_int = TCMU_CONF_LOG_LEVEL_MAX; \
	} else if (option->opt_int < TCMU_CONF_LOG_LEVEL_MIN) { \
		option->opt_int = TCMU_CONF_LOG_LEVEL_MIN; \
	} \
} while (0);

static void tcmu_conf_set_options(struct tcmu_config *cfg)
{
	/* set log_level option */
	TCMU_PARSE_CFG_INT(cfg, log_level);
	TCMU_CONF_CHECK_LOG_LEVEL(log_level);

	/* add your new config options */
}

struct tcmu_config *tcmu_config_new(void)
{
	struct tcmu_config *cfg;

	cfg = calloc(1, sizeof(*cfg));
	if (cfg == NULL) {
		tcmu_err("Alloc TCMU config failed!\n");
		return NULL;
	}

	return cfg;
}

void tcmu_config_destroy(struct tcmu_config *cfg)
{
	struct tcmu_conf_option *opt;

	darray_foreach(opt, tcmu_options) {
		if (opt->type == TCMU_OPT_STR)
			free(opt->opt_str);
	}

	darray_free(tcmu_options);

	free(cfg);
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

struct tcmu_conf_option *tcmu_register_option(char *key, tcmu_option_type type)
{
	struct tcmu_conf_option option, *opt;

	option.key = key;
	option.type = type;

	darray_append(tcmu_options, option);

	darray_foreach(opt, tcmu_options) {
		if (!strcmp(opt->key, key))
			return opt;
	}

	tcmu_err("failed to register new option!\n");
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

	while (isblank(*r) || *r == '=')
		r--;
	r++;
	*r = '\0';

	option = tcmu_get_option(p);
	if (!option) {
		r = s;
		while (isblank(*r) || *r == '=')
			r++;

		if (*r == '"' || *r == '\'') {
			type = TCMU_OPT_STR;
		} else if (isdigit(*r)) {
			type = TCMU_OPT_INT;
		} else {
			tcmu_err("option type %d not supported!\n");
			return;
		}

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
		s++;
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

		option->opt_str = strdup(s);
		break;
	default:
		tcmu_err("option type %d not supported!\n");
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

int tcmu_load_config(struct tcmu_config *cfg, const char *path)
{
	char buf[TCMU_MAX_CFG_FILE_SIZE];
	int fd, len;

	if (!path)
		path = "/etc/tcmu/tcmu.conf"; /* the default config file */

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		tcmu_err("Failed to open file '%s'\n", path);
		return -1;
	}

	len = tcmu_read_config(fd, buf, TCMU_MAX_CFG_FILE_SIZE);
	close(fd);
	if (len < 0) {
		tcmu_err("Failed to read file '%s'\n", path);
		return -1;
	}

	buf[len] = '\0';

	tcmu_parse_options(cfg, buf, len);

	return 0;
}
