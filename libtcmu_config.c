/*
 * Copyright 2016, China Mobile, Inc.
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

#include "libtcmu_config.h"
#include "libtcmu_log.h"

static struct tcmu_conf_option tcmu_options[] = {
	{
		.key = "log_level",
		.type = TCMU_OPT_INT,
		{
			.opt_int = 2,
		},
	},
	/* Add new options here */
	{
		.key = NULL,
		.type = TCMU_OPT_NONE,
		{},
	},
};

static int tcmu_get_option_index(const char *key)
{
	int i = 0;

	while (tcmu_options[i].key != NULL) {
		if (!strcmp(tcmu_options[i].key, key))
			return i;
		i++;
	}

	return -1;
}

#define TCMU_PARSE_CFG_INT(cfg, key) \
do { \
	int ind = tcmu_get_option_index(#key); \
	if (ind >= 0) { \
		cfg->key = tcmu_options[ind].opt_int; \
	} \
} while (0)

#define TCMU_PARSE_CFG_BOOL(cfg, key) \
do { \
	int ind = tcmu_get_option_index(#key); \
	if (ind >= 0) { \
		cfg->key = tcmu_options[ind].opt_bool; \
	} \
} while (0)

#define TCMU_PARSE_CFG_STR(cfg, key) \
do { \
	int ind = tcmu_get_option_index(#key); \
	if (ind >= 0) { \
		cfg->key = strdup(tcmu_options[ind].opt_str); } \
} while (0);

#define TCMU_FREE_CFG_STR(cfg, key) \
do { \
	cfg->key = NULL; \
	free(tcmu_options[i]->opt_str); \
} while (0);

#define TCMU_CONF_CHECK_LOG_LEVEL(key) \
do { \
	int ind = tcmu_get_option_index(#key); \
	if (tcmu_options[ind].opt_int > TCMU_CONF_LOG_LEVEL_MAX) { \
		tcmu_options[ind].opt_int = TCMU_CONF_LOG_LEVEL_MAX; \
	} else if (tcmu_options[ind].opt_int < TCMU_CONF_LOG_LEVEL_MIN) { \
		tcmu_options[ind].opt_int = TCMU_CONF_LOG_LEVEL_MIN; \
	} \
} while (0);

static void tcmu_conf_set_options(struct tcmu_config *cfg)
{
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
	/* TCMU_FREE_CFG_STR(cfg, "__STR__"); */

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

static void tcmu_parse_option(char **cur, const char *end)
{
	char *p = *cur, *q = *cur, *r, *s;
	int ind;

	while (isblank(*p))
		p++;

	TCMU_TO_LINE_END(q, end);
	*q = '\0';
	*cur = q + 1;

	s = r = strchr(p, '=');
	if (!r) {
		/* one boolean type option at file end or line end */
		r = p;
		while (!isblank(*r) && r < q)
			r++;
		*r = '\0';
		ind = tcmu_get_option_index(p);
		if (ind < 0)
			return;

		tcmu_options[ind].opt_bool = true;

		return;
	}

	while (isblank(*r) || *r == '=')
		r--;
	r++;
	*r = '\0';
	ind = tcmu_get_option_index(p);
	if (ind < 0)
		return;

	switch (tcmu_options[ind].type) {
		/* one int type option */
		case TCMU_OPT_INT:
			while (!isdigit(*s))
				s++;
			r = s;
			while (isdigit(*r))
				r++;
			*r= '\0';
			tcmu_options[ind].opt_int = atoi(s);
			break;
		/* one string type option */
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

			tcmu_options[ind].opt_str = strdup(s);
			break;
		default:
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
	if (len < 0) {
		tcmu_err("Failed to read file '%s'\n", path);
		return -1;
	}

	close(fd);

	buf[len] = '\0';

	tcmu_parse_options(cfg, buf, len);

	return 0;
}
