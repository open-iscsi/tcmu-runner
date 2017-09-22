/*
 * Copyright 2017, China Mobile, Inc.
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
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "libtcmu_time.h"

int time_string_now(char* buf)
{
	struct tm *tm;
	struct timeval tv;

	if (gettimeofday (&tv, NULL) < 0)
		return -1;

	/* The value maybe changed in multi-thread*/
	tm = localtime(&tv.tv_sec);
	if (tm == NULL)
		return -1;

	tm->tm_year += 1900;
	tm->tm_mon += 1;

	if (snprintf(buf, TCMU_TIME_STRING_BUFLEN,
	    "%4d-%02d-%02d %02d:%02d:%02d.%03d",
	    tm->tm_year, tm->tm_mon, tm->tm_mday,
	    tm->tm_hour, tm->tm_min, tm->tm_sec,
	    (int) (tv.tv_usec / 1000ull % 1000)) >= TCMU_TIME_STRING_BUFLEN)
		return ERANGE;

	return 0;
}
