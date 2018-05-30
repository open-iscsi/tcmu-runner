/*
 * Copyright 2017 China Mobile, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */

/* The time format string
 *
 * Yr  Mon  Day  Hour  Min  Sec Ms
 * %4d-%02d-%02d %02d:%02d:%02d.%03d
 *
 */

# define TCMU_TIME_STRING_BUFLEN \
    (4 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 3 + 1)
/*   Yr      Mon     Day     Hour    Min     Sec     Ms  NULL */

/* generate localtime string into buf */
int time_string_now(char* buf);
