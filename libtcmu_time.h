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
