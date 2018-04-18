/*
 * radius.h
 *
 * Copyright (C) 2017 Geenkle
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Giovanni Bezicheri <giovanni@geenkle.com>
 */

#ifndef _RADIUS_H
#define _RADIUS_H 1

#include <time.h>

/* Replies */
typedef struct {
    unsigned int idle;
    unsigned int session_timeout;
    unsigned int b_down;
    unsigned int b_up;
    unsigned int traffic_in;
    unsigned int traffic_out;
    unsigned int traffic_total;
} reply_t;

int radclient(char *, char *, char *, char *, char *, reply_t *);
int radacct_start(char *, char *, char *, char *, char *, char *, char *, char *);
int radacct_stop(char *, time_t, unsigned long, unsigned long, char *, char *, char *, char *, char *);
int radacct_interim_update(char *, time_t, unsigned long, unsigned long, char *, char *, char *, char *, char *);

#endif
