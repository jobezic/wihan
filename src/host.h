/*
 * Wihand - Wifi hotspot handler daemon
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

#ifndef _HOST_H
#define _HOST_H 1

#include <time.h>
#include "radius.h"
#include "tc.h"

#define __DEFAULT_IDLE  60
#define __OUTGOING_FLUSH 100
#define __TRAFFIC_IN_FLUSH 110
#define __TRAFFIC_OUT_FLUSH 120
#define __OUTGOING_ADD 130
#define __TRAFFIC_IN_ADD 140
#define __TRAFFIC_OUT_ADD 150
#define __CHECK_AUTH 160
#define __READ_TRAFFIC_IN 170
#define __READ_TRAFFIC_OUT 180
#define __REMOVE_HOST 190
#define __FILTER_GLOBAL_ADD 200
#define __NAT_GLOBAL_ADD 210


/* Define the host proto */
typedef struct {
    char ip[20];
    char mac[18];
    char status;
    int staled;
    time_t start_time;
    time_t stop_time;
    unsigned long traffic_in;
    unsigned long traffic_out;
    int idle;
    char session[20];
    unsigned int idle_timeout;
    unsigned int session_timeout;
    unsigned int b_up;
    unsigned int b_down;
    unsigned int max_traffic_in;
    unsigned int max_traffic_out;
    unsigned int max_traffic;
} host_t;

int get_host_by_ip(host_t [], int, char *, host_t **);
void write_hosts_list(host_t *, int);
int authorize_host(char *);
int check_authorized_host(char *);
int update_hosts(host_t *, int, host_t *, int);
int dnat_host(host_t *);
void start_host(host_t *);
void set_host_replies(host_t *, reply_t *);
int auth_host(host_t *, bandclass_t [], int, char *, char *, char *, char *, char *, char *, char *, char *, FILE *);
int iptables_man(const int, char *, char *);
unsigned long read_traffic_data(char *, const int);

#endif
