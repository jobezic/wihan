/*
 * Wihand - Wifi hotspot handler daemon
 *
 * Copyright (C) 2017-2018 Geenkle
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

#ifndef _WIHAND_H
#define _WIHAND_H 1

#define __MAIN_INTERVAL 1
#define __ACCT_INTERVAL 300

typedef struct {
    char *iface;
    char *iface_network_ip;
    char *called_station;
    char *wan;
    char *allowed_garden;
    char *captiveurl;
    char *logfile;
    char *aaa_method;
    int macauth;
    char *radius_host;
    char *radius_authport;
    char *radius_acctport;
    char *radius_secret;
    char *nasidentifier;
    int lma;
    char *wai_port;
    char *ssl_cert;
    char *ssl_key;
} config_t;

#endif
