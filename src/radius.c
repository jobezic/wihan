/*
 * radius.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

int radclient(char *username) {
    int ret;
    char cmd[255];

    snprintf(cmd, sizeof cmd, "/bin/radiusclient User-Name=\"%s\" > /dev/null 2>&1", username);
    ret = system(cmd);

    return ret;
}

int radacct_start(char *username, char *called_station, char *calling_station, char *session) {
    int ret;
    char cmd[255];
    char token[20];
    char mac[20];

    /* convert username in mac format */
    strcpy(mac, username);
    replacechar(mac, ':', '-');

    /* generate random token */
    gen_random(token, 16);
    strcpy(session, token);

    /*
     * Execute radius session start
     *
     * FIXME: make a fork of the main process for a better solution
     */
    snprintf(cmd,
            sizeof cmd,
            "echo Acct-Status-Type=\"Start\" User-Name=\"%s\" Called-Station-Id=\"%s\" Calling-Station-Id=\"%s\" Acct-Session-Id=\"%s\" | /bin/radacct",
            mac,
            called_station,
            calling_station,
            token);

    ret = system(cmd);

    return ret;
}

int radacct_stop(char *username, time_t session_time, unsigned long octets_in, unsigned long octets_out, char *session) {
    int ret;
    char cmd[255];
    char mac[20];

    /* convert username in mac format */
    strcpy(mac, username);
    replacechar(mac, ':', '-');

    /*
     * Execute radius session stop
     *
     * FIXME: make a fork of the main process for a better solution
     */
    snprintf(cmd,
            sizeof cmd,
            "echo Acct-Status-Type=\"Stop\" User-Name=\"%s\" Acct-Session-Time=%d Acct-Input-Octets=%lu Acct-Output-Octets=%lu Acct-Session-Id=\"%s\" | /bin/radacct",
            mac,
            session_time,
            octets_in,
            octets_out,
            session);

    ret = system(cmd);

    return ret;
}

int radacct_interim_update(char *username, time_t session_time, unsigned long octets_in, unsigned long octets_out, char *session) {
    int ret;
    char cmd[255];
    char mac[20];

    /* convert username in mac format */
    strcpy(mac, username);
    replacechar(mac, ':', '-');

    /*
     * Execute radius session stop
     *
     * FIXME: make a fork of the main process for a better solution
     */
    snprintf(cmd,
            sizeof cmd,
            "echo Acct-Status-Type=3 User-Name=\"%s\" Acct-Session-Time=%d Acct-Input-Octets=%lu Acct-Output-Octets=%lu Acct-Session-Id=\"%s\" | /bin/radacct",
            mac,
            session_time,
            octets_in,
            octets_out,
            session);

    ret = system(cmd);

    return ret;
}
