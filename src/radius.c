/*
 * radius.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wait.h>
#include "utils.h"
#include "radius.h"

int radclient(char *username, char *pass, char *nasid, char *host, char *port, char *secret, reply_t *reply) {
    int ret;
    char cmd[512];
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    char param[255] = "";
    char val[255];

    snprintf(cmd, sizeof cmd, "echo User-Name=%s,User-Password=%s,NAS-Identifier=%s | radclient -4xt 2 %s:%s auth %s", username, pass, nasid, host, port, secret);

    fp = popen(cmd, "r");
    if (fp) {
        while (getline(&line, &len, fp) != -1) {
            trim(line);
            sscanf(line, "%s = %s\n", param, val);

            if (strcmp(param, "Idle-Timeout") == 0) {
                reply->idle = atoi(val);
            }
            else if (strcmp(param, "Session-Timeout") == 0) {
                reply->session_timeout = atoi(val);
            }
            else if (strcmp(param, "WISPr-Bandwidth-Max-Down") == 0) {
                reply->b_down = atoi(val);
            }
            else if (strcmp(param, "WISPr-Bandwidth-Max-Up") == 0) {
                reply->b_up = atoi(val);
            }
            else if (strcmp(param, "ChilliSpot-Max-Input-Octets") == 0) {
                reply->traffic_in = atoi(val);
            }
            else if (strcmp(param, "ChilliSpot-Max-Output-Octets") == 0) {
                reply->traffic_out = atoi(val);
            }
            else if (strcmp(param, "ChilliSpot-Max-Total-Octets") == 0) {
                reply->traffic_total = atoi(val);
            }

            if (line != NULL) {
                free(line);
                line = NULL;
            }
        }

        if (line != NULL) {
            free(line);
            line = NULL;
        }
    }

    ret = pclose(fp);

    return WEXITSTATUS(ret);
}

int radacct_start(char *username,
        char *called_station,
        char *calling_station,
        char *session,
        char *nasid,
        char *radhost,
        char *radport,
        char *radsecret) {
    int ret;
    char cmd[512];
    char token[20];
    char mac[128];

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
            "echo Acct-Status-Type=\"Start\",User-Name=\"%s\",Called-Station-Id=\"%s\",Calling-Station-Id=\"%s\",Acct-Session-Id=\"%s\",NAS-Identifier=\"%s\" | radclient -4t 2 %s:%s acct %s",
            mac,
            called_station,
            calling_station,
            token,
            nasid,
            radhost,
            radport,
            radsecret);

    ret = system(cmd);

    return ret;
}

int radacct_stop(char *username,
        time_t session_time,
        unsigned long octets_in,
        unsigned long octets_out,
        char *session,
        char *nasid,
        char *radhost,
        char *radport,
        char *radsecret) {
    int ret;
    char cmd[512];
    char mac[128];

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
            "echo Acct-Status-Type=\"Stop\",User-Name=\"%s\",Acct-Session-Time=%d,Acct-Input-Octets=%lu,Acct-Output-Octets=%lu,Acct-Session-Id=\"%s\",NAS-Identifier=\"%s\" | radclient -4t 2 %s:%s acct %s",
            mac,
            session_time,
            octets_in,
            octets_out,
            session,
            nasid,
            radhost,
            radport,
            radsecret);

    ret = system(cmd);

    return ret;
}

int radacct_interim_update(char *username,
                           time_t session_time,
                           unsigned long octets_in,
                           unsigned long octets_out,
                           char *session,
                           char *nasid,
                           char *radhost,
                           char *radport,
                           char *radsecret) {
    int ret;
    char cmd[512];
    char mac[128];

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
            "echo Acct-Status-Type=3,User-Name=\"%s\",Acct-Session-Time=%d,Acct-Input-Octets=%lu,Acct-Output-Octets=%lu,Acct-Session-Id=\"%s\",NAS-Identifier=\"%s\" | radclient -4t 2 %s:%s acct %s",
            mac,
            session_time,
            octets_in,
            octets_out,
            session,
            nasid,
            radhost,
            radport,
            radsecret);

    ret = system(cmd);

    return ret;
}
