/*
 * tc.c
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
#include "utils.h"
#include "tc.h"

int init_bandwidth_stack(char *dev) {
    char cmd[255];
    int retcode;

    snprintf(cmd, sizeof cmd, "tc qdisc add dev %s handle ffff: ingress", dev);
    retcode = system(cmd);

    snprintf(cmd, sizeof cmd, "tc qdisc add dev %s root handle 1: htb default 1", dev);
    retcode = system(cmd);

    snprintf(cmd, sizeof cmd, "tc class add dev %s parent 1: classid 1:1 htb rate 100gbit burst 15k", dev);
    retcode = system(cmd);

    return retcode;
}

int deinit_bandwidth_stack(char *dev) {
    char cmd[255];
    int retcode;

    snprintf(cmd, sizeof cmd, "tc class del dev %s parent 1: classid 1:1", dev);
    retcode = system(cmd);

    snprintf(cmd, sizeof cmd, "tc qdisc del dev %s root handle 1: htb default 1", dev);
    retcode = system(cmd);

    snprintf(cmd, sizeof cmd, "tc qdisc del dev %s handle ffff: ingress", dev);
    retcode = system(cmd);

    return retcode;
}

int register_bclass(char *dev, int id, unsigned int bps, bandclass_t *bclass) {
    char cmd[255];
    int retcode;

    snprintf(cmd, sizeof cmd, "tc class add dev %s parent 1:1 classid 1:%d htb rate %dbit", dev, id, bps);
    retcode = system(cmd);

    if (retcode == 0) {
        bclass->classid = id;
        bclass->bps = bps;
    }

    return retcode;
}

int unregister_bclass(char *dev, bandclass_t bclass) {
    char cmd[255];
    int retcode;

    snprintf(cmd, sizeof cmd, "tc class del dev %s parent 1: classid 1:%d", dev, bclass.classid);
    retcode = system(cmd);

    return retcode;
}

int limit_up_band(char *dev, char *ip, unsigned int bps) {
    char cmd[255];
    int retcode;
    char addr[3];

    get_last_octects(ip, addr);

    snprintf(cmd, sizeof cmd, "tc filter add dev %s parent ffff: protocol ip prio %s u32 match ip src %s police rate %dbit burst 20k drop flowid :1", dev, addr, ip, bps);
    retcode = system(cmd);

    return retcode;
}

int limit_down_band(char *dev, char *ip, bandclass_t* bclass) {
    char cmd[255];
    int retcode;
    char addr[3];

    get_last_octects(ip, addr);

    snprintf(cmd, sizeof cmd, "tc filter add dev %s protocol ip parent 1:0 prio %s u32 match ip dst %s flowid 1:%d", dev, addr, ip, bclass->classid);
    retcode = system(cmd);

    return retcode;
}

int unlimit_up_band(char *dev, char *ip) {
    char cmd[255];
    int retcode;
    char addr[3];

    get_last_octects(ip, addr);

    snprintf(cmd, sizeof cmd, "tc filter del dev %s parent ffff: protocol ip prio %s", dev, addr);
    retcode = system(cmd);

    return retcode;
}

int unlimit_down_band(char *dev, char *ip) {
    char cmd[255];
    int retcode;
    char addr[3];

    get_last_octects(ip, addr);

    snprintf(cmd, sizeof cmd, "tc filter del dev %s protocol ip parent 1:0 prio %s", dev, addr);
    retcode = system(cmd);

    return retcode;
}

int get_or_instance_bclass(bandclass_t bclasses[],
                           int *bclasses_len,
                           unsigned int bandwidth,
                           char *iface,
                           bandclass_t **bclass,
                           int *registered) {
    int i, classid, found = 0;
    int ret = -1;

    for (i = 0; i < *bclasses_len; i++) {
        if (bclasses[i].bps == bandwidth) {
            found = 1;
            *bclass = &bclasses[i];

            ret = 0;
            break;
        }
    }

    if (found == 0) {
        classid = ((*bclasses_len)+1)*10;

        if (register_bclass(iface, classid, bandwidth, &bclasses[*bclasses_len]) == 0) {
            *bclass = &bclasses[*bclasses_len];
            (*bclasses_len)++;
            *registered = 1;

            ret = 0;
        }
    }

    return ret;
}
