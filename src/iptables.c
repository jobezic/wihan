/*
 * iptables.c
 *
 * Copyright (C) 2017 Geenkle Technologies
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
 * Author: Giovanni Bezicheri <jobezic@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int flush_chain(const char *table, const char *chain) {
    char cmd[255];
    int retcode;

    snprintf(cmd, sizeof cmd, "iptables -t %s -F %s", table, chain);
    retcode = system(cmd);

    return retcode;
}

int add_mac_rule_to_chain(const char *table, const char *chain, const char *mac, const char *policy) {
    char cmd[255];
    int retcode;

    snprintf(cmd, sizeof cmd, "iptables -t %s -A %s -m mac --mac-source \"%s\" -j %s", table, chain, mac, policy);
    retcode = system(cmd);

    return retcode;
}

int check_chain_rule(const char *table, const char *chain, const char *str) {
    char cmd[255];
    int retcode;

    snprintf(cmd, sizeof cmd, "iptables -t %s -nvL %s | grep %s > /dev/null 2>&1", table, chain, str);
    retcode = system(cmd);

    return retcode;
}

int read_chain_bytes(const char *table, const char *chain, const char *str, char *data) {
    char cmd[255];
    char pres[64] = "";
    int retcode = -1;
    FILE *fp;

    /* retrieve the chain bytes */
    snprintf(cmd,
            sizeof cmd, "iptables -t %s -nxvL %s | grep %s | awk '{ print $2 }' 2> /dev/null",
            table,
            chain,
            str);

    fp = popen(cmd, "r");

    if (fp) {
        fgets(pres, sizeof(pres)-1, fp);
        retcode = pclose(fp);

        if (retcode == 0) {
            strcpy(data, pres);
        }
    }

    return retcode;
}

int remove_rule_from_chain(const char *table, const char * chain, const char* str) {
    char cmd[255];
    char pres[64] = "";
    int retcode = -1;
    FILE *fp;

    /* search the rule to delete */
    snprintf(cmd,
            sizeof cmd, "iptables -t %s -nvL %s --line-numbers | grep %s | tail -n 1 | awk '{ print $1 }'",
            table,
            chain,
            str);

    fp = popen(cmd, "r");

    if (fp) {
        fgets(pres, sizeof(pres)-1, fp);
        retcode = pclose(fp);

        if (retcode == 0) {
            /* rule found, delete it */
            snprintf(cmd, sizeof cmd, "iptables -t %s -D %s %s", table, chain, pres);
            retcode = system(cmd);
        }
    }

    return retcode;
}
