/*
 * hosts.c
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "host.h"
#include "iptables.h"
#include "utils.h"

int get_host_by_ip(host_t hosts[], int hosts_len, char *ip, host_t **host) {
    int i = 0;
    host_t *target_host = NULL;

    for (i = 0; i < hosts_len; i++) {
        if (strcmp(hosts[i].ip, ip) == 0) {
            target_host = &hosts[i];
            *host = target_host;
            break;
        }
    }

    return target_host == NULL;
}

void write_hosts_list(host_t *hosts, int len) {
    FILE *status_file = NULL;
    char tbuff[20];
    char ebuff[20];
    int i;
    struct tm *sTm;

    status_file = fopen("/tmp/wihand.status", "w+");

    fprintf(status_file, "MAC\t\t\tStatus\tIdle\tSession Start\t\tSession Stop\t\tTraffic In\tTraffic Out\tSession\n");
    fprintf(status_file, "----------------------------------------------------------------------------------------------------------------------------------------\n");

    for (i = 0; i < len; i++) {
        strcpy(tbuff, "                   ");
        strcpy(ebuff, "                   ");

        if (hosts[i].start_time) {
            sTm = gmtime (&hosts[i].start_time);
            strftime (tbuff, sizeof(tbuff), "%Y-%m-%d %H:%M:%S", sTm);
        }

        if (hosts[i].stop_time) {
            sTm = gmtime (&hosts[i].stop_time);
            strftime (ebuff, sizeof(ebuff), "%Y-%m-%d %H:%M:%S", sTm);
        }

        if (hosts[i].traffic_in == 0 && hosts[i].traffic_out == 0) {
            fprintf(status_file, "%s\t%c\t%d\t%s\t%s\n", hosts[i].mac, hosts[i].status, hosts[i].idle, tbuff, ebuff);
        } else {
            fprintf(status_file, "%s\t%c\t%d\t%s\t%s\t\t%lu\t\t%lu\t%s\n",
                    hosts[i].mac,
                    hosts[i].status,
                    hosts[i].idle,
                    tbuff,
                    ebuff,
                    hosts[i].traffic_in,
                    hosts[i].traffic_out,
                    hosts[i].session);
        }
    }

    fclose(status_file);
}

int authorize_host(char *mac)
{
    int ret, ret_tia, ret_toa;

    ret = iptables_man(__OUTGOING_ADD, mac, NULL);
    ret_tia = iptables_man(__TRAFFIC_IN_ADD, mac, NULL);
    ret_toa = iptables_man(__TRAFFIC_OUT_ADD, mac, NULL);

    if (ret == 0 && ret_tia == 0 && ret_toa == 0)
        return 0;
    else
        return -1;
}

int check_authorized_host(char *mac)
{
    int ret;

    ret = iptables_man(__CHECK_AUTH, mac, NULL);

    return ret;
}

int update_hosts(host_t *hosts, int hosts_len, host_t *arp_cache, int arp_cache_len) {
    int i, h, found;
    int new_hosts_len = hosts_len;

    /* Check for new hosts */
    for (i = 0; i < arp_cache_len; i++) {

        /* Check if host exists in the daemon list */
        found = 0;
        for (h = 0; h < new_hosts_len; h++) {
            if (strcmp(hosts[h].mac, arp_cache[i].mac) == 0) {
                hosts[h].staled = arp_cache[i].staled;
                found = 1;
                break;
            }
        }

        if (!found) {
            /* New host found */
            strcpy(hosts[new_hosts_len].ip, arp_cache[i].ip);
            strcpy(hosts[new_hosts_len].mac, arp_cache[i].mac);
            hosts[new_hosts_len].staled = arp_cache[i].staled;

            new_hosts_len++;
        }
    }

    return new_hosts_len;
}

int dnat_host(host_t *host) {
    int ret;

    /* remove host from chains */
    ret = iptables_man(__REMOVE_HOST, host->mac, NULL);

    /* update host status */
    if (ret == 0) {
        host->status = 'D';
        host->stop_time = time(0);
    }

    return ret;
}

void start_host(host_t *host) {
    host->status = 'A';
    host->start_time = time(0);
    host->stop_time = NULL;
    host->idle = 0;
}

void set_host_replies(host_t *host, reply_t *reply) {
    host->idle_timeout = (reply->idle > 0 ? reply->idle : __DEFAULT_IDLE);
    host->session_timeout = reply->session_timeout;
    host->b_up = reply->b_up;
    host->b_down = reply->b_down;
    host->max_traffic_in = reply->traffic_in;
    host->max_traffic_out = reply->traffic_out;
    host->max_traffic = reply->traffic_total;
}

int auth_host(host_t *host,
              char *username,
              char *pass,
              bandclass_t bclasses[],
              int bclass_len,
              char *iface,
              char *mode,
              char *nasid,
              char *called_station,
              char *radhost,
              char *radauthport,
              char *radacctport,
              char *radsecret,
              FILE *log_stream)
{
    int ret = 0;
    reply_t reply;
    bandclass_t *dbclass;
    int registered = 0;
    char logstr[255];

    /* Try to auth the host */
    if (strcmp(mode, "radius") == 0) {
        ret = radclient(username, pass, nasid, radhost, radauthport, radsecret, &reply);
    }

    if (ret == 0) {
        snprintf(logstr, sizeof logstr, "Auth request %s for %s", (ret == 0) ? "AUTHORIZED" : "REJECTED", host->mac);
        writelog(log_stream, logstr);

        /* set host status on auth response outcome */
        if (iptables_man(__OUTGOING_ADD, host->mac, NULL) == 0
                && iptables_man(__TRAFFIC_IN_ADD, host->mac, NULL) == 0
                && iptables_man(__TRAFFIC_OUT_ADD, host->mac, NULL) == 0)
        {
            start_host(host);
            snprintf(logstr, sizeof logstr, "Authorize host %s", host->mac);
            writelog(log_stream, logstr);

            /* set host radius params */
            set_host_replies(host, &reply);

            /* set auth username into host */
            strcpy(host->username, username);

            /* Set bandwidth */
            if (reply.b_up > 0) {
                if (limit_up_band(iface, host->ip, reply.b_up) == 0) {
                    snprintf(logstr, sizeof logstr, "Set up bandwidth limit to %d kbps for host %s", reply.b_up, host->mac);
                    writelog(log_stream, logstr);
                } else {
                    snprintf(logstr, sizeof logstr, "Error in setting up bandwidth limit for host %s", host->mac);
                    writelog(log_stream, logstr);
                }
            }

            if (reply.b_down > 0) {
                if (get_or_instance_bclass(bclasses, &bclass_len, reply.b_down, iface, &dbclass, &registered) == 0) {
                    if (registered == 1) {
                        snprintf(logstr, sizeof logstr, "Register new down bandwidth class %d", dbclass->classid);
                        writelog(log_stream, logstr);
                    }

                    if (limit_down_band(iface, host->ip, dbclass) == 0) {
                        snprintf(logstr, sizeof logstr, "Set down bandwidth limit to %d kbps for host %s", reply.b_down, host->mac);
                        writelog(log_stream, logstr);
                    } else {
                        snprintf(logstr, sizeof logstr, "Error in set down bandwidth limit for host %s", host->mac);
                        writelog(log_stream, logstr);
                    }
                } else {
                    snprintf(logstr, sizeof logstr, "Error in registering new down bandwidth class %d", dbclass->classid);
                    writelog(log_stream, logstr);
                }
            }

            /* execute start acct */
            ret = radacct_start(username,
                                host->mac,
                                called_station,
                                host->session,
                                nasid,
                                radhost,
                                radacctport,
                                radsecret);

            if (ret != 0) {
                snprintf(logstr, sizeof logstr, "Fail to execute radacct start for host %s", host->mac);
                writelog(log_stream, logstr);
            }
        } else {
            host->status = 'D';
        }

    }

    return ret;
}

int iptables_man(const int action, char *mac, char *data) {
    int retcode;

    switch(action) {
        case __OUTGOING_FLUSH:
            retcode = flush_chain("mangle", "wlan0_Outgoing");

            break;
        case __TRAFFIC_IN_FLUSH:
            retcode = flush_chain("filter", "wlan0_Traffic_In");

            break;
        case __TRAFFIC_OUT_FLUSH:
            retcode = flush_chain("filter", "wlan0_Traffic_Out");

            break;
        case __OUTGOING_ADD:
            retcode = add_mac_rule_to_chain("mangle", "wlan0_Outgoing", mac, "MARK --set-mark 2");

            break;
        case __FILTER_GLOBAL_ADD:
            retcode = add_dest_rule("filter", "wlan0_Global", mac, "ACCEPT");

            break;
        case __NAT_GLOBAL_ADD:
            retcode = add_dest_rule("nat", "wlan0_Global", mac, "ACCEPT");

            break;
        case __TRAFFIC_IN_ADD:
            retcode = add_mac_rule_to_chain("filter", "wlan0_Traffic_In", mac, "ACCEPT");

            break;
        case __TRAFFIC_OUT_ADD:
            retcode = add_mac_rule_to_chain("filter", "wlan0_Traffic_Out", mac, "ACCEPT");

            break;
        case __CHECK_AUTH:
            retcode = check_chain_rule("mangle", "wlan0_Outgoing", mac);

            break;
        case __READ_TRAFFIC_IN:
            retcode = read_chain_bytes("filter", "wlan0_Traffic_In", mac, data);

            break;
        case __READ_TRAFFIC_OUT:
            retcode = read_chain_bytes("filter", "wlan0_Traffic_Out", mac, data);

            break;
        case __REMOVE_HOST:
            retcode = remove_rule_from_chain("mangle", "wlan0_Outgoing", mac)
                    || remove_rule_from_chain("filter", "wlan0_Traffic_In", mac)
                    || remove_rule_from_chain("filter", "wlan0_Traffic_Out", mac);
            break;
    }

    return retcode;
}

unsigned long read_traffic_data(char *mac, const int inout) {
    unsigned long res = 0;
    int ret;
    char bytes[64];

    ret = iptables_man(inout, mac, bytes);

    if (ret == 0) {
        if (strcmp(bytes, "") != 0) {
            res = atol(bytes);
        }
    }

    return res;
}
