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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include "../config.h"
#include "utils.h"
#include "iptables.h"
#include "radius.h"


#define __MAIN_INTERVAL 1
#define __ACCT_INTERVAL 300
#define __IDLE_TIMEOUT 60

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
    char ip[16];
    char mac[18];
    char status;
    time_t start_time;
    time_t stop_time;
    unsigned long traffic_in;
    unsigned long traffic_out;
    int idle;
    char session[20];
} host_t;

static int running = 0;
static int delay = 1;
static char *conf_file_name = NULL;
static char *pid_file_name = NULL;
static int pid_fd = -1;
static char *app_name = "wihand";
static char *iface = NULL;
static char *iface_network_ip = NULL;
static char *wan = NULL;
static char *logfile = NULL;
static char *allowed_garden = NULL;
static char *aaa_method = NULL;
static char *radius_host = NULL;
static char *radius_authport = NULL;
static char *radius_acctport = NULL;
static char *radius_secret = NULL;
static char *nasidentifier = NULL;
static FILE *log_stream = NULL;
host_t hosts[65535];
int hosts_len, loopcount = 1;


void writelog(FILE *log_stream, char *msg) {
    struct tm *sTm;
    char buff[20];
    int ret;

    time_t now = time (0);
    sTm = gmtime (&now);
    strftime (buff, sizeof(buff), "%Y-%m-%d %H:%M:%S", sTm);
    ret = fprintf(log_stream, "[%s] %s\n", buff, msg);

    if (ret < 0) {
        syslog(LOG_ERR, "Can not write to log stream: %s", strerror(errno));
        return;
    }
    ret = fflush(log_stream);
    if (ret != 0) {
        syslog(LOG_ERR, "Can not fflush() log stream: %s", strerror(errno));
        return;
    }
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

/**
 * Read configuration from config file
 */
int read_conf_file(int reload)
{
    FILE *conf_file = NULL;
    int ret = -1;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    char param[255];
    char val[255];

    if (conf_file_name == NULL) return 0;

    conf_file = fopen(conf_file_name, "r");

    if (conf_file == NULL) {
        syslog(LOG_ERR, "Can not open config file: %s, error: %s",
                conf_file_name, strerror(errno));
        return -1;
    }

    while ((read = getline(&line, &len, conf_file)) != -1) {
        trim(line);
        if (line[0] != '#' && line != "\n") {
            sscanf(line, "%s %s\n", param, val);

            if (strcmp(param, "iface") == 0) {
                iface = strdup(val);
            }
            else if (strcmp(param, "net") == 0) {
                iface_network_ip = strdup(val);
            }
            else if (strcmp(param, "wan") == 0) {
                wan = strdup(val);
            }
            else if (strcmp(param, "allow") == 0) {
                allowed_garden = strdup(val);
            }
            else if (strcmp(param, "log") == 0) {
                logfile = strdup(val);
            }
            else if (strcmp(param, "aaa_method") == 0) {
                aaa_method = strdup(val);
            }
            else if (strcmp(param, "radius") == 0) {
                radius_host = strdup(val);
            }
            else if (strcmp(param, "radauthport") == 0) {
                radius_authport = strdup(val);
            }
            else if (strcmp(param, "radacctport") == 0) {
                radius_acctport = strdup(val);
            }
            else if (strcmp(param, "radsecret") == 0) {
                radius_secret = strdup(val);
            }
            else if (strcmp(param, "nasidentifier") == 0) {
                nasidentifier = strdup(val);
            }
        }
    }

    if (ret > 0) {
        if (reload == 1) {
            syslog(LOG_INFO, "Reloaded configuration file %s of %s",
                conf_file_name,
                app_name);
        } else {
            syslog(LOG_INFO, "Configuration of %s read from file %s",
                app_name,
                conf_file_name);
        }
    }

    fclose(conf_file);
    if (line) {
        free(line);
    }

    return ret;
}

/**
 * This function tries to test config file
 */
int test_conf_file(char *_conf_file_name)
{
    FILE *conf_file = NULL;
    int ret = -1;

    conf_file = fopen(_conf_file_name, "r");

    if (conf_file == NULL) {
        writelog(log_stream, "Can't read config file");
        return EXIT_FAILURE;
    }

    ret = fscanf(conf_file, "%d", &delay);

    if (ret <= 0) {
        writelog(log_stream, "Wrong config file");
    }

    fclose(conf_file);

    if (ret > 0)
        return EXIT_SUCCESS;
    else
        return EXIT_FAILURE;
}

int print_status()
{
    FILE *status_file = NULL;
    int ret = -1;
    char line [256];

    status_file = fopen("/tmp/wihand.status", "r");

    if (status_file == NULL) {
        writelog(log_stream, "Can't read status file");
        return EXIT_FAILURE;
    }

    while ( fgets(line, sizeof line, status_file) ) {
        printf("%s", line);
    }

    fclose(status_file);

    if (ret > 0)
        return EXIT_SUCCESS;
    else
        return EXIT_FAILURE;

}

int iptables_man(const int action, char* mac, char* data) {
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

int authorize_host(char *mac)
{
    int ret, ret_tia, ret_toa;

    ret = iptables_man(__OUTGOING_ADD, mac, NULL);
    ret_tia = iptables_man(__TRAFFIC_IN_ADD, mac, NULL);
    ret_toa = iptables_man(__TRAFFIC_OUT_ADD, mac, NULL);

    if (ret == 0 && ret_tia == 0 && ret_toa == 0)
        return EXIT_SUCCESS;
    else
        return EXIT_FAILURE;
}

int check_authorized_host(char *mac)
{
    int ret;

    ret = iptables_man(__CHECK_AUTH, mac, NULL);

    return ret;
}


/**
 * Callback function for handling signals.
 */
void handle_signal(int sig)
{
    if (sig == SIGINT) {
        writelog(log_stream, "Stopping daemon ...");
        /* Unlock and close lockfile */
        if (pid_fd != -1) {
            lockf(pid_fd, F_ULOCK, 0);
            close(pid_fd);
        }
        /* Try to delete lockfile */
        if (pid_file_name != NULL) {
            unlink(pid_file_name);
        }
        running = 0;
        /* Reset signal handling to default behavior */
        signal(SIGINT, SIG_DFL);
    } else if (sig == SIGHUP) {
        writelog(log_stream, "Reloading daemon config file ...");
        read_conf_file(1);
    } else if (sig == SIGUSR1) {
    }
}

/**
 * This function will daemonize this app
 */
static void daemonize()
{
    pid_t pid = 0;
    int fd;

    /* Fork off the parent process */
    pid = fork();

    /* An error occurred */
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }

    /* Success: Let the parent terminate */
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    /* On success: The child process becomes session leader */
    if (setsid() < 0) {
        exit(EXIT_FAILURE);
    }

    /* Ignore signal sent from child to parent process */
    /* signal(SIGCHLD, SIG_IGN); */

    /* Fork off for the second time*/
    pid = fork();

    /* An error occurred */
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }

    /* Success: Let the parent terminate */
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    /* Set new file permissions */
    umask(0);

    /* Change the working directory to the root directory */
    /* or another appropriated directory */
    chdir("/");

    /* Close all open file descriptors */
    for (fd = sysconf(_SC_OPEN_MAX); fd > 0; fd--) {
        close(fd);
    }

    /* Reopen stdin (fd = 0), stdout (fd = 1), stderr (fd = 2) */
    /* stdin = fopen("/dev/null", "r");
    stdout = fopen("/dev/null", "w+");
    stderr = fopen("/dev/null", "w+"); */

    /* Try to write PID of daemon to lockfile */
    if (pid_file_name != NULL)
    {
        char str[256];
        pid_fd = open(pid_file_name, O_RDWR|O_CREAT, 0640);
        if (pid_fd < 0) {
            /* Can't open lockfile */
            exit(EXIT_FAILURE);
        }
        if (lockf(pid_fd, F_TLOCK, 0) < 0) {
            /* Can't lock file */
            exit(EXIT_FAILURE);
        }
        /* Get current PID */
        sprintf(str, "%d\n", getpid());
        /* Write PID to lockfile */
        write(pid_fd, str, strlen(str));
    }
}

/**
 * \brief Print help for this application
 */
void print_help(void)
{
    printf("\n Usage: %s [OPTIONS]\n\n", app_name);
    printf("  Options:\n");
    printf("   -h --help                 Print this help\n");
    printf("   -c --conf_file filename   Read configuration from the file\n");
/*    printf("   -t --test_conf filename   Test configuration file\n"); */
/*    printf("   -l --log_file  filename   Write logs to the file\n");*/
    printf("   -f --foreground           Run in foreground\n");
    printf("   -p --pid_file  filename   PID file used by the daemon\n");
    printf("   -s --status               Print status\n");
    printf("   -a --authorize mac        Authorize host\n");
    printf("\n");
}

int read_arp(host_t *hosts, char *iface) {
    FILE *file = fopen("/proc/net/arp", "r");
    char ip[20], mac[18];
    int i;

    if (file) {
        char line[256];
        i = 0;

        fgets(line, sizeof line, file);

        while (fgets(line, sizeof line, file)) {
            char a, b, c, dev[32];

            sscanf(line, "%s %s %s %s %s %s", (char*)&ip, &a, &b, (char*)&mac, &c, &dev);

            if (strcmp(dev, iface) == 0) {
                uppercase(mac);

                strcpy(hosts[i].ip, ip);
                strcpy(hosts[i].mac, mac);

                i++;
            }
        }

        fclose(file);
    }

    return i;
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
                found = 1;
                break;
            }
        }

        if (!found) {
            /* New host found */
            strcpy(hosts[new_hosts_len].ip, arp_cache[i].ip);
            strcpy(hosts[new_hosts_len].mac, arp_cache[i].mac);
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

int start_host(host_t *host) {
    int ret = 0;

    /* set host status to authorize */
    host->status = 'A';
    host->start_time = time(0);
    host->stop_time = NULL;
    host->idle = 0;

    return ret;
}


int auth_host(char *mac, char *mode, char* nasid, char *radhost, char* radport, char *radsecret) {
    int ret = 0;

    if (strcmp(mode, "radius") == 0) {
        ret = radclient(mac, nasid, radhost, radport, radsecret);
    }
    else if (strcmp(mode, "rex") == 0) {
        //TODO
    }

    return ret;
}

/* Main function */
int main(int argc, char *argv[])
{
    static struct option long_options[] = {
        {"conf_file", required_argument, 0, 'c'},
        {"test_conf", required_argument, 0, 't'},
        {"status", no_argument, 0, 's'},
        {"help", no_argument, 0, 'h'},
        {"foreground", no_argument, 0, 'f'},
        {"pid_file", required_argument, 0, 'p'},
        {"authorize", required_argument, 0, 'a'},
        {NULL, 0, 0, 0}
    };
    int value, option_index = 0;
    int start_daemonized = 1;

    char called_station[20];
    host_t arp_cache[1024]; /* FIXME: allocate dynamically */
    int arp_len, i, retcode, ret;
    char logstr[255];
    char radcmd[255];
    unsigned long traffic_in, traffic_out;
    char* pt;

    /* init random seed */
    srand(time(NULL));

    /* Try to process all command line arguments */
    while ((value = getopt_long(argc, argv, "c:l:t:p:a:fsh", long_options, &option_index)) != -1) {
        switch (value) {
            case 'c':
                conf_file_name = strdup(optarg);
                break;
            case 'p':
                pid_file_name = strdup(optarg);
                break;
            case 't':
                return test_conf_file(optarg);
            case 'a':
                return authorize_host(optarg);
            case 's':
                return print_status();
            case 'f':
                start_daemonized = 0;
                break;
            case 'h':
                print_help();
                return EXIT_SUCCESS;
            case '?':
                print_help();
                return EXIT_FAILURE;
            default:
                break;
        }
    }

    /* When daemonizing is requested at command line. */
    if (start_daemonized == 1) {
        /* It is also possible to use glibc function deamon()
         * at this point, but it is useful to customize your daemon. */
        daemonize();
    }

    /* Open system log and write message to it */
    openlog(argv[0], LOG_PID|LOG_CONS, LOG_DAEMON);
    syslog(LOG_INFO, "Started %s", app_name);

    /* Daemon will handle two signals */
    signal(SIGINT, handle_signal);
    signal(SIGHUP, handle_signal);
    signal(SIGUSR1, handle_signal);

    /* Read configuration from config file */
    read_conf_file(0);

    /* Try to open log file to this daemon */
    if (logfile != NULL) {
        log_stream = fopen(logfile, "a+");
        if (log_stream == NULL) {
            syslog(LOG_ERR, "Can not open log file: %s, error: %s",
                logfile, strerror(errno));
            log_stream = stdout;
        }
    } else {
        log_stream = stdout;
    }

    /* This global variable can be changed in function handling signal */
    running = 1;

    /* get <interface> mac address for calling station */
    snprintf(logstr, sizeof logstr, "Using interface %s", iface);
    writelog(log_stream, logstr);
    get_mac(iface, called_station);
    uppercase(called_station);
    replacechar(called_station, ':', '-');

    /* set iptables rules */
    snprintf(radcmd, sizeof radcmd, "/etc/wihan/setrules.sh %s %s %s", iface, iface_network_ip, wan);
    ret = system(radcmd);
    if (ret != 0) {
        snprintf(logstr, sizeof logstr, "Fail to set init firewall rules");
        writelog(log_stream, logstr);
    }

    /* Set allowed garden */
    pt = strtok (allowed_garden, ",");
    while (pt != NULL) {
        if (iptables_man(__FILTER_GLOBAL_ADD, pt, NULL) == 0 && iptables_man(__NAT_GLOBAL_ADD, pt, NULL) == 0) {
            snprintf(logstr, sizeof logstr, "Add %s to allowed garden", pt);
            writelog(log_stream, logstr);
        }

        pt = strtok(NULL, ",");
    }

    /* flush chains */
    if (iptables_man(__OUTGOING_FLUSH, NULL, NULL) == 0) {
        writelog(log_stream, "Flushing outgoing");
    }

    if (iptables_man(__TRAFFIC_IN_FLUSH, NULL, NULL) == 0) {
        writelog(log_stream, "Flushing traffic in");
    }

    if (iptables_man(__TRAFFIC_OUT_FLUSH, NULL, NULL) == 0) {
        writelog(log_stream, "Flushing traffic out");
    }

    /* Read arp list */
    hosts_len = read_arp(hosts, iface);

    /* Never ending loop of server */
    while (running == 1) {
        /* EP */

        /* Read arp cache */
        arp_len = read_arp(arp_cache, iface);

        /* Update hosts list */
        hosts_len = update_hosts(hosts, hosts_len, arp_cache, arp_len);

        /* Init mac list */
        for (i = 0; i < hosts_len; i++) {
            /* if status is not set make an auth request */
            if (!hosts[i].status) {
                /* send auth request for host */
                snprintf(logstr, sizeof logstr, "Sending auth request for %s", hosts[i].mac);
                writelog(log_stream, logstr);

                retcode = auth_host(hosts[i].mac,
                                    aaa_method,
                                    nasidentifier,
                                    radius_host,
                                    radius_authport,
                                    radius_secret);

                snprintf(logstr, sizeof logstr, "Auth request %s for %s", (retcode == 0) ? "AUTHORIZED" : "REJECTED", hosts[i].mac);
                writelog(log_stream, logstr);

                /* set host status on auth response outcome */
                if (retcode == 0
                        && iptables_man(__OUTGOING_ADD, hosts[i].mac, NULL) == 0
                        && iptables_man(__TRAFFIC_IN_ADD, hosts[i].mac, NULL) == 0
                        && iptables_man(__TRAFFIC_OUT_ADD, hosts[i].mac, NULL) == 0)
                {
                    if(start_host(&hosts[i]) == 0) {
                        snprintf(logstr, sizeof logstr, "Authorize host %s", hosts[i].mac);
                        writelog(log_stream, logstr);

                        /* execute start acct */
                        ret = radacct_start(hosts[i].mac,
                                            hosts[i].mac,
                                            called_station,
                                            hosts[i].session,
                                            nasidentifier,
                                            radius_host,
                                            radius_acctport,
                                            radius_secret);

                        if (ret != 0) {
                            snprintf(logstr, sizeof logstr, "Fail to execute radacct start for host %s", hosts[i].mac);
                            writelog(log_stream, logstr);
                        }
                    }
                } else {
                    hosts[i].status = 'D';
                }
            }

            /* check for iptables entries for the host */
            retcode = check_authorized_host(hosts[i].mac);

            if (retcode == 0 && hosts[i].status != 'A') {
                if (start_host(&hosts[i]) == 0) {
                    snprintf(logstr, sizeof logstr, "Authorize host %s", hosts[i].mac);
                    writelog(log_stream, logstr);

                    /* execute start acct */
                    ret = radacct_start(hosts[i].mac,
                                        hosts[i].mac,
                                        called_station,
                                        hosts[i].session,
                                        nasidentifier,
                                        radius_host,
                                        radius_acctport,
                                        radius_secret);

                    if (ret != 0) {
                        snprintf(logstr, sizeof logstr, "Fail to execute radacct start for host %s", hosts[i].mac);
                        writelog(log_stream, logstr);
                    }
                }
            }

            if (retcode > 0 && hosts[i].status != 'D') {
                hosts[i].status = 'D';
            }

            /* set traffic data */
            traffic_in = read_traffic_data(hosts[i].mac, __READ_TRAFFIC_IN);

            if (traffic_in > 0) {
                /* reset idle if traffic */
                if (hosts[i].traffic_in != traffic_in) {
                    hosts[i].idle = 0;
                }

                /* update traffic data */
                hosts[i].traffic_in = traffic_in;
            }

            traffic_out = read_traffic_data(hosts[i].mac, __READ_TRAFFIC_OUT);

            if (traffic_out > 0) {
                /* reset idle if traffic */
                if (hosts[i].traffic_out != traffic_out) {
                    hosts[i].idle = 0;
                }

                /* update traffic data */
                hosts[i].traffic_out = traffic_out;
            }

            /* inc idle timeout if hosts is allowed */
            if (hosts[i].status == 'A') {
                hosts[i].idle++;
            }

            /* Check for idle timeout */
            if (hosts[i].status == 'A' && hosts[i].idle > __IDLE_TIMEOUT) {
                if (dnat_host(&hosts[i]) == 0) {
                    snprintf(logstr, sizeof logstr, "DNAT %s for idle timeout", hosts[i].mac);

                    /* execute stop acct */
                    ret = radacct_stop(hosts[i].mac,
                            difftime(hosts[i].stop_time,hosts[i].start_time),
                            hosts[i].traffic_in,
                            hosts[i].traffic_out,
                            hosts[i].session,
                            nasidentifier,
                            radius_host,
                            radius_acctport,
                            radius_secret);

                    if (ret != 0) {
                        snprintf(logstr, sizeof logstr, "Fail to execute radacct stop for host %s", hosts[i].mac);
                        writelog(log_stream, logstr);
                    }
                } else {
                    snprintf(logstr, sizeof logstr, "Fail to DNAT %s for idle timeout", hosts[i].mac);
                }
                writelog(log_stream, logstr);
            }
        }

        /* Write hosts list */
        write_hosts_list(hosts, hosts_len);

        /* Accounting */
        if (loopcount == __ACCT_INTERVAL) {
            loopcount = 1; /* reset the loop counter */

            /* cycle for each host */
            for (i = 0; i < hosts_len; i++) {
                if (hosts[i].status == 'A') {
                    /* execute interim acct */
                    ret = radacct_interim_update(hosts[i].mac,
                            difftime(time(0), hosts[i].start_time),
                            hosts[i].traffic_in,
                            hosts[i].traffic_out,
                            hosts[i].session,
                            nasidentifier,
                            radius_host,
                            radius_acctport,
                            radius_secret);

                    if (ret != 0) {
                        snprintf(logstr, sizeof logstr, "Fail to execute radacct interim update for host %s", hosts[i].mac);
                        writelog(log_stream, logstr);
                   }
               }

            }
        }

        loopcount++;

        /* Real server should use select() or poll() for waiting at
         * asynchronous event. Note: sleep() is interrupted, when
         * signal is received. */
        sleep(__MAIN_INTERVAL);
    }

    /* Close log file, when it is used. */
    if (log_stream != stdout) {
        fclose(log_stream);
    }

    /* Write system log and close it. */
    syslog(LOG_INFO, "Stopped %s", app_name);
    closelog();

    /* Free allocated memory */
    if (conf_file_name != NULL) free(conf_file_name);
    if (pid_file_name != NULL) free(pid_file_name);
    if (iface != NULL) free(iface);
    if (iface_network_ip != NULL) free(iface_network_ip);
    if (wan != NULL) free(wan);
    if (logfile != NULL) free(logfile);
    if (allowed_garden != NULL) free(allowed_garden);
    if (aaa_method != NULL) free(aaa_method);
    if (radius_host != NULL) free(radius_host);
    if (radius_authport != NULL) free(radius_authport);
    if (radius_acctport != NULL) free(radius_acctport);
    if (radius_secret != NULL) free(radius_secret);
    if (nasidentifier != NULL) free(nasidentifier);

    return EXIT_SUCCESS;
}
