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
#include <string.h>
#include "../config.h"
#include "wihand.h"
#include "host.h"
#include "utils.h"
#include "radius.h"
#include "tc.h"
#include "wai.h"

static int running = 0;
static int delay = 1;
static char *conf_file_name = NULL;
static char *pid_file_name = NULL;
static int pid_fd = -1;
static char *app_name = "wihand";
static FILE *log_stream = NULL;
host_t hosts[65535];
int hosts_len, loopcount = 1, bclass_len = 0;
bandclass_t bclasses[65535];

static config_t __config = {
    .iface = NULL,
    .iface_network_ip = NULL,
    .wan = NULL,
    .allowed_garden = NULL,
    .logfile = NULL,
    .aaa_method = NULL,
    .radius_host = NULL,
    .radius_authport = NULL,
    .radius_acctport = NULL,
    .radius_secret = NULL,
    .nasidentifier = NULL,
    .config_lma = 0,
    .wai_port = NULL,
    .config_ssl_cert = NULL,
    .config_ssl_key = NULL
};

/**
 * Read configuration from config file
 */
int read_conf_file(config_t *config, int reload)
{
    FILE *conf_file = NULL;
    int ret = -1;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    char param[255] = "";
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
        if (line[0] != '#' && line[0] != '\n') {
            sscanf(line, "%s %s\n", param, val);

            if (strcmp(param, "iface") == 0) {
                config->iface = strdup(val);
            }
            else if (strcmp(param, "net") == 0) {
                config->iface_network_ip = strdup(val);
            }
            else if (strcmp(param, "wan") == 0) {
                config->wan = strdup(val);
            }
            else if (strcmp(param, "allow") == 0) {
                config->allowed_garden = strdup(val);
            }
            else if (strcmp(param, "log") == 0) {
                config->logfile = strdup(val);
            }
            else if (strcmp(param, "aaa_method") == 0) {
                config->aaa_method = strdup(val);
            }
            else if (strcmp(param, "radius") == 0) {
                config->radius_host = strdup(val);
            }
            else if (strcmp(param, "radauthport") == 0) {
                config->radius_authport = strdup(val);
            }
            else if (strcmp(param, "radacctport") == 0) {
                config->radius_acctport = strdup(val);
            }
            else if (strcmp(param, "radsecret") == 0) {
                config->radius_secret = strdup(val);
            }
            else if (strcmp(param, "nasidentifier") == 0) {
                config->nasidentifier = strdup(val);
            }
            else if (strcmp(param, "lma") == 0) {
                config->config_lma = strcmp(val, "yes") == 0;
            }
            else if (strcmp(param, "wai_port") == 0) {
                config->wai_port = strdup(val);
            }
            else if (strcmp(param, "sslcert") == 0) {
                config->config_ssl_cert = strdup(val);
            }
            else if (strcmp(param, "sslkey") == 0) {
                config->config_ssl_key = strdup(val);
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

/**
 * Callback function for handling signals.
 */
void handle_signal(int sig)
{
    int i;
    char logstr[255];

    if (sig == SIGINT) {
        writelog(log_stream, "Stopping daemon ...");

        /* Unset fw rules TODO */

        /* Deinit bandwidth stack */
        if (__config.iface) {
            for (i = 0; i < hosts_len; i++) {
                if (hosts[i].b_up > 0) {
                    snprintf(logstr, sizeof logstr, "Unlimit up bandwidth for host %s", hosts[i].mac);
                    writelog(log_stream, logstr);

                    unlimit_up_band(__config.iface, hosts[i].ip);
                }

                if (hosts[i].b_down > 0) {
                    snprintf(logstr, sizeof logstr, "Unlimit down bandwidth for host %s", hosts[i].mac);
                    writelog(log_stream, logstr);

                    unlimit_down_band(__config.iface, hosts[i].ip);
                }
            }

            if (bclass_len > 0) {
                for (i = 0; i < bclass_len; i++) {
                    snprintf(logstr, sizeof logstr, "Unregister bandwidth class %d", bclasses[i].classid);
                    writelog(log_stream, logstr);

                    unregister_bclass(__config.iface, bclasses[i]);
                }
            }

            writelog(log_stream, "Deinit bandwidth stack");
            deinit_bandwidth_stack(__config.iface);
        }


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
/*    printf("   -l --log_file  filename   Write logs to the file\n");*/
    printf("   -f --foreground           Run in foreground\n");
    printf("   -p --pid_file  filename   PID file used by the daemon\n");
    printf("   -s --status               Print status\n");
    printf("   -a --authorize mac        Authorize host\n");
    printf("\n");
}

int read_arp(host_t *hosts, char *iface) {
    FILE *file = fopen("/proc/net/arp", "r");
    char ip[128], mac[128], mask[128], dev[128];
    int i, type, flags;

    if (file) {
        char line[256];
        i = 0;

        fgets(line, sizeof line, file);

        while (fgets(line, sizeof line, file)) {
            sscanf(line, "%s 0x%x 0x%x %s %s %s\n", ip, &type, &flags, mac, mask, dev);

            if (strcmp(dev, iface) == 0) {
                uppercase(mac);

                strcpy(hosts[i].ip, ip);
                strcpy(hosts[i].mac, mac);
                hosts[i].staled = (flags == 0);

                i++;
            }
        }

        fclose(file);
    }

    return i;
}

/* Main function */
int main(int argc, char *argv[])
{
    static struct option long_options[] = {
        {"conf_file", required_argument, 0, 'c'},
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
    int arp_len, i, retcode, ret, bclass_i, bclass_found, classid;
    char logstr[255];
    char radcmd[255];
    unsigned long traffic_in, traffic_out;
    char* pt;
    reply_t reply;
    time_t curtime;
    char *dnat_reason;
    bandclass_t *dbclass;
    int registered = 0;

    /* init random seed */
    srand(time(NULL));

    /* Try to process all command line arguments */
    while ((value = getopt_long(argc, argv, "c:l:p:a:fsh", long_options, &option_index)) != -1) {
        switch (value) {
            case 'c':
                conf_file_name = strdup(optarg);
                break;
            case 'p':
                pid_file_name = strdup(optarg);
                break;
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
    read_conf_file(&__config, 0);

    /* Try to open log file to this daemon */
    if (__config.logfile != NULL) {
        log_stream = fopen(__config.logfile, "a+");
        if (log_stream == NULL) {
            syslog(LOG_ERR, "Can not open log file: %s, error: %s",
                __config.logfile, strerror(errno));
            log_stream = stdout;
        }
    } else {
        log_stream = stdout;
    }

    /* This global variable can be changed in function handling signal */
    running = 1;

    /* get <interface> mac address for calling station */
    snprintf(logstr, sizeof logstr, "Using interface %s", __config.iface);
    writelog(log_stream, logstr);
    get_mac(__config.iface, called_station);
    uppercase(called_station);
    replacechar(called_station, ':', '-');

    /* set iptables rules */
    snprintf(radcmd, sizeof radcmd, "/etc/wihan/setrules.sh %s %s %s", __config.iface, __config.iface_network_ip, __config.wan);
    ret = system(radcmd);
    if (ret != 0) {
        snprintf(logstr, sizeof logstr, "Fail to set init firewall rules");
        writelog(log_stream, logstr);
    }

    /* Set allowed garden */
    pt = strtok (__config.allowed_garden, ",");
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

    /* init bandwidth stack */
    if (init_bandwidth_stack(__config.iface) == 0) {
        writelog(log_stream, "Init bandwidth stack");
    } else {
        writelog(log_stream, "Failed to init bandwidth stack!");
    }

    /* Read arp list */
    hosts_len = read_arp(hosts, __config.iface);

    /* Start WAI */
    if (__config.wai_port == NULL || start_wai(__config.wai_port, log_stream, __config.config_ssl_cert, __config.config_ssl_key, hosts, hosts_len) != 0) {
        writelog(log_stream, "Failed to init WAI!");
    }

    /* Never ending loop of server */
    while (running == 1) {
        /* EP */

        /* Read arp cache */
        arp_len = read_arp(arp_cache, __config.iface);

        /* Update hosts list */
        hosts_len = update_hosts(hosts, hosts_len, arp_cache, arp_len);

        /* Init mac list */
        for (i = 0; i < hosts_len; i++) {
            /* if status is not set make an auth request */
            if ((!hosts[i].status || (hosts[i].status == 'D' && hosts[i].idle > hosts[i].idle_timeout)) && !hosts[i].staled) {
                /* send auth request for host */
                snprintf(logstr, sizeof logstr, "Sending auth request for %s", hosts[i].mac);
                writelog(log_stream, logstr);

                retcode = auth_host(hosts[i].mac,
                                    __config.aaa_method,
                                    __config.nasidentifier,
                                    __config.radius_host,
                                    __config.radius_authport,
                                    __config.radius_secret,
                                    &reply);

                snprintf(logstr, sizeof logstr, "Auth request %s for %s", (retcode == 0) ? "AUTHORIZED" : "REJECTED", hosts[i].mac);
                writelog(log_stream, logstr);

                /* set host status on auth response outcome */
                if (retcode == 0
                        && iptables_man(__OUTGOING_ADD, hosts[i].mac, NULL) == 0
                        && iptables_man(__TRAFFIC_IN_ADD, hosts[i].mac, NULL) == 0
                        && iptables_man(__TRAFFIC_OUT_ADD, hosts[i].mac, NULL) == 0)
                {
                    start_host(&hosts[i]);
                    snprintf(logstr, sizeof logstr, "Authorize host %s", hosts[i].mac);
                    writelog(log_stream, logstr);

                    /* set host radius params */
                    set_host_replies(&hosts[i], &reply);

                    /* Set bandwidth */
                    if (reply.b_up > 0) {
                        if (limit_up_band(__config.iface, hosts[i].ip, reply.b_up) == 0) {
                            snprintf(logstr, sizeof logstr, "Set up bandwidth limit to %d kbps for host %s", reply.b_up, hosts[i].mac);
                            writelog(log_stream, logstr);
                        } else {
                            snprintf(logstr, sizeof logstr, "Error in setting up bandwidth limit for host %s", hosts[i].mac);
                            writelog(log_stream, logstr);
                        }
                    }

                    if (reply.b_down > 0) {
                        if (get_or_instance_bclass(bclasses, &bclass_len, reply.b_down, __config.iface, &dbclass, &registered) == 0) {
                            if (registered == 1) {
                                snprintf(logstr, sizeof logstr, "Register new down bandwidth class %d", dbclass->classid);
                                writelog(log_stream, logstr);
                            }

                            if (limit_down_band(__config.iface, hosts[i].ip, &bclasses[bclass_i]) == 0) {
                                snprintf(logstr, sizeof logstr, "Set down bandwidth limit to %d kbps for host %s", reply.b_down, hosts[i].mac);
                                writelog(log_stream, logstr);
                            } else {
                                snprintf(logstr, sizeof logstr, "Error in set down bandwidth limit for host %s", hosts[i].mac);
                                writelog(log_stream, logstr);
                            }
                        } else {
                            snprintf(logstr, sizeof logstr, "Error in registering new down bandwidth class %d", dbclass->classid);
                            writelog(log_stream, logstr);
                        }
                    }

                    /* execute start acct */
                    ret = radacct_start(hosts[i].mac,
                                        hosts[i].mac,
                                        called_station,
                                        hosts[i].session,
                                        __config.nasidentifier,
                                        __config.radius_host,
                                        __config.radius_acctport,
                                        __config.radius_secret);

                    if (ret != 0) {
                        snprintf(logstr, sizeof logstr, "Fail to execute radacct start for host %s", hosts[i].mac);
                        writelog(log_stream, logstr);
                    }
                } else {
                    hosts[i].status = 'D';
                }
            }

            /* check for iptables entries for the host (MANUAL AUTH) */
            retcode = check_authorized_host(hosts[i].mac);

            if (!hosts[i].staled && retcode == 0 && hosts[i].status != 'A') {
                start_host(&hosts[i]);
                snprintf(logstr, sizeof logstr, "Authorize host %s", hosts[i].mac);
                writelog(log_stream, logstr);

                /* execute start acct */
                ret = radacct_start(hosts[i].mac,
                                    hosts[i].mac,
                                    called_station,
                                    hosts[i].session,
                                    __config.nasidentifier,
                                    __config.radius_host,
                                    __config.radius_acctport,
                                    __config.radius_secret);

                if (ret != 0) {
                    snprintf(logstr, sizeof logstr, "Fail to execute radacct start for host %s", hosts[i].mac);
                    writelog(log_stream, logstr);
                }
            }

            if (!hosts[i].staled && retcode > 0 && hosts[i].status != 'D') {
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

            /* Check for idle timeout and session timeout */
            curtime = time(NULL);
            if (hosts[i].status == 'A' &&
                (hosts[i].idle > hosts[i].idle_timeout ||
                 hosts[i].session_timeout > 0 && curtime - hosts[i].start_time > hosts[i].session_timeout ||
                 hosts[i].max_traffic_in > 0 && hosts[i].traffic_in > hosts[i].max_traffic_in ||
                 hosts[i].max_traffic_out > 0 && hosts[i].traffic_out > hosts[i].max_traffic_out ||
                 hosts[i].max_traffic > 0 && hosts[i].traffic_in + hosts[i].traffic_out > hosts[i].max_traffic))
            {
                /* Disconnect for idle timeout */
                if (dnat_host(&hosts[i]) == 0) {
                    if (hosts[i].idle > hosts[i].idle_timeout) {
                        dnat_reason = "idle timeout";
                    }
                    else if (hosts[i].max_traffic_in > 0 && hosts[i].traffic_in > hosts[i].max_traffic_in) {
                        dnat_reason = "traffic in limit reached";
                    }
                    else if (hosts[i].max_traffic_out > 0 && hosts[i].traffic_out > hosts[i].max_traffic_out) {
                        dnat_reason = "traffic out limit reached";
                    }
                    else if (hosts[i].max_traffic > 0 && hosts[i].traffic_in + hosts[i].traffic_out > hosts[i].max_traffic) {
                        dnat_reason = "traffic limit reached";
                    }
                    else {
                        dnat_reason = "session timeout";
                    }

                    snprintf(logstr, sizeof logstr, "DNAT %s for %s", hosts[i].mac, dnat_reason);
                    writelog(log_stream, logstr);

                    /* execute stop acct */
                    ret = radacct_stop(hosts[i].mac,
                            difftime(hosts[i].stop_time,hosts[i].start_time),
                            hosts[i].traffic_in,
                            hosts[i].traffic_out,
                            hosts[i].session,
                            __config.nasidentifier,
                            __config.radius_host,
                            __config.radius_acctport,
                            __config.radius_secret);

                    if (ret != 0) {
                        snprintf(logstr, sizeof logstr, "Fail to execute radacct stop for host %s", hosts[i].mac);
                        writelog(log_stream, logstr);
                    }

                    /* Remove bandwidth limits */
                    if (hosts[i].b_up > 0 && unlimit_up_band(__config.iface, hosts[i].ip) != 0) {
                        snprintf(logstr, sizeof logstr, "Fail to remove up bandwidth limit for host %s", hosts[i].mac);
                        writelog(log_stream, logstr);
                    }

                    if (hosts[i].b_down > 0 && unlimit_down_band(__config.iface, hosts[i].ip) != 0) {
                        snprintf(logstr, sizeof logstr, "Fail to remove down bandwidth limit for host %s", hosts[i].mac);
                        writelog(log_stream, logstr);
                    }
                } else {
                    snprintf(logstr, sizeof logstr, "Fail to DNAT %s for %s", hosts[i].mac, dnat_reason);
                    writelog(log_stream, logstr);
                }
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
                            __config.nasidentifier,
                            __config.radius_host,
                            __config.radius_acctport,
                            __config.radius_secret);

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


    /* Stop WAI */
    stop_wai();

    /* Close log file, when it is used. */
    if (log_stream != stdout) {
        fclose(log_stream);
    }

    /* Write system log and close it. */
    syslog(LOG_INFO, "Stopped %s", app_name);
    closelog();

printf("exit wai\n");
    /* Free allocated memory */
    if (conf_file_name != NULL) free(conf_file_name);
    if (pid_file_name != NULL) free(pid_file_name);
    if (__config.iface != NULL) free(__config.iface);
    if (__config.iface_network_ip != NULL) free(__config.iface_network_ip);
    if (__config.wan != NULL) free(__config.wan);
    if (__config.logfile != NULL) free(__config.logfile);
    if (__config.allowed_garden != NULL) free(__config.allowed_garden);
    if (__config.aaa_method != NULL) free(__config.aaa_method);
    if (__config.radius_host != NULL) free(__config.radius_host);
    if (__config.radius_authport != NULL) free(__config.radius_authport);
    if (__config.radius_acctport != NULL) free(__config.radius_acctport);
    if (__config.radius_secret != NULL) free(__config.radius_secret);
    if (__config.nasidentifier != NULL) free(__config.nasidentifier);
    if (__config.wai_port != NULL) free(__config.wai_port);
    if (__config.config_ssl_cert != NULL) free(__config.config_ssl_cert);
    if (__config.config_ssl_key != NULL) free(__config.config_ssl_key);

    return EXIT_SUCCESS;
}
