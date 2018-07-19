/*
 * wai.c
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
#include <pthread.h>
#include "../config.h"
#include "../mongoose/mongoose.h"
#include "utils.h"
#include "host.h"
#include "wihand.h"

struct thread_data {
   int loop;
   const char *wai_port;
   FILE *log_stream;
   host_t *hosts;
   int *hosts_len;
   bandclass_t *bclasses;
   int *bclasses_len;
   const config_t *config;
};

struct thread_data intercom_data;

static void handle_login(struct mg_connection *nc,
                         struct http_message *hm,
                         host_t *hosts,
                         const int hosts_len,
                         bandclass_t bclasses[],
                         int bclasses_len,
                         FILE *log_stream,
                         char *iface,
                         char *aaa_method,
                         int lma,
                         char *nasidentifier,
                         char *called_station,
                         char *radius_host,
                         char *radius_authport,
                         char *radius_acctport,
                         char *radius_secret) {
    char src_addr[32];
    char username[128], password[128], token[128], userurl[255];
    char logstr[255];
    int retcode = 0;
    host_t *host;
    reply_t reply;
    int ret;

    mg_sock_addr_to_str(&nc->sa, src_addr, sizeof(src_addr), MG_SOCK_STRINGIFY_IP);

    mg_get_http_var(&hm->query_string, "username", username, sizeof(username));
    mg_get_http_var(&hm->query_string, "password", password, sizeof(password));
    mg_get_http_var(&hm->query_string, "token", token, sizeof(token));
    mg_get_http_var(&hm->query_string, "userurl", userurl, sizeof(userurl));

    snprintf(logstr, sizeof logstr, "WAI /login request received from ip %s", src_addr);
    writelog(log_stream, logstr);

    mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: text/plain\r\n\r\n");

    if (get_host_by_ip(hosts, hosts_len, src_addr, &host) == 0) {
        if (!host->status || host->status == 'D') {
            // Try to auth with username, password passed
            snprintf(logstr, sizeof logstr, "Sending auth request for %s", host->mac);
            writelog(log_stream, logstr);

            ret = auth_host(host,
                            strlen(token) > 0 ? token : username,
                            strlen(token) > 0 ? "token-pass" : password,
                            bclasses,
                            bclasses_len,
                            iface,
                            aaa_method,
                            lma,
                            nasidentifier,
                            called_station,
                            radius_host,
                            radius_authport,
                            radius_acctport,
                            radius_secret,
                            log_stream);

            if (ret == 0) {
               mg_printf(nc, "{ \"status\": \"ok\" }");
            } else {
               mg_printf(nc, "{ \"status\": \"error\" }");
            }
        } else {
            mg_printf(nc, "{ \"status\": \"error\" }");
        }
    } else {
        mg_printf(nc, "{ \"status\": \"error\" }");
    }

    nc->flags |= MG_F_SEND_AND_CLOSE;
}

static void handle_status(struct mg_connection *nc, struct http_message *hm, host_t *hosts, const int hosts_len) {
    char src_addr[32];
    host_t *host;

    mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: text/plain\r\n\r\n");

    mg_sock_addr_to_str(&nc->sa, src_addr, sizeof(src_addr), MG_SOCK_STRINGIFY_IP);

    if (get_host_by_ip(hosts, hosts_len, src_addr, &host) == 0) {
            mg_printf(nc, "{ \"ip\": \"%s\""
                          ", \"mac\": \"%s\""
                          ", \"status\": \"%c\" }",
                    host->ip,
                    host->mac,
                    host->status);
    } else {
        mg_printf(nc, "{ \"status\": \"error\" }");
    }

    nc->flags |= MG_F_SEND_AND_CLOSE;
}

static int has_prefix(const struct mg_str *uri, const struct mg_str *prefix) {
  return uri->len == prefix->len && memcmp(uri->p, prefix->p, prefix->len) == 0;
}

static void ev_handler(struct mg_connection *nc, int ev, void *ev_data) {
    struct http_message *hm = (struct http_message *) ev_data;
    static const struct mg_str api_prefix = MG_MK_STR("/hotspot.cgi");
    char addr[32];
    struct thread_data *t_data;
    char* res = "Location: /hotspot.cgi";
    char redirect_str[512];
    host_t *host;

    t_data = (struct thread_data *)nc->user_data;

    switch (ev) {
        case MG_EV_HTTP_REQUEST:
            mg_sock_addr_to_str(&nc->sa, addr, sizeof(addr), MG_SOCK_STRINGIFY_IP);

            if (mg_vcmp(&hm->uri, "/test") == 0) {
                mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: text/plain\r\n\r\n");
                mg_printf(nc, "{ \"status\": \"ok\" }");
                nc->flags |= MG_F_SEND_AND_CLOSE;
            }
            else if (mg_vcmp(&hm->uri, "/status") == 0) {
                handle_status(nc, hm, t_data->hosts, *t_data->hosts_len);
            }
            else if (mg_vcmp(&hm->uri, "/login") == 0) {
                handle_login(nc,
                             hm,
                             t_data->hosts,
                             *t_data->hosts_len,
                             t_data->bclasses,
                             *t_data->bclasses_len,
                             t_data->log_stream,
                             t_data->config->iface,
                             t_data->config->aaa_method,
                             t_data->config->lma,
                             t_data->config->nasidentifier,
                             t_data->config->called_station,
                             t_data->config->radius_host,
                             t_data->config->radius_authport,
                             t_data->config->radius_acctport,
                             t_data->config->radius_secret);
            } else if (has_prefix(&hm->uri, &api_prefix)) {
                mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: text/html\r\n\r\n");

                if (get_host_by_ip(t_data->hosts, *t_data->hosts_len, addr, &host) == 0) {
                    char host_mac[30];
                    strcpy(host_mac, host->mac);
                    replacechar(host_mac, ':', '-');
                    snprintf(redirect_str, sizeof redirect_str, "<head><title>Redirecting</title><META http-equiv=\"refresh\" content=\"0;URL=%s?nas=%s&mac=%s\"></head><body></body></html>",
                            t_data->config->captiveurl,
                            t_data->config->called_station,
                            host_mac);
                    mg_printf(nc, redirect_str);
                } else {
                    mg_printf(nc, "{ \"status\": \"error\" }");
                }

                nc->flags |= MG_F_SEND_AND_CLOSE;
            }
            else if (mg_vcmp(&hm->uri, "/favicon.ico") == 0) {
                mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: text/plain\r\n\r\n");
                nc->flags |= MG_F_SEND_AND_CLOSE;
            } else {
                mg_send_head(nc, 302, strlen(res), res);
                nc->flags |= MG_F_SEND_AND_CLOSE;
            }

            break;

         default:
            break;
    }
}

void *WAI(void *thread_arg) {
    struct thread_data *my_data;
    struct mg_mgr mgr;
    struct mg_connection *nc, *nc_http;
    struct mg_bind_opts bind_opts;
    char logstr[255];
    char http_port[20];

    my_data = (struct thread_data *) thread_arg;

    snprintf(http_port, sizeof http_port, "%d", atoi(my_data->wai_port)-1);

    mg_mgr_init(&mgr, NULL);
    memset(&bind_opts, 0, sizeof(bind_opts));
    bind_opts.user_data = my_data;
    nc_http = mg_bind_opt(&mgr, http_port, ev_handler, bind_opts);
#if HAVE_LIBSSL
    bind_opts.ssl_cert = my_data->config->ssl_cert;
    bind_opts.ssl_key = my_data->config->ssl_key;
#endif
    nc = mg_bind_opt(&mgr, my_data->wai_port, ev_handler, bind_opts);
    if (nc == NULL) {
        snprintf(logstr, sizeof logstr, "Error starting WAI on port %s", my_data->wai_port);
        writelog(my_data->log_stream, logstr);
        return NULL;
    }

    snprintf(logstr, sizeof logstr, "Starting WAI on port %s", my_data->wai_port);
    writelog(my_data->log_stream, logstr);

    // Set up HTTP server parameters
    mg_set_protocol_http_websocket(nc);
    mg_set_protocol_http_websocket(nc_http);

    /* Accept requests */
    while (my_data->loop) {
        mg_mgr_poll(&mgr, 1000);
    }

    mg_mgr_free(&mgr);

    writelog(my_data->log_stream, "Exit from WAI main thread");

    pthread_exit(NULL);
}

int start_wai(const char *port,
              FILE *log_stream,
              const config_t *config,
              host_t hosts[],
              const int *hosts_len,
              bandclass_t bclasses[],
              const int *bclass_len) {
    pthread_t thread;
    int rc;

    intercom_data.loop = 1;
    intercom_data.wai_port = port;
    intercom_data.log_stream = log_stream;
    intercom_data.hosts = hosts;
    intercom_data.hosts_len = hosts_len;
    intercom_data.bclasses = bclasses;
    intercom_data.bclasses_len = bclass_len;
    intercom_data.config = config;

    rc = pthread_create(&thread, NULL, WAI, (void *) &intercom_data);

    return rc;
}

int stop_wai() {
    intercom_data.loop = 0;

    //pthread_exit(NULL);
}
