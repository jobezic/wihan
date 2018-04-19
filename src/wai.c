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

struct thread_data {
   int loop;
   const char *wai_port;
   FILE *log_stream;
#if HAVE_LIBSSL
   const char *sslcert;
   const char *sslkey;
#endif
};

struct thread_data intercom_data;

static struct mg_serve_http_opts s_http_server_opts;

static void ev_handler(struct mg_connection *nc, int ev, void *ev_data) {
    struct http_message *hm = (struct http_message *) ev_data;

    switch (ev) {
        case MG_EV_HTTP_REQUEST:
            if (mg_vcmp(&hm->uri, "/") == 0) {
                mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
                mg_printf_http_chunk(nc, "{ \"status\": \"ok\" }");
                mg_send_http_chunk(nc, "", 0);
            }

            break;

         default:
            break;
    }
}

void *WAI(void *thread_arg) {
    struct thread_data *my_data;
    my_data = (struct thread_data *) thread_arg;
    struct mg_mgr mgr;
    struct mg_connection *nc;
    struct mg_bind_opts bind_opts;
    char logstr[255];

    mg_mgr_init(&mgr, NULL);
    memset(&bind_opts, 0, sizeof(bind_opts));
#if HAVE_LIBSSL
    bind_opts.ssl_cert = my_data->sslcert;
    bind_opts.ssl_key = my_data->sslkey;
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
    s_http_server_opts.enable_directory_listing = "no";

    /* Accept requests */
    while (my_data->loop) {
        mg_mgr_poll(&mgr, 1000);
    }

    mg_mgr_free(&mgr);

    writelog(my_data->log_stream, "Exit from WAI main thread");

    pthread_exit(NULL);
}

int start_wai(const char *port, FILE *log_stream, const char *sslcert, const char *sslkey) {
    pthread_t thread;
    int rc;

    intercom_data.loop = 1;
    intercom_data.wai_port = port;
    intercom_data.log_stream = log_stream;
#if HAVE_LIBSSL
    intercom_data.sslcert = sslcert;
    intercom_data.sslkey = sslkey;
#endif
    rc = pthread_create(&thread, NULL, WAI, (void *) &intercom_data);

    return rc;
}

int stop_wai() {
    intercom_data.loop = 0;

    //pthread_exit(NULL);
}
