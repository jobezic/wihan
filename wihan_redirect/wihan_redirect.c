/*
 * iptables.c
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
 * Author: Giovanni Bezicheri <jobezic@gmail.com>
 */

#include "mongoose.h"

static const char *s_http_port = "80";
static struct mg_serve_http_opts s_http_server_opts;

static int has_prefix(const struct mg_str *uri, const struct mg_str *prefix) {
  return uri->len == prefix->len && memcmp(uri->p, prefix->p, prefix->len) == 0;
}

static void ev_handler(struct mg_connection *nc, int ev, void *p) {
  static const struct mg_str api_prefix = MG_MK_STR("/hotspot.cgi");
  struct http_message *hm = (struct http_message *) p;
  char* res = "Location: http://hotspot.net/hotspot.cgi";

  if (ev == MG_EV_HTTP_REQUEST) {
    if (has_prefix(&hm->uri, &api_prefix)) {
      mg_serve_http(nc, (struct http_message *) p, s_http_server_opts);
    } else {
      mg_send_head(nc, 302, strlen(res), res);
    }
  }
}

int main(void) {
  struct mg_mgr mgr;
  struct mg_connection *nc;

  mg_mgr_init(&mgr, NULL);
  printf("Starting wihan_redirect on port %s\n", s_http_port);
  nc = mg_bind(&mgr, s_http_port, ev_handler);
  if (nc == NULL) {
    printf("Failed to create listener\n");
    return 1;
  }

  // Set up HTTP server parameters
  mg_set_protocol_http_websocket(nc);
  s_http_server_opts.document_root = ".";  // Serve current directory
  s_http_server_opts.enable_directory_listing = "no";

  for (;;) {
    mg_mgr_poll(&mgr, 1000);
  }
  mg_mgr_free(&mgr);

  return 0;
}
