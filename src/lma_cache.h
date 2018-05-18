/*
 * lma_cache.h
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

#ifndef _LMA_CACHE_H
#define _LMA_CACHE_H 1

#include "radius.h"
#include "host.h"

typedef struct {
    char id[20];
    unsigned int created_at;
    unsigned int expired_at;
    unsigned int session_timeout;
    unsigned int session_time;
    limits_t limits;
} entry_t;

int cache_retrieve_host(char *, entry_t *);
int cache_persist_host(entry_t *);
int cache_update_host(entry_t *);

#endif
