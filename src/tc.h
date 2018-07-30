/*
 * tc.h
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

#ifndef _TC_H
#define _TC_H 1

typedef struct {
    int classid;
    unsigned int bps;
} bandclass_t;

int init_bandwidth_stack(char *);
int deinit_bandwidth_stack(char *);
int register_bclass(char *, int, unsigned int, bandclass_t *);
int get_or_instance_bclass(bandclass_t [], int *, unsigned int, char *, bandclass_t **, int *);
int unregister_bclass(char *, bandclass_t);
int limit_down_band(char *, char *, bandclass_t *);
int limit_up_band(char *, char *, unsigned int);
int unlimit_up_band(char *, char *);
int unlimit_down_band(char *, char *);

#endif
