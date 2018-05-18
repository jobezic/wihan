/*
 * iptables.h
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

#ifndef _IPTABLES_H
#define _IPTABLES_H 1

int remove_rule_from_chain(const char *, const char *, const char *);
int read_chain_bytes(const char *, const char *, const char *, char *);
int check_chain_rule(const char *, const char *, const char *);
int add_mac_rule_to_chain(const char *, const char *, const char *, const char *);
int add_dest_rule(const char*, const char *, const char *, const char *);
int flush_chain(const char *, const char *);

#endif
