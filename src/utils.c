/*
 * utils.c
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

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

void uppercase ( char *sPtr )
{
    while ( *sPtr != '\0' ) {
        *sPtr = toupper ( ( unsigned char ) *sPtr );
        ++sPtr;
    }
}

void gen_random(char *s, const int len) {
    int i;
    static const char alphanum[] =
        "0123456789"
        "abcdef";

    for (i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    s[len] = 0;
}

int replacechar(char *str, char orig, char rep) {
    char *ix = str;
    int n = 0;

    while ((ix = strchr(ix, orig)) != NULL) {
        *ix++ = rep;
        n++;
    }

    return n;
}

int get_mac(char *iface, char *mac) {
    char path[60];
    FILE *f;
    int ret = -1, chread;

    snprintf(path, sizeof path, "/sys/class/net/%s/address", iface);

    f = fopen(path, "r");

    if (f) {
        chread = fscanf(f, "%s", mac);

        if (chread > 0) {
            ret = 0;
        }

        fclose(f);
    }

    return ret;
}
