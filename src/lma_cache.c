/*
 * lma_cache.c
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
#include <string.h>
#include "lma_cache.h"

int cache_retrieve_host(char *id, entry_t *entry) {
    int ret = -1;
    FILE* fp;

    fp = fopen("/tmp/wihand.bin", "rb");
    if (fp) {
        while(fread(entry, sizeof(*entry), 1, fp)) {
            if (strcmp(entry->id, id) == 0) {
                ret = entry->expired_at > 0 && entry->created_at + time(NULL) > entry->expired_at;
                ret |= entry->session_timeout > 0 && entry->session_time > entry->session_timeout;
                break;
            }
        }

        fclose(fp);
    }

    return ret;
}

int cache_persist_host(entry_t *entry) {
    int ret = -1, read;
    FILE* fp;

    fp = fopen("/tmp/wihand.bin", "a+b");
    if (fp) {
        read = fwrite(entry, sizeof(*entry), 1, fp);

        fclose (fp);

        ret = read != 1;
    }

    return ret;
}

int cache_update_host(entry_t *entry) {
    int ret = -1;
    FILE* fp;
    int p = 0, found = 0, write;
    entry_t entry_read;

    fp = fopen("/tmp/wihand.bin", "rb+");
    if (fp) {
        while(fread(&entry_read, sizeof(entry_read), 1, fp)) {
            if (strcmp(entry_read.id, entry->id) == 0) {
                p = ftell(fp)-sizeof(entry_read);
                found = 1;
                break;
            }
        }

        if (found) {
            fseek(fp, p, SEEK_SET);
            write = fwrite(entry, sizeof(*entry), 1, fp);
            ret = write != 1;
        }

        fclose(fp);
    }

    return ret;
}
