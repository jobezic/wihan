# Copyright (C) 2017 Geenkle
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.  If not, see
# <http://www.gnu.org/licenses/>.
#
# Author: Giovanni Bezicheri <giovanni@geenkle.com>
#

AC_PREREQ([2.59])
AC_INIT([wihan], [1.0], [giovanni@geenkle.com])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AM_INIT_AUTOMAKE

AC_PROG_CC
AM_PROG_CC_C_O

AC_LANG([C])

#PKG_CHECK_MODULES([libjson_c], [json-c])

AC_SEARCH_LIBS([pthread_mutex_lock], [pthread])

AC_CONFIG_SUBDIRS([wihan_redirect])
AC_CONFIG_SUBDIRS([freeradius-client])
AC_OUTPUT
