# Copyright (C) 2017-2018 Geenkle
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

AUTOMAKE_OPTIONS = foreign nostdinc
bin_PROGRAMS = wihand
wihand_LDADD = -lpthread

if WITH_SSL
wihand_CPPFLAGS = -DMG_ENABLE_SSL -DCONFDIR='"$(confdir)"'
wihand_LDADD += -lssl -lcrypto
endif

wihand_SOURCES = \
	src/host.c \
	src/iptables.c \
	src/radius.c \
	src/utils.c \
	src/tc.c \
	src/wihand.c \
	src/lma_cache.c \
	mongoose/mongoose.c \
	src/wai.c

confdir = $(sysconfdir)/@PACKAGE@

conf_DATA = example/conf

dist_conf_SCRIPTS = utils/setrules.sh
