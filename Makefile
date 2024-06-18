# Makefile for HaxIRCd
#
# Written by: Test_User <hax@andrewyu.org>
#
# This is free and unencumbered software released into the public
# domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

ORIGINAL_CFLAGS := $(CFLAGS)

INCLUDEFLAGS =

LDFLAGS = -lpthread

.makeopts:
	printf '%s\n' 'LAST_PLAINTEXT_CLIENT = $(PLAINTEXT_CLIENT)' > .makeopts
	printf '%s\n' 'LAST_PLAINTEXT_SERVER = $(PLAINTEXT_SERVER)' >> .makeopts
	printf '%s\n' 'LAST_GNUTLS_CLIENT = $(GNUTLS_CLIENT)' >> .makeopts
	printf '%s\n' 'LAST_GNUTLS_SERVER = $(GNUTLS_SERVER)' >> .makeopts
	printf '%s\n' 'LAST_OPENSSL_CLIENT = $(OPENSSL_CLIENT)' >> .makeopts
	printf '%s\n' 'LAST_OPENSSL_SERVER = $(OPENSSL_SERVER)' >> .makeopts
	printf '%s\n' 'LAST_INSPIRCD2_PROTOCOL = $(INSPIRCD2_PROTOCOL)' >> .makeopts
	printf '%s\n' 'LAST_INSPIRCD3_PROTOCOL = $(INSPIRCD3_PROTOCOL)' >> .makeopts
	printf '%s\n' 'LAST_HAXSERV_PSEUDOCLIENT = $(HAXSERV_PSEUDOCLIENT)' >> .makeopts
	printf '%s\n' 'LAST_SAFE_STACK = $(SAFE_STACK)' >> .makeopts
	printf '%s\n' 'LAST_FUTEX = $(FUTEX)' >> .makeopts
	printf '%s\n' 'LAST_CFLAGS = $(ORIGINAL_CFLAGS)' >> .makeopts
	printf '%s\n' 'LAST_CC = $(CC)' >> .makeopts

include .makeopts

rebuild = 0

# tabs not allowed :(
ifneq ($(PLAINTEXT_CLIENT),)
ifneq ($(PLAINTEXT_CLIENT),$(LAST_PLAINTEXT_CLIENT))
rebuild = 1
endif
else
PLAINTEXT_CLIENT = $(LAST_PLAINTEXT_CLIENT)
endif

ifneq ($(PLAINTEXT_SERVER),)
ifneq ($(PLAINTEXT_SERVER),$(LAST_PLAINTEXT_SERVER))
rebuild = 1
endif
else
PLAINTEXT_SERVER = $(LAST_PLAINTEXT_SERVER)
endif

ifneq ($(GNUTLS_CLIENT),)
ifneq ($(GNUTLS_CLIENT),$(LAST_GNUTLS_CLIENT))
rebuild = 1
endif
else
GNUTLS_CLIENT = $(LAST_GNUTLS_CLIENT)
endif

ifneq ($(GNUTLS_SERVER),)
ifneq ($(GNUTLS_SERVER),$(LAST_GNUTLS_SERVER))
rebuild = 1
endif
else
GNUTLS_SERVER = $(LAST_GNUTLS_SERVER)
endif

ifneq ($(OPENSSL_CLIENT),)
ifneq ($(OPENSSL_CLIENT),$(LAST_OPENSSL_CLIENT))
rebuild = 1
endif
else
OPENSSL_CLIENT = $(LAST_OPENSSL_CLIENT)
endif

ifneq ($(OPENSSL_SERVER),)
ifneq ($(OPENSSL_SERVER),$(LAST_OPENSSL_SERVER))
rebuild = 1
endif
else
OPENSSL_SERVER = $(LAST_OPENSSL_SERVER)
endif

ifneq ($(INSPIRCD2_PROTOCOL),)
ifneq ($(INSPIRCD2_PROTOCOL),$(LAST_INSPIRCD2_PROTOCOL))
rebuild = 1
endif
else
INSPIRCD2_PROTOCOL = $(LAST_INSPIRCD2_PROTOCOL)
endif

ifneq ($(INSPIRCD3_PROTOCOL),)
ifneq ($(INSPIRCD3_PROTOCOL),$(LAST_INSPIRCD3_PROTOCOL))
rebuild = 1
endif
else
INSPIRCD3_PROTOCOL = $(LAST_INSPIRCD3_PROTOCOL)
endif

ifneq ($(HAXSERV_PSEUDOCLIENT),)
ifneq ($(HAXSERV_PSEUDOCLIENT),$(LAST_HAXSERV_PSEUDOCLIENT))
rebuild = 1
endif
else
HAXSERV_PSEUDOCLIENT = $(LAST_HAXSERV_PSEUDOCLIENT)
endif

ifneq ($(SAFE_STACK),)
ifneq ($(SAFE_STACK),$(LAST_SAFE_STACK))
rebuild = 1
endif
else
SAFE_STACK = $(LAST_SAFE_STACK)
endif

ifneq ($(ORIGINAL_CFLAGS),)
ifneq ($(ORIGINAL_CFLAGS),$(LAST_CFLAGS))
rebuild = 1
endif
else
ORIGINAL_CFLAGS = $(LAST_CFLAGS)
CFLAGS = $(LAST_CFLAGS)
endif

ifneq ($(CC),)
ifneq ($(CC),$(LAST_CC))
rebuild = 1
endif
else
CC = $(LAST_CC)
endif

ifneq ($(FUTEX),)
ifneq ($(FUTEX),$(LAST_FUTEX))
rebuild = 1
endif
else
FUXEX = $(LAST_FUTEX)
endif

ifeq ($(rebuild),1)
.PHONY: .makeopts
endif

CFLAGS += $(INCLUDEFLAGS) -D_REENTRANT -ggdb3 -Wall -Wextra -Wsign-conversion -Wno-unused-parameter -Wno-implicit-fallthrough -std=gnu99

USE_PLAINTEXT = 0
USE_CLIENT = 0
USE_GNUTLS = 0
USE_SERVER = 0

OFILES = config.o general_network.o haxstring_utils.o real_main.o table.o mutex.o
SOFILES = HaxIRCd.so

ifeq ($(PLAINTEXT_CLIENT),1)
CFLAGS += -DUSE_PLAINTEXT_CLIENT
USE_CLIENT = 1
USE_PLAINTEXT = 1
endif

ifeq ($(PLAINTEXT_SERVER),1)
CFLAGS += -DUSE_PLAINTEXT_SERVER
USE_SERVER = 1
USE_PLAINTEXT = 1
endif

ifeq ($(GNUTLS_CLIENT),1)
CFLAGS += -DUSE_GNUTLS_CLIENT
USE_CLIENT = 1
USE_GNUTLS = 1
endif

ifeq ($(GNUTLS_SERVER),1)
CFLAGS += -DUSE_GNUTLS_SERVER
USE_SERVER = 1
USE_GNUTLS = 1
endif

ifeq ($(OPENSSL_CLIENT),1)
CFLAGS += -DUSE_OPENSSL_CLIENT
USE_CLIENT = 1
USE_OPENSSL = 1
endif

ifeq ($(OPENSSL_SERVER),1)
CFLAGS += -DUSE_OPENSSL_SERVER
USE_SERVER = 1
USE_OPENSSL = 1
endif



ifeq ($(INSPIRCD2_PROTOCOL),1)
OFILES += protocols/inspircd2.o
CFLAGS += -DUSE_INSPIRCD2_PROTOCOL
USE_PROTOCOLS = 1
endif

ifeq ($(INSPIRCD3_PROTOCOL),1)
OFILES += protocols/inspircd3.o
CFLAGS += -DUSE_INSPIRCD3_PROTOCOL
USE_PROTOCOLS = 1
endif



ifeq ($(HAXSERV_PSEUDOCLIENT),1)
SOFILES += pseudoclients/haxserv.so
CFLAGS += -DUSE_HAXSERV_PSEUDOCLIENT
USE_PSEUDOCLIENTS = 1
endif



ifeq ($(USE_CLIENT),1)
OFILES += client_network.o
CFLAGS += -DUSE_CLIENT
endif

ifeq ($(USE_SERVER),1)
ifneq ($(USE_PROTOCOLS),1)
$(error You must use some s2s protocol if you want to use a server transport layer)
endif
OFILES += server_network.o
CFLAGS += -DUSE_SERVER
endif

ifeq ($(USE_PLAINTEXT),1)
OFILES += plaintext_network.o
CFLAGS += -DUSE_PLAINTEXT
endif

ifeq ($(USE_GNUTLS),1)
OFILES += gnutls_network.o
CFLAGS += -DUSE_GNUTLS $(shell pkg-config gnutls --cflags)
LDFLAGS += $(shell pkg-config gnutls --libs)
endif

ifeq ($(USE_OPENSSL),1)
OFILES += openssl_network.o
CFLAGS += -DUSE_OPENSSL $(shell pkg-config openssl --cflags)
LDFLAGS += $(shell pkg-config openssl --libs)
endif



ifeq ($(USE_PROTOCOLS),1)
ifneq ($(USE_SERVER),1)
$(error You must have some form of server transport layer enabled if you hope to use an s2s protocol)
endif
OFILES += protocols.o
endif



ifeq ($(USE_PSEUDOCLIENTS),1)
OFILES += pseudoclients.o
CFLAGS += -DUSE_PSEUDOCLIENTS
endif



ifeq ($(FUTEX),1)
CFLAGS += -DUSE_FUTEX
endif



ifeq ($(SAFE_STACK),1)
CFLAGS += -fstack-check
endif



DEPS = $(shell $(CC) $(CFLAGS) -M -MT $(1).$(2) $(1).c | sed 's_\\$$__') .makeopts Makefile


.PHONY: all clean
all: HaxIRCd $(SOFILES)

HaxIRCd: main.c
	$(CC) main.c -o HaxIRCd

HaxIRCd.so: $(OFILES) .makeopts Makefile
	$(CC) $(OFILES) -shared -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

%.so: %.c
	$(CC) $(CFLAGS) -shared -fPIC $< -o $@

$(call DEPS,config,o)

$(call DEPS,general_network,o)

$(call DEPS,haxstring_utils,o)

$(call DEPS,real_main,o)

$(call DEPS,main,o)

$(call DEPS,mutex,o)

$(call DEPS,protocols,o)

$(call DEPS,table,o)

ifeq ($(USE_PLAINTEXT),1)
$(call DEPS,plaintext_network,o)
endif

ifeq ($(USE_GNUTLS),1)
$(call DEPS,gnutls_network,o)
endif

ifeq ($(USE_OPENSSL),1)
$(call DEPS,openssl_network,o)
endif

ifeq ($(USE_CLIENT),1)
$(call DEPS,client_network,o)
endif

ifeq ($(USE_SERVER),1)
$(call DEPS,server_network,o)
endif

ifeq ($(USE_PROTOCOLS),1)
$(call DEPS,protocols,o)
endif

ifeq ($(INSPIRCD2_PROTOCOL),1)
$(call DEPS,protocols/inspircd2,o)
endif

ifeq ($(INSPIRCD3_PROTOCOL),1)
$(call DEPS,protocols/inspircd3,o)
endif

ifeq ($(USE_PSEUDOCLIENTS),1)
$(call DEPS,pseudoclients,o)
endif

ifeq ($(HAXSERV_PSEUDOCLIENT),1)
$(call DEPS,pseudoclients/haxserv,so)
endif

clean:
	$(RM) HaxIRCd *.o *.so protocols/*.o protocols/*.so pseudoclients/*.o pseudoclients/*.so
