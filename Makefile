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
	> .makeopts
	printf '%s\n' 'LAST_CLIENT = $(CLIENT)' >> .makeopts
	printf '%s\n' 'LAST_SERVER = $(SERVER)' >> .makeopts
	printf '%s\n' 'LAST_PLAINTEXT_NETWORK = $(PLAINTEXT_NETWORK)' >> .makeopts
	printf '%s\n' 'LAST_GNUTLS_NETWORK = $(GNUTLS_NETWORK)' >> .makeopts
	printf '%s\n' 'LAST_OPENSSL_NETWORK = $(OPENSSL_NETWORK)' >> .makeopts
	printf '%s\n' 'LAST_PLAINTEXT_BUFFERED_NETWORK = $(PLAINTEXT_BUFFERED_NETWORK)' >> .makeopts
	printf '%s\n' 'LAST_GNUTLS_BUFFERED_NETWORK = $(GNUTLS_BUFFERED_NETWORK)' >> .makeopts
	printf '%s\n' 'LAST_OPENSSL_BUFFERED_NETWORK = $(OPENSSL_BUFFERED_NETWORK)' >> .makeopts
	printf '%s\n' 'LAST_INSPIRCD2_PROTOCOL = $(INSPIRCD2_PROTOCOL)' >> .makeopts
	printf '%s\n' 'LAST_INSPIRCD3_PROTOCOL = $(INSPIRCD3_PROTOCOL)' >> .makeopts
	printf '%s\n' 'LAST_INSPIRCD4_PROTOCOL = $(INSPIRCD4_PROTOCOL)' >> .makeopts
	printf '%s\n' 'LAST_HAXSERV_PSEUDOCLIENT = $(HAXSERV_PSEUDOCLIENT)' >> .makeopts
	printf '%s\n' 'LAST_SERVICES_PSEUDOCLIENT = $(SERVICES_PSEUDOCLIENT)' >> .makeopts
	printf '%s\n' 'LAST_SAFE_STACK = $(SAFE_STACK)' >> .makeopts
	printf '%s\n' 'LAST_FUTEX = $(FUTEX)' >> .makeopts
	printf '%s\n' 'LAST_MISERABLE_SPINLOCKS = $(MISERABLE_SPINLOCKS)' >> .makeopts
	printf '%s\n' 'LAST_ATOMICS = $(ATOMICS)' >> .makeopts
	printf '%s\n' 'LAST_IPv4 = $(IPv4)' >> .makeopts
	printf '%s\n' 'LAST_IPv6 = $(IPv6)' >> .makeopts
	printf '%s\n' 'LAST_CFLAGS = $(ORIGINAL_CFLAGS)' >> .makeopts
	printf '%s\n' 'LAST_CC = $(CC)' >> .makeopts

$(shell [ -e .makeopts ] || > .makeopts)

include .makeopts

rebuild = 0

# tabs not allowed :(
ifneq ($(CLIENT),)
ifneq ($(CLIENT),$(LAST_CLIENT))
rebuild = 1
endif
else
CLIENT := $(LAST_CLIENT)
endif

ifneq ($(SERVER),)
ifneq ($(SERVER),$(LAST_SERVER))
rebuild = 1
endif
else
SERVER := $(LAST_SERVER)
endif

ifneq ($(PLAINTEXT_NETWORK),)
ifneq ($(PLAINTEXT_NETWORK),$(LAST_PLAINTEXT_NETWORK))
rebuild = 1
endif
else
PLAINTEXT_NETWORK := $(LAST_PLAINTEXT_NETWORK)
endif

ifneq ($(GNUTLS_NETWORK),)
ifneq ($(GNUTLS_NETWORK),$(LAST_GNUTLS_NETWORK))
rebuild = 1
endif
else
GNUTLS_NETWORK := $(LAST_GNUTLS_NETWORK)
endif

ifneq ($(OPENSSL_NETWORK),)
ifneq ($(OPENSSL_NETWORK),$(LAST_OPENSSL_NETWORK))
rebuild = 1
endif
else
OPENSSL_NETWORK := $(LAST_OPENSSL_NETWORK)
endif

ifneq ($(PLAINTEXT_BUFFERED_NETWORK),)
ifneq ($(PLAINTEXT_BUFFERED_NETWORK),$(LAST_PLAINTEXT_BUFFERED_NETWORK))
rebuild = 1
endif
else
PLAINTEXT_BUFFERED_NETWORK := $(LAST_PLAINTEXT_BUFFERED_NETWORK)
endif

ifneq ($(GNUTLS_BUFFERED_NETWORK),)
ifneq ($(GNUTLS_BUFFERED_NETWORK),$(LAST_GNUTLS_BUFFERED_NETWORK))
rebuild = 1
endif
else
GNUTLS_BUFFERED_NETWORK := $(LAST_GNUTLS_BUFFERED_NETWORK)
endif

ifneq ($(OPENSSL_BUFFERED_NETWORK),)
ifneq ($(OPENSSL_BUFFERED_NETWORK),$(LAST_OPENSSL_BUFFERED_NETWORK))
rebuild = 1
endif
else
OPENSSL_BUFFERED_NETWORK := $(LAST_OPENSSL_BUFFERED_NETWORK)
endif

ifneq ($(INSPIRCD2_PROTOCOL),)
ifneq ($(INSPIRCD2_PROTOCOL),$(LAST_INSPIRCD2_PROTOCOL))
rebuild = 1
endif
else
INSPIRCD2_PROTOCOL := $(LAST_INSPIRCD2_PROTOCOL)
endif

ifneq ($(INSPIRCD3_PROTOCOL),)
ifneq ($(INSPIRCD3_PROTOCOL),$(LAST_INSPIRCD3_PROTOCOL))
rebuild = 1
endif
else
INSPIRCD3_PROTOCOL := $(LAST_INSPIRCD3_PROTOCOL)
endif

ifneq ($(INSPIRCD4_PROTOCOL),)
ifneq ($(INSPIRCD4_PROTOCOL),$(LAST_INSPIRCD4_PROTOCOL))
rebuild = 1
endif
else
INSPIRCD4_PROTOCOL := $(LAST_INSPIRCD4_PROTOCOL)
endif

ifneq ($(HAXSERV_PSEUDOCLIENT),)
ifneq ($(HAXSERV_PSEUDOCLIENT),$(LAST_HAXSERV_PSEUDOCLIENT))
rebuild = 1
endif
else
HAXSERV_PSEUDOCLIENT := $(LAST_HAXSERV_PSEUDOCLIENT)
endif

ifneq ($(SERVICES_PSEUDOCLIENT),)
ifneq ($(SERVICES_PSEUDOCLIENT),$(LAST_SERVICES_PSEUDOCLIENT))
rebuild = 1
endif
else
SERVICES_PSEUDOCLIENT := $(LAST_SERVICES_PSEUDOCLIENT)
endif

ifneq ($(SAFE_STACK),)
ifneq ($(SAFE_STACK),$(LAST_SAFE_STACK))
rebuild = 1
endif
else
SAFE_STACK := $(LAST_SAFE_STACK)
endif

ifneq ($(ORIGINAL_CFLAGS),)
ifneq ($(ORIGINAL_CFLAGS),$(LAST_CFLAGS))
rebuild = 1
endif
else
ORIGINAL_CFLAGS := $(LAST_CFLAGS)
CFLAGS := $(LAST_CFLAGS)
endif

ifneq ($(CC),)
ifneq ($(CC),$(LAST_CC))
rebuild = 1
endif
else
CC := $(LAST_CC)
endif

ifneq ($(FUTEX),)
ifneq ($(FUTEX),$(LAST_FUTEX))
rebuild = 1
endif
else
FUTEX := $(LAST_FUTEX)
endif

ifneq ($(MISERABLE_SPINLOCKS),)
ifneq ($(MISERABLE_SPINLOCKS),$(LAST_MISERABLE_SPINLOCKS))
rebuild = 1
endif
else
MISERABLE_SPINLOCKS := $(LAST_MISERABLE_SPINLOCKS)
endif

ifneq ($(ATOMICS),)
ifneq ($(ATOMICS),$(LAST_ATOMICS))
rebuild = 1
endif
else
ATOMICS := $(LAST_ATOMICS)
endif

ifneq ($(IPv4),)
ifneq ($(IPv4),$(LAST_IPv4))
rebuild = 1
endif
else
IPv4 := $(LAST_IPv4)
endif

ifneq ($(IPv6),)
ifneq ($(IPv6),$(LAST_IPv6))
rebuild = 1
endif
else
IPv6 := $(LAST_IPv6)
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

USE_IRCD := 0
ifeq ($(CLIENT),1)
OFILES += client_network.o
CFLAGS += -DUSE_CLIENT
USE_IRCD := 1
USE_CLIENT := 1
endif

ifeq ($(SERVER),1)
OFILES += server_network.o
CFLAGS += -DUSE_SERVER
USE_IRCD := 1
USE_SERVER := 1
endif

ifneq ($(USE_IRCD),1)
$(error Well, you neither want clients nor servers, so... int main(void) {return 0;}, your IRCd is complete.)
endif


USE_NETWORK := 0
ifeq ($(PLAINTEXT_NETWORK),1)
OFILES += networks/plaintext.o
CFLAGS += -DUSE_PLAINTEXT_NETWORK
USE_NETWORK := 1
USE_PLAINTEXT_NETWORK := 1
endif

ifeq ($(GNUTLS_NETWORK),1)
OFILES += networks/gnutls.o
CFLAGS += -DUSE_GNUTLS_NETWORK $(shell pkg-config gnutls --cflags)
LDFLAGS += $(shell pkg-config gnutls --libs)
USE_NETWORK := 1
USE_GNUTLS_NETWORK := 1
endif

ifeq ($(OPENSSL_NETWORK),1)
OFILES += networks/openssl.o
CFLAGS += -DUSE_OPENSSL_NETWORK $(shell pkg-config openssl --cflags)
LDFLAGS += $(shell pkg-config openssl --libs)
USE_NETWORK := 1
USE_OPENSSL_NETWORK := 1
endif

ifeq ($(PLAINTEXT_BUFFERED_NETWORK),1)
OFILES += networks/plaintext_buffered.o
CFLAGS += -DUSE_PLAINTEXT_BUFFERED_NETWORK
USE_NETWORK := 1
USE_PLAINTEXT_BUFFERED_NETWORK := 1
endif

ifeq ($(GNUTLS_BUFFERED_NETWORK),1)
OFILES += networks/gnutls_buffered.o
CFLAGS += -DUSE_GNUTLS_BUFFERED_NETWORK $(shell pkg-config gnutls --cflags)
LDFLAGS += $(shell pkg-config gnutls --libs)
USE_NETWORK := 1
USE_GNUTLS_BUFFERED_NETWORK := 1
endif

ifeq ($(OPENSSL_BUFFERED_NETWORK),1)
OFILES += networks/openssl_buffered.o
CFLAGS += -DUSE_OPENSSL_BUFFERED_NETWORK $(shell pkg-config openssl --cflags)
LDFLAGS += $(shell pkg-config openssl --libs)
USE_NETWORK := 1
USE_OPENSSL_BUFFERED_NETWORK := 1
endif

ifneq ($(USE_NETWORK),1)
$(error How would you like to communicate with these clients or servers?)
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

ifeq ($(INSPIRCD4_PROTOCOL),1)
OFILES += protocols/inspircd4.o
CFLAGS += -DUSE_INSPIRCD4_PROTOCOL
USE_PROTOCOLS = 1
endif

ifeq ($(USE_SERVER),1)
ifneq ($(USE_PROTOCOLS),1)
$(error You must use some s2s protocol if you want to link servers)
endif
endif



ifeq ($(HAXSERV_PSEUDOCLIENT),1)
SOFILES += pseudoclients/haxserv.so
CFLAGS += -DUSE_HAXSERV_PSEUDOCLIENT
USE_PSEUDOCLIENTS = 1
endif

ifeq ($(SERVICES_PSEUDOCLIENT),1)
SOFILES += pseudoclients/services.so
CFLAGS += -DUSE_SERVICES_PSEUDOCLIENT $(shell pkg-config --cflags lmdb)
LDFLAGS += $(shell pkg-config --libs lmdb)
USE_PSEUDOCLIENTS = 1
endif



ifeq ($(USE_PLAINTEXT_BUFFERED),1)
OFILES += networks/plaintext_buffered.o
CFLAGS += -DUSE_PLAINTEXT_BUFFERED
endif

ifeq ($(USE_GNUTLS_BUFFERED),1)
OFILES += networks/gnutls_buffered.o
CFLAGS += -DUSE_GNUTLS_BUFFERED
endif

ifeq ($(USE_OPENSSL_BUFFERED),1)
OFILES += networks/openssl_buffered.o
CFLAGS += -DUSE_OPENSSL_BUFFERED
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

ifeq ($(MISERABLE_SPINLOCKS),1)
ifeq ($(FUTEX),1)
$(error Miserable spinlocks are only enabled when noy using futexes)
endif
CFLAGS += -DUSE_MISERABLE_SPINLOCKS
endif

ifeq ($(ATOMICS),1)
CFLAGS += -DUSE_ATOMICS
endif



IP_ENABLED := 0

ifeq ($(IPv4),1)
CFLAGS += -DUSE_IPv4
IP_ENABLED := 1
endif

ifeq ($(IPv6),1)
CFLAGS += -DUSE_IPv6
IP_ENABLED := 1
endif

ifneq ($(IP_ENABLED),1)
$(error I don't know how you intend to use TCP/IP without IP)
endif



ifeq ($(SAFE_STACK),1)
CFLAGS += -fstack-check
endif



DEPS = $(shell $(CC) $(CFLAGS) -M -MT $(1).$(2) $(1).c | sed 's_\\$$__') .makeopts Makefile


.PHONY: all clean
all: HaxIRCd $(SOFILES)

HaxIRCd: main.c .makeopts Makefile
	$(CC) main.c -o HaxIRCd

HaxIRCd.so: $(OFILES) .makeopts Makefile
	$(CC) $(OFILES) -shared -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

%.so: %.c
	$(CC) $(CFLAGS) -shared -fPIC $< -o $@ $(LDFLAGS)

$(call DEPS,config,o)

$(call DEPS,general_network,o)

$(call DEPS,haxstring_utils,o)

$(call DEPS,real_main,o)

$(call DEPS,main,o)

$(call DEPS,mutex,o)

$(call DEPS,protocols,o)

$(call DEPS,table,o)

ifeq ($(USE_PLAINTEXT),1)
$(call DEPS,networks/plaintext,o)
endif

ifeq ($(USE_GNUTLS),1)
$(call DEPS,networks/gnutls,o)
endif

ifeq ($(USE_OPENSSL),1)
$(call DEPS,networks/openssl,o)
endif

ifeq ($(USE_PLAINTEXT_BUFFERED),1)
$(call DEPS,networks/plaintext_buffered,o)
endif

ifeq ($(USE_GNUTLS_BUFFERED),1)
$(call DEPS,networks/gnutls_buffered,o)
endif

ifeq ($(USE_OPENSSL_BUFFERED),1)
$(call DEPS,networks/openssl_buffered,o)
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

ifeq ($(INSPIRCD4_PROTOCOL),1)
$(call DEPS,protocols/inspircd4,o)
endif

ifeq ($(USE_PSEUDOCLIENTS),1)
$(call DEPS,pseudoclients,o)
endif

ifeq ($(HAXSERV_PSEUDOCLIENT),1)
$(call DEPS,pseudoclients/haxserv,so)
endif

ifeq ($(SERVICES_PSEUDOCLIENT),1)
$(call DEPS,pseudoclients/services,so)
endif

clean:
	$(RM) HaxIRCd
	for file in `find . -name '*.so'`; do $(RM) $$file; done
	for file in `find . -name '*.o'`; do $(RM) $$file; done
