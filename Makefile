# Makefile for HaxServ
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

INCLUDEFLAGS =

CFLAGS += $(INCLUDEFLAGS) -D_REENTRANT -ggdb3 -Wall -Wextra -Wsign-conversion -Wno-unused-parameter -Wno-implicit-fallthrough -std=gnu99

LDFLAGS = -lpthread

.makeopts:
	> .makeopts

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

ifneq ($(SAFE_STACK),)
ifneq ($(SAFE_STACK),$(LAST_SAFE_STACK))
rebuild = 1
endif
else
SAFE_STACK = $(LAST_SAFE_STACK)
endif

ifneq ($(CFLAGS),)
ifneq ($(CFLAGS),$(LAST_CFLAGS))
rebuild = 1
endif
else
CFLAGS = $(LAST_CFLAGS)
endif

ifneq ($(CC),)
ifneq ($(CC),$(LAST_CC))
rebuild = 1
endif
else
CC = $(LAST_CC)
endif

ifeq ($(rebuild),1)
$(shell printf '%s\n' 'LAST_PLAINTEXT_CLIENT = $(PLAINTEXT_CLIENT)' > .makeopts)
$(shell printf '%s\n' 'LAST_PLAINTEXT_SERVER = $(PLAINTEXT_SERVER)' >> .makeopts)
$(shell printf '%s\n' 'LAST_GNUTLS_CLIENT = $(GNUTLS_CLIENT)' >> .makeopts)
$(shell printf '%s\n' 'LAST_GNUTLS_SERVER = $(GNUTLS_SERVER)' >> .makeopts)
$(shell printf '%s\n' 'LAST_OPENSSL_CLIENT = $(OPENSSL_CLIENT)' >> .makeopts)
$(shell printf '%s\n' 'LAST_OPENSSL_SERVER = $(OPENSSL_SERVER)' >> .makeopts)
$(shell printf '%s\n' 'LAST_INSPIRCD2_PROTOCOL = $(INSPIRCD2_PROTOCOL)' >> .makeopts)
$(shell printf '%s\n' 'LAST_SAFE_STACK = $(SAFE_STACK)' >> .makeopts)
$(shell printf '%s\n' 'LAST_CFLAGS = $(CFLAGS)' >> .makeopts)
$(shell printf '%s\n' 'LAST_CC = $(CC)' >> .makeopts)
endif

USE_PLAINTEXT = 0
USE_CLIENT = 0
USE_GNUTLS = 0
USE_SERVER = 0

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


OFILES = config.o general_network.o haxstring_utils.o main.o protocols.o table.o

ifeq ($(USE_CLIENT),1)
OFILES += client_network.o
CFLAGS += -DUSE_CLIENT
endif

ifeq ($(USE_SERVER),1)
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

ifeq ($(SAFE_STACK),1)
CFLAGS += -fstack-check
endif



ifeq ($(INSPIRCD2_PROTOCOL),1)
ifneq ($(USE_SERVER),1)
$(error You must have some form of server transport layer enabled if you hope to use the inspircd2 protocol)
endif
OFILES += protocols/inspircd2.o
CFLAGS += -DUSE_INSPIRCD2_PROTOCOL
endif


DEPS = $(shell $(CC) $(CFLAGS) -M -MT $(1).o $(1).c | sed -z 's/\\\n //g') .makeopts Makefile


.PHONY: all clean
all: haxserv

haxserv: $(OFILES) .makeopts Makefile
	$(CC) $(OFILES) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(call DEPS,config)

$(call DEPS,general_network)

$(call DEPS,haxstring_utils)

$(call DEPS,main)

$(call DEPS,protocols)

$(call DEPS,table)

ifeq ($(USE_PLAINTEXT),1)
$(call DEPS,plaintext_network)
endif

ifeq ($(USE_GNUTLS),1)
$(call DEPS,gnutls_network)
endif

ifeq ($(USE_OPENSSL),1)
$(call DEPS,openssl_network)
endif

ifeq ($(USE_CLIENT),1)
$(call DEPS,client_network)
endif

ifeq ($(USE_SERVER),1)
$(call DEPS,server_network)
endif

ifeq ($(INSPIRCD2_PROTOCOL),1)
$(call DEPS,protocols/inspircd2)
endif

clean:
	$(RM) -r haxserv *.o protocols/*.o
