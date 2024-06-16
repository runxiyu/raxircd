# HaxIRCd, a public domain multi-protocol IRCd with redundant links

**This is a work in progress.**

## Goals

* Could link in a network among multiple traditional protocols from different
  traditional IRCDs.
* Could provide internal services (ChanServ, NickServ, HaxServ) and synchronize
  the services database, handling collisions gracefully.
* Correct, Fast and scalable.
* Modular.
  More extensive runtime module reloading is planned.
* Replace [CoupServ](https://git.andrewyu.org/hax/coupserv.git/about) and
  perhaps [PyLink](https://github.com/PyLink/PyLink) in the distant future.

## Some implementation details(-ish)

* `dlopen(3)` is used to dynamically load `HaxIRCd.so`; this is for RTLD_GLOBAL,
  so we can use the contained symbols for the actual loadable modules.
* All strings that we handle (i.e. not required by external libraries) are
  length-specified, not null-terminated. Null bytes are treated as any other
  character in networking.
* Configuration is just another source file, `config.c`. The header file
  `config.h` defines the configuration options needed.

## Dependencies

* Reasonably modern UNIX-like system with support for POSIX threads.
  We haven't tested on non-Linux systems yet.
* If you want TLS support, GnuTLS, OpenSSL, or LibreSSL.

## Why

* [PyLink](https://github.com/PyLink/PyLink) is used by the
  [rx](https://irc.runxiyu.org) IRC network, but it's unmaintained and we still
  want to use something like it.
* [CoupServ](https://git.andrewyu.org/hax/coupserv.git/about) uses the 1202
  (InspIRCd v2) protocol, which is not supported by InspIRCd v4; more generally,
  we want to make protocols pluggable modules.

## Project links

* Git repo: <https://git.andrewyu.org/hax/haxircd.git>
* IRC channel: [#chat](ircs://irc.runxiyu.org/#chat) on [rx](https://irc.runxiyu.org)
* Task tracker: <https://todo.sr.ht/~runxiyu/haxircd>
* Mailing list: <https://lists.sr.ht/~runxiyu/haxircd>
