# rollingpcapng

[![Coverity status](https://scan.coverity.com/projects/15505/badge.svg)](https://scan.coverity.com/projects/gteissier-rollingpcapng)

# Rationale

A network blackbox, always on, with two cool features:

* you can generate a snapshot of the rolling buffer of packets
* you can tag packets, specifying a new tag at will, that will tag newly captured packets

# Usage

This tool has been developped when you need to start a lot of tests sequentially, and you need to be sure to collect packets when one of these tests has failed e.g. when performing fuzzing tests :)

In details, this gives:

1. Measure: how many packets will be kept ?
2. Launch `rpcapng`: on which interface ?
3. Mind your business: start your favorite fuzzing tool
4. When starting a new test: tag newly captured packets using `rpcapngctl tag <mytag>`
5. When a test fails: generate a dump of packets using `rpcapngctl dump <pcapng name>`
6. Go to step 4

At the end, you will have a serie of pcapng dumps, containing tagged frames.

## `rpcapng` help

```
# ./rpcapng -h
usage: ./rpcapng -i <interface> [-r rx_ring_size] [-R roll_ring_size] [-c ctl_path] [-Z user]
  -i <interface>: the network interface to capture from
  -r rx_ring_size: the number of slots in the PF_PACKET rx ring used to pull packets from NIC
     DUE TO IMPLEMENTATION, USE ONLY A POWER OF TWO
     defaults to 1024
  -R roll_ring_size: the number of slots in the network blackbox
     defaults to 1024
  -c ctl_path: Unix path of control socket
     defaults to /tmp/rpcapng.ctl
  -Z user: run under user identity, once privileged ops are done
```

## `rpcapngctl` help

```
# ./rpcapngctl -h
usage: ./rpcapngctl [-c ctl_path] mode [arg]
  -c ctl_path: Unix path of control socket
  mode can be:
  tag <tag>: set the comment for newly captured packets
  clear: reset the packet ring buffer
  dump <file>: dump the packet ring buffer to a file
  arg is limited to 254 bytes
```

# Behind the scenes

## Packet capture

It uses what `libpcap` uses internally: a `PF\_PACKET` socket, a memory mapped ring of packets. Additionally, a BPF code is loaded to filter out ssh trafic, given by the filter `not port 22`. Once packets are captured, they are copied from the `PF\_PACKET` ring to the blackbox.

## Always-on blackbox

The ring is implemented with a doubly-linked list, through the use of BSD macros of the `TAILQ_*` family. Once filled, oldest items will be replaced by newest ones.

## Pcap-ng allows to tag packet

# Security features

## Hardened toolchain

It happends at two places:

* compiling: using ```-fPIE -fpie \
  -Wformat -Wformat-security -Werror=format-security \
  -D_FORTIFY_SOURCE=2 \
  -fstack-protector-strong`
* linking: using `$(CC) -fpie -Wl,-z,relro,-z,now,-z,defs`

## Privilege drop

Only a few operations require to have `CAP\_NET\_RAW` capabilities:

* opening a `PF\_PACKET` socket
* changing the running UID to another unprivileged UID

Privileges are dropped after these steps are performed.

As an additional layer of insurance, privileges are dropped, and we request kernel to never grant any privileges to our process or one of its descendants.

## System calls filtering

When starting, the daemon reduces the set of allowed system calls to the strict minimum. The set of allowed system calls is defined in `rpcapng.seccomp√`.
