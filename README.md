# rollingpcapng

[![Coverity status](https://scan.coverity.com/projects/15505/badge.svg)](https://scan.coverity.com/projects/gteissier-rollingpcapng)

# Rationale

A network blackbox, always on, with two cool features:

* you can generate a snapshot of the rolling buffer of packets
* you can tag packets, specifying a new tag at will. This tag will be visible in the snapshot.

# Usage

This tool has been developped to help when you need to start a lot of tests sequentially, and you need to be sure to collect packets when one of these tests has failed e.g. when performing fuzzing tests :)

In details, this gives:

1. Measure: how many packets will be kept ?
2. Launch `rpcapng`: on which interface ?
3. Mind your business: start your favorite fuzzing tool
4. When starting a new test: tag newly captured packets using `rpcapngctl tag <mytag>`
5. When a test fails: generate a dump of packets using `rpcapngctl dump <pcapng name>`
6. Go to step 4

At the end, you will have a set of pcapng dumps, containing tagged frames.

## Typical use of `rpcapng`

At least, you shall give the interface on which to capture, and the user under which capture will run:

```
./rpcapng -i ens3 -Z rolling
```

You may tune other parameters, such as:

* the capacity of the `PF_PACKET` ring buffer, using `-r` option. Note that this option shall be a power of two
* the capacity of the rolling ring buffer, using `-R` option.

The full help is given below:

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

# Behind the scenes

## Packet capture

It uses what `libpcap` uses internally: a `PF_PACKET` socket, and a memory mapped ring of packets. Additionally, a BPF code is loaded to filter out ssh trafic, given by the filter `not port 22`, translated to BPF bytecode. Once packets are captured, they are copied from the `PF_PACKET` ring to the blackbox. While we could have used only one ring buffer to store the packets, the problem is that the kernel will not reuse a busy slot, but rather drop newly captured frames. The behaviour is not what we want, hence we have implemented a second ring buffer to support it.

If you want to change the BPF code used to filter traffic, take a look at `daemon.c`, and find the line `static struct sock_filter bpf[] = {`. The content of this array is given by `tcpdump -dd "not port 22"`, to filter out ssh trafic. You can change the content of this array and recompile `rpcapng`.

## Always-on blackbox

The second ring buffer is implemented with a doubly-linked list, through the use of BSD macros of the `TAILQ_*` family. Once filled, oldest items will be replaced by newest ones. The associated memory is allocated at startup and reused.

## Pcap-ng allows to tag packet

Packets stored in the ring buffer are associated with the current tag at the time of capture. At a given time, the ring buffer contains packets which are tagged with different values. Reference counting is used to track use of tags, and free the associated memory when packets tagged with this value have been overwritten by more recent entries.

# Security features

## Hardened toolchain

* compile time: using

```
-fPIE -fpie \
  -Wformat -Wformat-security -Werror=format-security \
  -D_FORTIFY_SOURCE=2 \
  -fstack-protector-strong
```

* link time: using `$(CC) -fpie -Wl,-z,relro,-z,now,-z,defs`

## Privilege drop

Only a few operations require to have `CAP_NET_RAW` capabilities:

* opening a `PF_PACKET` socket
* changing the running UID to another unprivileged UID

Privileges are dropped after these steps are performed.

As an additional layer of insurance, we request kernel to never grant any privileges to our process or one of its descendants.

## System calls filtering

When starting, the daemon reduces the set of allowed system calls to the strict minimum. The set of allowed system calls is defined in `rpcapng.seccomp`.

Please note that the system call list currently targets x86-64 ABI, and glibc evolution may bring new system calls under the seccomp filter. If a new system call is not whitelisted, `rpcapng` will be killed with `Bad system call`. Take a look at `dmesg` output will give you the culprit, namely its system call number, which then can be added to `rpcapng.seccomp` before recompiling the binary.
