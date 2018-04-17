# rollingpcapng

Capture packets and create pcapng files

# Rationale

`tcpdump` and `dumpcap` allows to capture packets. However, in some cases, it is hard to impossible to capture packets and dump them in a file. The needed disk space would simply be impossible to give.

In order to accomplish this goal, both support to make rolling captures:

* a limit, number of packets, duration of capture or size of the capture, allows to trig a roll
* a number of rolls can be kept
* once reached, the oldest roll gets destroyed

