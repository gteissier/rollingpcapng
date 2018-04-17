<a href="https://scan.coverity.com/projects/gteissier-rollingpcapng">
  <img alt="Coverity Scan Build Status"
       src="https://img.shields.io/coverity/scan/15505.svg"/>
</a>

# rollingpcapng

Capture packets and create pcapng files

# Rationale

`tcpdump` and `dumpcap` allows to capture packets. However, in some cases, it is hard to impossible to capture packets and dump them in a file. The needed disk space would simply be impossible to give.

In order to accomplish this goal, both support to make rolling captures:

* a limit, number of packets, duration of capture or size of the capture, allows to trig a roll
* a number of rolls can be kept
* once reached the threshold, the oldest roll gets destroyed

# 

# 

# 
