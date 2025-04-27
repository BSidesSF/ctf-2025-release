# Toothless

The idea behind the challenge is to appear daunting at first but be rather
trivial to solve.

When you explore the PCAP file, you'll notice a lot of repeated ICMP requests
and responses between the same IP addresses. 
However, only one ICMP request is missing a response. This packet contains a
base64 string in its data.
If you decode the base64 string, you'll have the flag. 
