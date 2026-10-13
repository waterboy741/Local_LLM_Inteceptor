# Synthetic M4 ARP frames

These hexadecimal Ethernet/ARP frames are invented offline test data, with
documentation-only IPv4 addresses and locally administered MAC addresses.
They are not captures from any network.

`arp-request.hex` represents a broadcast request from 192.0.2.10 asking for
192.0.2.30. `arp-reply.hex` represents a synthetic reply to that client claiming
192.0.2.30 at MAC 02:00:00:00:00:20. The latter demonstrates the proposed ARP
mapping in data only; it is never injected by these tests.

Each frame contains the 14-byte Ethernet header and 28-byte Ethernet/IPv4 ARP
message, without Ethernet padding or frame check sequence. Tests add padding,
truncate at each byte boundary, and alter header fields to verify bounds and
unsupported-type handling.
