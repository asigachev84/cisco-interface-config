# cisco-interface-config

Code snippet that works with Cisco Switch CLI
It checks every interface confguration and if an interface has Spanning-Tree BPDUFilter configured, saves the output to text file

Finally you get a text file that has output like this:

=================================
SWITCH: SW-Floor-15
IP: 192.168.1.15
=================================
interface FastEthernet0/1
 switchport access vlan 300
 switchport mode access
 no cdp enable
 spanning-tree portfast
 spanning-tree bpdufilter enable
end

interface FastEthernet0/2
 switchport access vlan 300
 switchport mode access
 no cdp enable
 spanning-tree portfast
 spanning-tree bpdufilter enable
end

interface FastEthernet0/3
 switchport access vlan 127
 switchport mode access
 storm-control broadcast level 10.00
 storm-control multicast level 10.00
 storm-control unicast level 10.00
 storm-control action trap
 no cdp enable
 spanning-tree bpdufilter enable
end

interface FastEthernet0/4
 switchport access vlan 127
 switchport mode access
 storm-control broadcast level 10.00
 storm-control multicast level 10.00
 storm-control unicast level 10.00
 storm-control action trap
 no cdp enable
 spanning-tree bpdufilter enable
end

===========================================

The script may be used to do any tipe of operation on switches ports. 
Works with any Ethernet ports (Ethernet, FastE, GigE, TenGigE) and supports X, X/Y and X/Y/Z numbering.
