# cisco-interface-config

Code snippet that works with Cisco Switch CLI
It checks every interface confguration and if an interface has Spanning-Tree BPDUFilter configured, saves the output to text file

Finally you get a text file with Hostname, IP and list of interfaces that have STP BPDUFilter configured and their respective configuration. This is for every switch you check.

The script may be used to perform any type of operation on switches ports, like "show me ports that have this thing configured"or  "if port has this configured, do this", just needs slight modifications to do this.

Works with any Ethernet ports (Ethernet, FastE, GigE, TenGigE) and supports X, X/Y and X/Y/Z numbering.
