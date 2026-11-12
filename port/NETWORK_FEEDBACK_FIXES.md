# LAN address validation

A CIDR-list LAN configuration such as `192.168.1.1/24` has no separate visible
netmask field. LuCI previously accepted a bare replacement address through
`ipmask4`. With no UCI netmask, netifd installs it as `/32`, losing the connected
subnet route and preventing ordinary LAN clients from reaching the router.

Patch115 requires explicit CIDR or dotted-mask notation in list mode, including
when switching from the traditional address/netmask form. The traditional form
and explicit `/32` addresses remain supported. Address-list additions, removals
and deletion now trigger the existing connectivity warning. A separate template
cache suffix prevents clients retaining old JavaScript without depending on the
other resource-version patches' suffix.

`test_lan_address_ui.py` executes the actual LuCI validation compiler and types,
static protocol form methods, and connectivity-warning code. It applies the
entire LuCI patch series twice. `--before` reproduces the bare-address bug.
The isolated network experiment used netifd/rpcd/uhttpd binaries identical to the
running device: explicit `/24` changes retained ping and HTTP access, bare IP
installed `/32` and lost both, restoring `/24` recovered both. The rpcd timeout
restored the original UCI address. The fixture manually dispatched network reload;
it did not exercise procd, DHCP renewal, a full browser apply, or the physical NI.

2.5G NI4 already has FE registration, ingress admission and egress mapping.
There is no evidence-based driver change for that port in this patch. The blue
`lan1` has no cable carrier in the captured device, so physical FE forwarding
and sustained 2.5G throughput remain unverified.
