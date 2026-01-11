# TopoDrawer IOS-like CLI Test Suite (Simulator-Compatible)

This suite is **strictly limited** to commands currently simulated by the engine and allowed by the PDF-derived authority gate.

Notes:
- `show` / `ping` / `traceroute` are EXEC-only. In config modes, use `do ...`.
- Interfaces are case-sensitive in output. Use IOS-style shortnames: `int g0/0`, `int gi0/0`, `int f0/1`.
- `no shut` is supported (normalizes to `no shutdown`).

---

## 0) CLI Grammar Sanity (any device)

Paste:

```text
en
conf t
do sh ip int brief
exit
sh ip int brief
```

Expected:
- No `% Command not supported in this simulator.` for the above.

---

## 1) L3 Basics + Static Routing (R1 ↔ R2)

Topology:
- Two routers R1 and R2 connected by a single link.

### R1

```text
en
conf t
int g0/0
ip address 10.0.0.1 255.255.255.252
no shut
end
sh ip int brief
```

### R2

```text
en
conf t
int g0/0
ip address 10.0.0.2 255.255.255.252
no shut
end
sh ip int brief
```

### Verify

On R1:

```text
ping 10.0.0.2
traceroute 10.0.0.2
sh ip route
```

---

## 2) Switch VLAN Access + MAC Learning (R1 — SW1 — R2)

Topology:
- R1 connected to SW1 port 1
- R2 connected to SW1 port 2

### SW1 (VLAN 10 access ports)

```text
en
conf t
vlan 10
name USERS
exit

int f0/1
switchport mode access
switchport access vlan 10
no shut
exit

int f0/2
switchport mode access
switchport access vlan 10
no shut
end

sh vlan brief
sh spanning-tree
```

### R1 + R2 (treat router interfaces as access VLAN 10 in this simulator)

On R1:

```text
en
conf t
int g0/0
switchport mode access
switchport access vlan 10
ip address 192.168.10.1 255.255.255.0
no shut
end
```

On R2:

```text
en
conf t
int g0/0
switchport mode access
switchport access vlan 10
ip address 192.168.10.2 255.255.255.0
no shut
end
```

### Verify + MAC learning

On R1:

```text
ping 192.168.10.2
```

On SW1:

```text
sh mac address-table
```

Expected:
- `show mac address-table` contains learned `DYNAMIC` entries after the ping.

---

## 3) Trunk Allowed VLANs (two-switch trunk)

Topology:
- SW1 connected to SW2 via a trunk link.

### SW1

```text
en
conf t
vlan 10
name USERS
exit

int f0/24
switchport mode trunk
switchport trunk allowed vlan 10
no shut
end

sh interfaces trunk
```

### SW2

```text
en
conf t
vlan 10
name USERS
exit

int f0/24
switchport mode trunk
switchport trunk allowed vlan 10
no shut
end

sh interfaces trunk
```

---

## 4) OSPFv2 (single-area, basic)

Topology:
- R1 ↔ R2 directly connected.

### R1

```text
en
conf t
int g0/0
ip address 10.0.0.1 255.255.255.252
no shut
exit

router ospf 1
network 10.0.0.0 0.0.0.3 area 0
end

sh ip ospf neighbor
sh ip route
sh ip protocols
```

### R2

```text
en
conf t
int g0/0
ip address 10.0.0.2 255.255.255.252
no shut
exit

router ospf 1
network 10.0.0.0 0.0.0.3 area 0
end

sh ip ospf neighbor
sh ip route
```

---

## 5) ACL (ICMP any/any only; counters)

Topology:
- R1 ↔ R2 directly connected.

### R1 (apply inbound ACL on interface)

```text
en
conf t
int g0/0
ip address 10.0.0.1 255.255.255.252
no shut
exit

ip access-list extended BLOCK_ICMP
deny icmp any any
permit ip any any
end

conf t
int g0/0
ip access-group BLOCK_ICMP in
end

sh access-lists
```

### R2

```text
en
conf t
int g0/0
ip address 10.0.0.2 255.255.255.252
no shut
end
```

### Verify

On R2:

```text
ping 10.0.0.1
```

Expected:
- Ping is blocked with ACL-prohibited message.
- `show access-lists` on R1 increments hit counters.

---

## 6) EtherChannel Summary (logical grouping only)

Topology:
- SW1 and SW2 connected with two parallel links (2 physical links between the same switches).

On SW1 (repeat with the two member interfaces):

```text
en
conf t
int f0/1
channel-group 1 mode active
no shut
exit

int f0/2
channel-group 1 mode active
no shut
end

sh etherchannel summary
```

On SW2 (match the same member ports):

```text
en
conf t
int f0/1
channel-group 1 mode active
no shut
exit

int f0/2
channel-group 1 mode active
no shut
end

sh etherchannel summary
```
