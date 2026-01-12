import unittest

from sim.core import TopologySim
from sim.cli import CLIEngine
from sim.pc_cli import PCCLIEngine


class TestAdvanced(unittest.TestCase):
    def test_etherchannel_behaves_like_single_stp_edge(self):
        """Max-ish L2: EtherChannel + trunks + STP loop + host traffic.

        Expectation:
        - Two parallel links bundled into the same channel-group should not have a
          member port blocked by STP just because there are parallel physical links.
        - In a triangle, STP should still block some *other* edge to break the loop.
        - End-host ping in VLAN 10 should succeed.
        """

        sim = TopologySim()
        for uid in ("SW1", "SW2", "SW3"):
            sim.add_device(uid, "switch")
        sim.add_device("PC2", "host")
        sim.add_device("PC3", "host")

        # SW1 <-> SW2: two parallel links (bundle into Po1)
        sw1_p1 = sim.allocate_interface_name("SW1")
        sw2_p1 = sim.allocate_interface_name("SW2")
        sim.connect("SW1", sw1_p1, "SW2", sw2_p1)

        sw1_p2 = sim.allocate_interface_name("SW1")
        sw2_p2 = sim.allocate_interface_name("SW2")
        sim.connect("SW1", sw1_p2, "SW2", sw2_p2)

        # SW1 <-> SW3: single link
        sw1_s3 = sim.allocate_interface_name("SW1")
        sw3_s1 = sim.allocate_interface_name("SW3")
        sim.connect("SW1", sw1_s3, "SW3", sw3_s1)

        # SW2 <-> SW3: single link (completes loop)
        sw2_s3 = sim.allocate_interface_name("SW2")
        sw3_s2 = sim.allocate_interface_name("SW3")
        sim.connect("SW2", sw2_s3, "SW3", sw3_s2)

        # PCs on SW2 and SW3
        sw2_pc = sim.allocate_interface_name("SW2")
        sw3_pc = sim.allocate_interface_name("SW3")
        sim.connect("SW2", sw2_pc, "PC2", "Eth0")
        sim.connect("SW3", sw3_pc, "PC3", "Eth0")

        cli = CLIEngine(sim)

        def cfg_access(sw: str, ifname: str, vlan: int):
            c = cli.new_context(sw)
            cli.execute(c, "enable")
            cli.execute(c, "conf t")
            cli.execute(c, f"interface {ifname}")
            cli.execute(c, "switchport mode access")
            cli.execute(c, f"switchport access vlan {vlan}")
            cli.execute(c, "no shutdown")
            cli.execute(c, "end")

        def cfg_trunk(sw: str, ifname: str, allowed: str):
            c = cli.new_context(sw)
            cli.execute(c, "enable")
            cli.execute(c, "conf t")
            cli.execute(c, f"interface {ifname}")
            cli.execute(c, "switchport mode trunk")
            cli.execute(c, f"switchport trunk allowed vlan {allowed}")
            cli.execute(c, "no shutdown")
            cli.execute(c, "end")

        def cfg_channel(sw: str, ifname: str, gid: int):
            c = cli.new_context(sw)
            cli.execute(c, "enable")
            cli.execute(c, "conf t")
            cli.execute(c, f"interface {ifname}")
            cli.execute(c, f"channel-group {gid} mode on")
            cli.execute(c, "end")

        # VLAN 10 everywhere on access ports
        cfg_access("SW2", sw2_pc, 10)
        cfg_access("SW3", sw3_pc, 10)

        # Trunks
        for sw, ifn in (
            ("SW1", sw1_p1),
            ("SW1", sw1_p2),
            ("SW2", sw2_p1),
            ("SW2", sw2_p2),
            ("SW1", sw1_s3),
            ("SW3", sw3_s1),
            ("SW2", sw2_s3),
            ("SW3", sw3_s2),
        ):
            cfg_trunk(sw, ifn, "10")

        # Bundle the parallel SW1<->SW2 links
        for sw, ifn in (("SW1", sw1_p1), ("SW1", sw1_p2), ("SW2", sw2_p1), ("SW2", sw2_p2)):
            cfg_channel(sw, ifn, 1)

        # EtherChannel should show up.
        sw2_ctx = cli.new_context("SW2")
        out = cli.execute(sw2_ctx, "show etherchannel summary").output
        self.assertIn("Po1", out)
        self.assertIn(sw2_p1, out)
        self.assertIn(sw2_p2, out)

        # STP should not block either EtherChannel member due to parallelism.
        stp2 = cli.execute(sw2_ctx, "show spanning-tree").output
        self.assertNotIn(f"{sw2_p1:<19} Altn", stp2)
        self.assertNotIn(f"{sw2_p2:<19} Altn", stp2)

        # End-host traffic should succeed in VLAN 10.
        pccli = PCCLIEngine(sim)
        pc2 = pccli.new_context("PC2")
        pc3 = pccli.new_context("PC3")
        pccli.execute(pc2, "ip 10.10.10.2 255.255.255.0")
        pccli.execute(pc3, "ip 10.10.10.3 255.255.255.0")
        ping = pccli.execute(pc2, "ping 10.10.10.3").output
        self.assertIn("Success rate", ping)

    def test_ospf_chain_with_acl_blocks_then_allows(self):
        """Max-ish L3: OSPF across a chain plus ACL enforcement."""

        sim = TopologySim()
        for uid, kind in (
            ("R1", "router"),
            ("R2", "router"),
            ("R3", "router"),
            ("PC1", "host"),
            ("PC3", "host"),
        ):
            sim.add_device(uid, kind)

        # R1 -- R2
        r1_r2 = sim.allocate_interface_name("R1")
        r2_r1 = sim.allocate_interface_name("R2")
        sim.connect("R1", r1_r2, "R2", r2_r1)

        # R2 -- R3
        r2_r3 = sim.allocate_interface_name("R2")
        r3_r2 = sim.allocate_interface_name("R3")
        sim.connect("R2", r2_r3, "R3", r3_r2)

        # Edge hosts
        r1_pc = sim.allocate_interface_name("R1")
        r3_pc = sim.allocate_interface_name("R3")
        sim.connect("R1", r1_pc, "PC1", "Eth0")
        sim.connect("R3", r3_pc, "PC3", "Eth0")

        cli = CLIEngine(sim)
        r1 = cli.new_context("R1")
        r2 = cli.new_context("R2")
        r3 = cli.new_context("R3")

        def cfg_if(ctx, ifname: str, ip: str, mask: str):
            cli.execute(ctx, "enable")
            cli.execute(ctx, "conf t")
            cli.execute(ctx, f"interface {ifname}")
            cli.execute(ctx, f"ip address {ip} {mask}")
            cli.execute(ctx, "no shutdown")
            cli.execute(ctx, "end")

        cfg_if(r1, r1_r2, "10.0.12.1", "255.255.255.252")
        cfg_if(r2, r2_r1, "10.0.12.2", "255.255.255.252")
        cfg_if(r2, r2_r3, "10.0.23.1", "255.255.255.252")
        cfg_if(r3, r3_r2, "10.0.23.2", "255.255.255.252")
        cfg_if(r1, r1_pc, "192.168.1.1", "255.255.255.0")
        cfg_if(r3, r3_pc, "192.168.3.1", "255.255.255.0")

        # OSPF
        for ctx, nets in (
            (r1, ["10.0.12.0 0.0.0.3", "192.168.1.0 0.0.0.255"]),
            (r2, ["10.0.12.0 0.0.0.3", "10.0.23.0 0.0.0.3"]),
            (r3, ["10.0.23.0 0.0.0.3", "192.168.3.0 0.0.0.255"]),
        ):
            cli.execute(ctx, "enable")
            cli.execute(ctx, "conf t")
            cli.execute(ctx, "router ospf 1")
            for n in nets:
                cli.execute(ctx, f"network {n} area 0")
            cli.execute(ctx, "end")

        pccli = PCCLIEngine(sim)
        pc1 = pccli.new_context("PC1")
        pc3 = pccli.new_context("PC3")
        pccli.execute(pc1, "ip 192.168.1.10 255.255.255.0 192.168.1.1")
        pccli.execute(pc3, "ip 192.168.3.10 255.255.255.0 192.168.3.1")

        ok = pccli.execute(pc1, "ping 192.168.3.10").output
        self.assertIn("Success rate", ok)

        # Apply an ACL on R2 that blocks ICMP.
        cli.execute(r2, "enable")
        cli.execute(r2, "conf t")
        cli.execute(r2, "ip access-list extended BLOCKICMP")
        cli.execute(r2, "deny icmp any any")
        cli.execute(r2, "permit ip any any")
        cli.execute(r2, "exit")
        cli.execute(r2, f"interface {r2_r3}")
        cli.execute(r2, "ip access-group BLOCKICMP out")
        cli.execute(r2, "end")

        blocked = pccli.execute(pc1, "ping 192.168.3.10").output
        self.assertIn("prohibited", blocked.lower())

        # Remove the ACL and confirm ping succeeds again.
        cli.execute(r2, "enable")
        cli.execute(r2, "conf t")
        cli.execute(r2, f"interface {r2_r3}")
        cli.execute(r2, "no ip access-group out")
        cli.execute(r2, "end")

        ok2 = pccli.execute(pc1, "ping 192.168.3.10").output
        self.assertIn("Success rate", ok2)


if __name__ == "__main__":
    unittest.main()
