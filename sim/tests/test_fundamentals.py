import unittest

from sim.core import TopologySim
from sim.cli import CLIEngine
from sim.pc_cli import PCCLIEngine


class TestFundamentals(unittest.TestCase):
    def test_pc_ping_default_gateway(self):
        sim = TopologySim()
        sim.add_device("R1", "router")
        sim.add_device("PC1", "host")

        r1_if = sim.allocate_interface_name("R1")
        sim.connect("R1", r1_if, "PC1", "Eth0")

        cli = CLIEngine(sim)
        r1 = cli.new_context("R1")
        cli.execute(r1, "enable")
        cli.execute(r1, "conf t")
        cli.execute(r1, f"interface {r1_if}")
        cli.execute(r1, "ip address 192.168.1.1 255.255.255.0")
        cli.execute(r1, "no shutdown")
        cli.execute(r1, "end")

        pccli = PCCLIEngine(sim)
        pc1 = pccli.new_context("PC1")
        pccli.execute(pc1, "ip 192.168.1.10 255.255.255.0 192.168.1.1")

        out = pccli.execute(pc1, "ping 192.168.1.1").output
        self.assertIn("Success rate", out)

    def test_pc_to_pc_via_single_router(self):
        sim = TopologySim()
        sim.add_device("R1", "router")
        sim.add_device("PC1", "host")
        sim.add_device("PC2", "host")

        r1_if1 = sim.allocate_interface_name("R1")
        r1_if2 = sim.allocate_interface_name("R1")
        sim.connect("R1", r1_if1, "PC1", "Eth0")
        sim.connect("R1", r1_if2, "PC2", "Eth0")

        cli = CLIEngine(sim)
        r1 = cli.new_context("R1")
        cli.execute(r1, "enable")
        cli.execute(r1, "conf t")
        cli.execute(r1, f"interface {r1_if1}")
        cli.execute(r1, "ip address 192.168.1.1 255.255.255.0")
        cli.execute(r1, "no shutdown")
        cli.execute(r1, "exit")
        cli.execute(r1, f"interface {r1_if2}")
        cli.execute(r1, "ip address 192.168.2.1 255.255.255.0")
        cli.execute(r1, "no shutdown")
        cli.execute(r1, "end")

        pccli = PCCLIEngine(sim)
        pc1 = pccli.new_context("PC1")
        pc2 = pccli.new_context("PC2")
        pccli.execute(pc1, "ip 192.168.1.10 255.255.255.0 192.168.1.1")
        pccli.execute(pc2, "ip 192.168.2.10 255.255.255.0 192.168.2.1")

        out = pccli.execute(pc1, "ping 192.168.2.10").output
        self.assertIn("Success rate", out)

    def test_static_routing_two_routers_end_hosts(self):
        sim = TopologySim()
        for uid, kind in (
            ("R1", "router"),
            ("R2", "router"),
            ("PC1", "host"),
            ("PC2", "host"),
        ):
            sim.add_device(uid, kind)

        # R1 -- R2
        r1_r2 = sim.allocate_interface_name("R1")
        r2_r1 = sim.allocate_interface_name("R2")
        sim.connect("R1", r1_r2, "R2", r2_r1)

        # Host links
        r1_pc = sim.allocate_interface_name("R1")
        r2_pc = sim.allocate_interface_name("R2")
        sim.connect("R1", r1_pc, "PC1", "Eth0")
        sim.connect("R2", r2_pc, "PC2", "Eth0")

        cli = CLIEngine(sim)
        r1 = cli.new_context("R1")
        r2 = cli.new_context("R2")

        def cfg_if(ctx, ifname: str, ip: str, mask: str):
            cli.execute(ctx, "enable")
            cli.execute(ctx, "conf t")
            cli.execute(ctx, f"interface {ifname}")
            cli.execute(ctx, f"ip address {ip} {mask}")
            cli.execute(ctx, "no shutdown")
            cli.execute(ctx, "end")

        # Transit /30
        cfg_if(r1, r1_r2, "10.0.0.1", "255.255.255.252")
        cfg_if(r2, r2_r1, "10.0.0.2", "255.255.255.252")

        # LANs
        cfg_if(r1, r1_pc, "192.168.1.1", "255.255.255.0")
        cfg_if(r2, r2_pc, "192.168.2.1", "255.255.255.0")

        # Static routes
        cli.execute(r1, "enable")
        cli.execute(r1, "conf t")
        cli.execute(r1, "ip route 192.168.2.0 255.255.255.0 10.0.0.2")
        cli.execute(r1, "end")

        cli.execute(r2, "enable")
        cli.execute(r2, "conf t")
        cli.execute(r2, "ip route 192.168.1.0 255.255.255.0 10.0.0.1")
        cli.execute(r2, "end")

        pccli = PCCLIEngine(sim)
        pc1 = pccli.new_context("PC1")
        pc2 = pccli.new_context("PC2")
        pccli.execute(pc1, "ip 192.168.1.10 255.255.255.0 192.168.1.1")
        pccli.execute(pc2, "ip 192.168.2.10 255.255.255.0 192.168.2.1")

        out = pccli.execute(pc1, "ping 192.168.2.10").output
        self.assertIn("Success rate", out)

    def test_vlan_trunk_allowed_vlans(self):
        """Harder L2: VLAN access ports across a trunk with allowed VLANs.

        Note: this is not full router-on-a-stick (no dot1q subinterfaces), but it
        validates trunk fundamentals that higher-level labs depend on.
        """

        sim = TopologySim()
        sim.add_device("SW1", "switch")
        sim.add_device("SW2", "switch")
        sim.add_device("PC1", "host")
        sim.add_device("PC2", "host")

        # SW1 -- SW2 trunk
        sw1_trk = sim.allocate_interface_name("SW1")
        sw2_trk = sim.allocate_interface_name("SW2")
        sim.connect("SW1", sw1_trk, "SW2", sw2_trk)

        # PCs into access VLAN 10
        sw1_pc = sim.allocate_interface_name("SW1")
        sw2_pc = sim.allocate_interface_name("SW2")
        sim.connect("SW1", sw1_pc, "PC1", "Eth0")
        sim.connect("SW2", sw2_pc, "PC2", "Eth0")

        cli = CLIEngine(sim)
        sw1 = cli.new_context("SW1")
        sw2 = cli.new_context("SW2")

        def cfg_access(ctx, ifname: str, vlan: int):
            cli.execute(ctx, "enable")
            cli.execute(ctx, "conf t")
            cli.execute(ctx, f"interface {ifname}")
            cli.execute(ctx, "switchport mode access")
            cli.execute(ctx, f"switchport access vlan {vlan}")
            cli.execute(ctx, "no shutdown")
            cli.execute(ctx, "end")

        def cfg_trunk(ctx, ifname: str, allowed: str):
            cli.execute(ctx, "enable")
            cli.execute(ctx, "conf t")
            cli.execute(ctx, f"interface {ifname}")
            cli.execute(ctx, "switchport mode trunk")
            cli.execute(ctx, f"switchport trunk allowed vlan {allowed}")
            cli.execute(ctx, "no shutdown")
            cli.execute(ctx, "end")

        cfg_access(sw1, sw1_pc, 10)
        cfg_access(sw2, sw2_pc, 10)
        cfg_trunk(sw1, sw1_trk, "10")
        cfg_trunk(sw2, sw2_trk, "10")

        pccli = PCCLIEngine(sim)
        pc1 = pccli.new_context("PC1")
        pc2 = pccli.new_context("PC2")
        pccli.execute(pc1, "ip 10.10.10.1 255.255.255.0")
        pccli.execute(pc2, "ip 10.10.10.2 255.255.255.0")

        ok = pccli.execute(pc1, "ping 10.10.10.2").output
        self.assertIn("Success rate", ok)

        # Now disallow VLAN 10 on the trunk and verify ping fails.
        cfg_trunk(sw1, sw1_trk, "20")
        cfg_trunk(sw2, sw2_trk, "20")
        blocked = pccli.execute(pc1, "ping 10.10.10.2").output
        self.assertIn("unreachable", blocked.lower())


if __name__ == "__main__":
    unittest.main()
