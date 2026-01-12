import unittest

from sim.core import TopologySim
from sim.cli import CLIEngine
from sim.pc_cli import PCCLIEngine


class TestRouting(unittest.TestCase):
    def test_two_routers_ping_connected(self):
        sim = TopologySim()
        sim.add_device("R1", "router")
        sim.add_device("R2", "router")

        r1_if = sim.allocate_interface_name("R1")
        r2_if = sim.allocate_interface_name("R2")
        sim.connect("R1", r1_if, "R2", r2_if)

        cli = CLIEngine(sim)
        c1 = cli.new_context("R1")
        c2 = cli.new_context("R2")

        cli.execute(c1, "enable")
        cli.execute(c1, "conf t")
        cli.execute(c1, f"interface {r1_if}")
        cli.execute(c1, "ip address 10.0.0.1 255.255.255.0")
        cli.execute(c1, "no shutdown")
        cli.execute(c1, "end")

        cli.execute(c2, "enable")
        cli.execute(c2, "conf t")
        cli.execute(c2, f"interface {r2_if}")
        cli.execute(c2, "ip address 10.0.0.2 255.255.255.0")
        cli.execute(c2, "no shutdown")
        cli.execute(c2, "end")

        out = cli.execute(c1, "ping 10.0.0.2").output
        self.assertIn("Success rate", out)

    def test_ospf_routes_form(self):
        sim = TopologySim()
        sim.add_device("R1", "router")
        sim.add_device("R2", "router")

        r1_if0 = sim.allocate_interface_name("R1")
        r2_if0 = sim.allocate_interface_name("R2")
        sim.connect("R1", r1_if0, "R2", r2_if0)

        r1_if1 = sim.allocate_interface_name("R1")
        r2_if1 = sim.allocate_interface_name("R2")
        # loopback-ish stubs (no physical links) but connected routes should exist when admin up.
        sim.ensure_interface("R1", r1_if1)
        sim.ensure_interface("R2", r2_if1)

        cli = CLIEngine(sim)
        c1 = cli.new_context("R1")
        c2 = cli.new_context("R2")

        for ctx, uplink, ip in ((c1, r1_if0, "10.0.0.1"), (c2, r2_if0, "10.0.0.2")):
            cli.execute(ctx, "enable")
            cli.execute(ctx, "conf t")
            cli.execute(ctx, f"interface {uplink}")
            cli.execute(ctx, f"ip address {ip} 255.255.255.0")
            cli.execute(ctx, "no shutdown")
            cli.execute(ctx, "exit")

        cli.execute(c1, f"interface {r1_if1}")
        cli.execute(c1, "ip address 192.168.1.1 255.255.255.0")
        cli.execute(c1, "no shutdown")
        cli.execute(c1, "exit")

        cli.execute(c2, f"interface {r2_if1}")
        cli.execute(c2, "ip address 192.168.2.1 255.255.255.0")
        cli.execute(c2, "no shutdown")
        cli.execute(c2, "exit")

        cli.execute(c1, "router ospf 1")
        cli.execute(c1, "network 10.0.0.0 0.0.0.255 area 0")
        cli.execute(c1, "network 192.168.1.0 0.0.0.255 area 0")
        cli.execute(c1, "end")

        cli.execute(c2, "conf t")
        cli.execute(c2, "router ospf 1")
        cli.execute(c2, "network 10.0.0.0 0.0.0.255 area 0")
        cli.execute(c2, "network 192.168.2.0 0.0.0.255 area 0")
        cli.execute(c2, "end")

        out = cli.execute(c1, "show ip ospf neighbor").output
        # R2 router-id derives from highest active interface IP (192.168.2.1)
        self.assertIn("192.168.2.1", out)

        rt = cli.execute(c1, "show ip route").output
        self.assertIn("192.168.2.0/24", rt)

    def test_ospf_multi_link_no_false_neighbors_and_ping(self):
        """Regression: routed links must not collapse into one shared segment.

        If unrelated routed links share the same L2 segment, OSPF may form false
        adjacencies and install routes with an impossible next hop, causing
        '% Destination unreachable' even with correct configs.
        """

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

        # PCs on edge routers
        r1_pc = sim.allocate_interface_name("R1")
        r3_pc = sim.allocate_interface_name("R3")
        sim.connect("R1", r1_pc, "PC1", "Eth0")
        sim.connect("R3", r3_pc, "PC3", "Eth0")

        cli = CLIEngine(sim)
        r1 = cli.new_context("R1")
        r2 = cli.new_context("R2")
        r3 = cli.new_context("R3")

        def cfg_if(ctx, ifname: str, ip: str, mask: str):
            cli.execute(ctx, f"interface {ifname}")
            cli.execute(ctx, f"ip address {ip} {mask}")
            cli.execute(ctx, "no shutdown")
            cli.execute(ctx, "exit")

        # Configure routed links + LAN stubs
        for ctx in (r1, r2, r3):
            cli.execute(ctx, "enable")
            cli.execute(ctx, "conf t")

        cfg_if(r1, r1_r2, "10.0.12.1", "255.255.255.252")
        cfg_if(r2, r2_r1, "10.0.12.2", "255.255.255.252")

        cfg_if(r2, r2_r3, "10.0.23.1", "255.255.255.252")
        cfg_if(r3, r3_r2, "10.0.23.2", "255.255.255.252")

        cfg_if(r1, r1_pc, "192.168.1.1", "255.255.255.0")
        cfg_if(r3, r3_pc, "192.168.3.1", "255.255.255.0")

        # OSPF everywhere
        cli.execute(r1, "router ospf 1")
        cli.execute(r1, "network 10.0.12.0 0.0.0.3 area 0")
        cli.execute(r1, "network 192.168.1.0 0.0.0.255 area 0")
        cli.execute(r1, "end")

        cli.execute(r2, "router ospf 1")
        cli.execute(r2, "network 10.0.12.0 0.0.0.3 area 0")
        cli.execute(r2, "network 10.0.23.0 0.0.0.3 area 0")
        cli.execute(r2, "end")

        cli.execute(r3, "router ospf 1")
        cli.execute(r3, "network 10.0.23.0 0.0.0.3 area 0")
        cli.execute(r3, "network 192.168.3.0 0.0.0.255 area 0")
        cli.execute(r3, "end")

        # Ensure R1 does not falsely neighbor with R3.
        nb = cli.execute(r1, "show ip ospf neighbor").output
        # R2 router-id derives from highest active IP (10.0.23.1); R3 should not appear.
        self.assertIn("10.0.23.1", nb)
        self.assertNotIn("10.0.23.2", nb)

        # End-to-end ping PC1 -> PC3 across OSPF.
        pccli = PCCLIEngine(sim)
        pc1 = pccli.new_context("PC1")
        pc3 = pccli.new_context("PC3")
        pccli.execute(pc1, "ip 192.168.1.10 255.255.255.0 192.168.1.1")
        pccli.execute(pc3, "ip 192.168.3.10 255.255.255.0 192.168.3.1")

        out = pccli.execute(pc1, "ping 192.168.3.10").output
        self.assertIn("Success rate", out)


if __name__ == "__main__":
    unittest.main()
