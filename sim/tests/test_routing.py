import unittest

from sim.core import TopologySim
from sim.cli import CLIEngine


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
        self.assertIn("R2", out)

        rt = cli.execute(c1, "show ip route").output
        self.assertIn("192.168.2.0/24", rt)


if __name__ == "__main__":
    unittest.main()
