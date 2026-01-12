import unittest

from sim.core import TopologySim
from sim.cli import CLIEngine


class TestOSPFRouterID(unittest.TestCase):
    def test_router_id_command_and_adjacency(self):
        sim = TopologySim()
        sim.add_device("R1", "router")
        sim.add_device("R2", "router")

        # Links
        sim.connect("R1", "Gi0/0", "R2", "Gi0/0")

        cli = CLIEngine(sim)
        r1 = cli.new_context("R1")
        r2 = cli.new_context("R2")

        # R1 config
        cli.execute(r1, "enable")
        cli.execute(r1, "conf t")
        cli.execute(r1, "interface Gi0/0")
        cli.execute(r1, "ip address 10.0.0.1 255.255.255.0")
        cli.execute(r1, "no shutdown")
        cli.execute(r1, "exit")
        cli.execute(r1, "interface Lo0")
        cli.execute(r1, "ip address 1.1.1.1 255.255.255.255")
        cli.execute(r1, "no shutdown")
        cli.execute(r1, "exit")
        cli.execute(r1, "router ospf 1")
        cli.execute(r1, "router-id 1.1.1.1")
        cli.execute(r1, "network 10.0.0.0 0.0.0.255 area 0")
        cli.execute(r1, "network 1.1.1.1 0.0.0.0 area 0")
        cli.execute(r1, "end")

        # R2 config
        cli.execute(r2, "enable")
        cli.execute(r2, "conf t")
        cli.execute(r2, "interface Gi0/0")
        cli.execute(r2, "ip address 10.0.0.2 255.255.255.0")
        cli.execute(r2, "no shutdown")
        cli.execute(r2, "exit")
        cli.execute(r2, "interface Lo0")
        cli.execute(r2, "ip address 2.2.2.2 255.255.255.255")
        cli.execute(r2, "no shutdown")
        cli.execute(r2, "exit")
        cli.execute(r2, "router ospf 1")
        cli.execute(r2, "router-id 2.2.2.2")
        cli.execute(r2, "network 10.0.0.0 0.0.0.255 area 0")
        cli.execute(r2, "network 2.2.2.2 0.0.0.0 area 0")
        cli.execute(r2, "end")

        # Neighbor display should show router-id
        nb_out = cli.execute(r1, "show ip ospf neighbor").output
        self.assertIn("2.2.2.2", nb_out)

        # R1 should learn R2's loopback via OSPF
        routes = sim.routes_for("R1")
        self.assertTrue(any(str(r.prefix) == "2.2.2.2/32" and r.protocol == "O" for r in routes))

    def test_router_id_fallback_highest_interface(self):
        sim = TopologySim()
        sim.add_device("R3", "router")
        cli = CLIEngine(sim)
        r3 = cli.new_context("R3")

        cli.execute(r3, "enable")
        cli.execute(r3, "conf t")
        cli.execute(r3, "interface Gi0/0")
        cli.execute(r3, "ip address 10.0.1.1 255.255.255.0")
        cli.execute(r3, "no shutdown")
        cli.execute(r3, "exit")
        cli.execute(r3, "router ospf 1")
        cli.execute(r3, "network 10.0.1.0 0.0.0.255 area 0")
        cli.execute(r3, "end")

        proto = cli.execute(r3, "show ip protocols").output
        self.assertIn("Router ID 10.0.1.1", proto)


if __name__ == "__main__":
    unittest.main()
