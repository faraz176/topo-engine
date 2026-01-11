import unittest

from sim.core import TopologySim
from sim.cli import CLIEngine


class TestSwitching(unittest.TestCase):
    def test_switch_vlan_access_ping(self):
        sim = TopologySim()
        sim.add_device("R1", "router")
        sim.add_device("R2", "router")
        sim.add_device("SW1", "switch")

        r1_if = sim.allocate_interface_name("R1")
        r2_if = sim.allocate_interface_name("R2")
        sw_if1 = sim.allocate_interface_name("SW1")
        sw_if2 = sim.allocate_interface_name("SW1")

        sim.connect("R1", r1_if, "SW1", sw_if1)
        sim.connect("R2", r2_if, "SW1", sw_if2)

        cli = CLIEngine(sim)
        c1 = cli.new_context("R1")
        c2 = cli.new_context("R2")
        csw = cli.new_context("SW1")

        cli.execute(csw, "enable")
        cli.execute(csw, "conf t")
        cli.execute(csw, f"interface {sw_if1}")
        cli.execute(csw, "switchport mode access")
        cli.execute(csw, "switchport access vlan 10")
        cli.execute(csw, "no shutdown")
        cli.execute(csw, "exit")
        cli.execute(csw, f"interface {sw_if2}")
        cli.execute(csw, "switchport mode access")
        cli.execute(csw, "switchport access vlan 10")
        cli.execute(csw, "no shutdown")
        cli.execute(csw, "end")

        for ctx, ifn, ip in ((c1, r1_if, "10.10.10.1"), (c2, r2_if, "10.10.10.2")):
            cli.execute(ctx, "enable")
            cli.execute(ctx, "conf t")
            cli.execute(ctx, f"interface {ifn}")
            # treat router port as access vlan 10 for L2 adjacency in this build
            cli.execute(ctx, "switchport mode access")
            cli.execute(ctx, "switchport access vlan 10")
            cli.execute(ctx, f"ip address {ip} 255.255.255.0")
            cli.execute(ctx, "no shutdown")
            cli.execute(ctx, "end")

        out = cli.execute(c1, "ping 10.10.10.2").output
        self.assertIn("Success rate", out)

        # After traffic, the switch should have learned MACs.
        out = cli.execute(csw, "show mac address-table").output
        self.assertIn("Mac Address Table", out)
        self.assertIn("DYNAMIC", out)


class TestSpanningTree(unittest.TestCase):
    def test_spanning_tree_blocks_loop(self):
        sim = TopologySim()
        for sw in ("SW1", "SW2", "SW3"):
            sim.add_device(sw, "switch")

        # Triangle between switches.
        sw1_a = sim.allocate_interface_name("SW1")
        sw2_a = sim.allocate_interface_name("SW2")
        sim.connect("SW1", sw1_a, "SW2", sw2_a)

        sw1_b = sim.allocate_interface_name("SW1")
        sw3_a = sim.allocate_interface_name("SW3")
        sim.connect("SW1", sw1_b, "SW3", sw3_a)

        sw2_b = sim.allocate_interface_name("SW2")
        sw3_b = sim.allocate_interface_name("SW3")
        sim.connect("SW2", sw2_b, "SW3", sw3_b)

        cli = CLIEngine(sim)

        def trunk_up(uid: str, ifnames):
            c = cli.new_context(uid)
            cli.execute(c, "enable")
            cli.execute(c, "conf t")
            for ifn in ifnames:
                cli.execute(c, f"interface {ifn}")
                cli.execute(c, "switchport mode trunk")
                cli.execute(c, "no shutdown")
                cli.execute(c, "exit")
            cli.execute(c, "end")
            return c

        trunk_up("SW1", (sw1_a, sw1_b))
        trunk_up("SW2", (sw2_a, sw2_b))
        c3 = trunk_up("SW3", (sw3_a, sw3_b))

        # On a triangle, our simplified STP should block at least one port.
        out = cli.execute(c3, "show spanning-tree").output
        self.assertIn("Spanning tree enabled", out)
        self.assertTrue("BLK" in out or "Altn" in out)


if __name__ == "__main__":
    unittest.main()
