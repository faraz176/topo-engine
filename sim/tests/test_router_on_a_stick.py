import unittest

from sim.core import TopologySim
from sim.cli import CLIEngine
from sim.pc_cli import PCCLIEngine


class TestRouterOnAStick(unittest.TestCase):
    def test_roas_vlan10_vlan20_and_misconfigs(self):
        sim = TopologySim()
        sim.add_device("R1", "router")
        sim.add_device("SW1", "switch")
        sim.add_device("PC10", "host")
        sim.add_device("PC20", "host")

        r1_uplink = sim.allocate_interface_name("R1")  # Gi0/0
        sw1_trunk = sim.allocate_interface_name("SW1")  # Fa0/1
        sw1_v10 = sim.allocate_interface_name("SW1")  # Fa0/2
        sw1_v20 = sim.allocate_interface_name("SW1")  # Fa0/3

        sim.connect("R1", r1_uplink, "SW1", sw1_trunk)
        sim.connect("SW1", sw1_v10, "PC10", "Eth0")
        sim.connect("SW1", sw1_v20, "PC20", "Eth0")

        cli = CLIEngine(sim)
        r1 = cli.new_context("R1")
        sw1 = cli.new_context("SW1")

        # SW1 VLANs + access ports
        cli.execute(sw1, "enable")
        cli.execute(sw1, "conf t")
        cli.execute(sw1, "vlan 10")
        cli.execute(sw1, "name VLAN10")
        cli.execute(sw1, "exit")
        cli.execute(sw1, "vlan 20")
        cli.execute(sw1, "name VLAN20")
        cli.execute(sw1, "exit")

        cli.execute(sw1, f"interface {sw1_v10}")
        cli.execute(sw1, "switchport mode access")
        cli.execute(sw1, "switchport access vlan 10")
        cli.execute(sw1, "no shutdown")
        cli.execute(sw1, "exit")

        cli.execute(sw1, f"interface {sw1_v20}")
        cli.execute(sw1, "switchport mode access")
        cli.execute(sw1, "switchport access vlan 20")
        cli.execute(sw1, "no shutdown")
        cli.execute(sw1, "exit")

        # Trunk to router carries both VLANs
        cli.execute(sw1, f"interface {sw1_trunk}")
        cli.execute(sw1, "switchport mode trunk")
        cli.execute(sw1, "switchport trunk allowed vlan 10,20")
        cli.execute(sw1, "no shutdown")
        cli.execute(sw1, "end")

        # R1 router-on-a-stick
        cli.execute(r1, "enable")
        cli.execute(r1, "conf t")
        cli.execute(r1, f"interface {r1_uplink}")
        cli.execute(r1, "no shutdown")
        cli.execute(r1, "exit")

        cli.execute(r1, f"interface {r1_uplink}.10")
        cli.execute(r1, "encapsulation dot1q 10")
        cli.execute(r1, "ip address 192.168.10.1 255.255.255.0")
        cli.execute(r1, "no shutdown")
        cli.execute(r1, "exit")

        cli.execute(r1, f"interface {r1_uplink}.20")
        cli.execute(r1, "encapsulation dot1q 20")
        cli.execute(r1, "ip address 192.168.20.1 255.255.255.0")
        cli.execute(r1, "no shutdown")
        cli.execute(r1, "end")

        pccli = PCCLIEngine(sim)
        pc10 = pccli.new_context("PC10")
        pc20 = pccli.new_context("PC20")
        pccli.execute(pc10, "ip 192.168.10.10 255.255.255.0 192.168.10.1")
        pccli.execute(pc20, "ip 192.168.20.10 255.255.255.0 192.168.20.1")

        # Same VLAN host -> gateway
        self.assertIn("Success rate", pccli.execute(pc10, "ping 192.168.10.1").output)
        self.assertIn("Success rate", pccli.execute(pc20, "ping 192.168.20.1").output)

        # Inter-VLAN via router
        self.assertIn("Success rate", pccli.execute(pc10, "ping 192.168.20.10").output)

        # VLAN mismatch must break connectivity: put PC20 port into VLAN 10
        cli.execute(sw1, "enable")
        cli.execute(sw1, "conf t")
        cli.execute(sw1, f"interface {sw1_v20}")
        cli.execute(sw1, "switchport access vlan 10")
        cli.execute(sw1, "end")

        out = pccli.execute(pc20, "ping 192.168.20.1").output
        self.assertIn("unreachable", out.lower())

        # Restore VLAN 20, then misconfigure trunk to drop VLAN 20
        cli.execute(sw1, "enable")
        cli.execute(sw1, "conf t")
        cli.execute(sw1, f"interface {sw1_v20}")
        cli.execute(sw1, "switchport access vlan 20")
        cli.execute(sw1, "exit")
        cli.execute(sw1, f"interface {sw1_trunk}")
        cli.execute(sw1, "switchport trunk allowed vlan 10")
        cli.execute(sw1, "end")

        out2 = pccli.execute(pc20, "ping 192.168.20.1").output
        self.assertIn("unreachable", out2.lower())


if __name__ == "__main__":
    unittest.main()
