import unittest

from sim.core import TopologySim
from sim.cli import CLIEngine
from sim.pc_cli import PCCLIEngine


class TestMaxLevel(unittest.TestCase):
    def test_ospf_redundant_paths_deterministic_and_failover(self):
        r"""Max-level: redundant OSPF paths + deterministic choice + failover.

        Topology (diamond):
            R2
           /  \
        R1      R4
           \  /
            R3

        Expectation:
        - With equal-cost paths, the simulator picks a deterministic next-hop.
        - If the preferred path link goes down, it fails over to the alternate.
        """

        sim = TopologySim()
        for uid, kind in (
            ("R1", "router"),
            ("R2", "router"),
            ("R3", "router"),
            ("R4", "router"),
            ("PC1", "host"),
            ("PC4", "host"),
        ):
            sim.add_device(uid, kind)

        # Links
        r1_r2 = sim.allocate_interface_name("R1")
        r2_r1 = sim.allocate_interface_name("R2")
        l12 = sim.connect("R1", r1_r2, "R2", r2_r1)

        r1_r3 = sim.allocate_interface_name("R1")
        r3_r1 = sim.allocate_interface_name("R3")
        l13 = sim.connect("R1", r1_r3, "R3", r3_r1)

        r2_r4 = sim.allocate_interface_name("R2")
        r4_r2 = sim.allocate_interface_name("R4")
        l24 = sim.connect("R2", r2_r4, "R4", r4_r2)

        r3_r4 = sim.allocate_interface_name("R3")
        r4_r3 = sim.allocate_interface_name("R4")
        l34 = sim.connect("R3", r3_r4, "R4", r4_r3)

        # Edge LANs
        r1_pc = sim.allocate_interface_name("R1")
        r4_pc = sim.allocate_interface_name("R4")
        sim.connect("R1", r1_pc, "PC1", "Eth0")
        sim.connect("R4", r4_pc, "PC4", "Eth0")

        cli = CLIEngine(sim)

        def cfg_if(uid: str, ifname: str, ip: str, mask: str):
            c = cli.new_context(uid)
            cli.execute(c, "enable")
            cli.execute(c, "conf t")
            cli.execute(c, f"interface {ifname}")
            cli.execute(c, f"ip address {ip} {mask}")
            cli.execute(c, "no shutdown")
            cli.execute(c, "end")

        # /30 transit links
        cfg_if("R1", r1_r2, "10.0.12.1", "255.255.255.252")
        cfg_if("R2", r2_r1, "10.0.12.2", "255.255.255.252")

        cfg_if("R1", r1_r3, "10.0.13.1", "255.255.255.252")
        cfg_if("R3", r3_r1, "10.0.13.2", "255.255.255.252")

        cfg_if("R2", r2_r4, "10.0.24.1", "255.255.255.252")
        cfg_if("R4", r4_r2, "10.0.24.2", "255.255.255.252")

        cfg_if("R3", r3_r4, "10.0.34.1", "255.255.255.252")
        cfg_if("R4", r4_r3, "10.0.34.2", "255.255.255.252")

        # LANs
        cfg_if("R1", r1_pc, "192.168.1.1", "255.255.255.0")
        cfg_if("R4", r4_pc, "192.168.4.1", "255.255.255.0")

        # OSPF on all routers for all connected nets
        def ospf_all(uid: str, nets):
            c = cli.new_context(uid)
            cli.execute(c, "enable")
            cli.execute(c, "conf t")
            cli.execute(c, "router ospf 1")
            for n in nets:
                cli.execute(c, f"network {n} area 0")
            cli.execute(c, "end")

        ospf_all("R1", ["10.0.12.0 0.0.0.3", "10.0.13.0 0.0.0.3", "192.168.1.0 0.0.0.255"])
        ospf_all("R2", ["10.0.12.0 0.0.0.3", "10.0.24.0 0.0.0.3"])
        ospf_all("R3", ["10.0.13.0 0.0.0.3", "10.0.34.0 0.0.0.3"])
        ospf_all("R4", ["10.0.24.0 0.0.0.3", "10.0.34.0 0.0.0.3", "192.168.4.0 0.0.0.255"])

        # Hosts
        pccli = PCCLIEngine(sim)
        pc1 = pccli.new_context("PC1")
        pc4 = pccli.new_context("PC4")
        pccli.execute(pc1, "ip 192.168.1.10 255.255.255.0 192.168.1.1")
        pccli.execute(pc4, "ip 192.168.4.10 255.255.255.0 192.168.4.1")

        # Baseline should work.
        ping = pccli.execute(pc1, "ping 192.168.4.10").output
        self.assertIn("Success rate", ping)

        # Deterministic path: should pick R2 as first hop from R1 towards R4's LAN
        tr = pccli.execute(pc1, "traceroute 192.168.4.10").output
        self.assertIn("10.0.12.2", tr)
        self.assertNotIn("10.0.13.2", tr)

        # Fail over by removing the preferred link R2<->R4
        sim.remove_link(l24)

        ping2 = pccli.execute(pc1, "ping 192.168.4.10").output
        self.assertIn("Success rate", ping2)

        tr2 = pccli.execute(pc1, "traceroute 192.168.4.10").output
        self.assertIn("10.0.13.2", tr2)
        self.assertNotIn("10.0.12.2", tr2)


if __name__ == "__main__":
    unittest.main()
