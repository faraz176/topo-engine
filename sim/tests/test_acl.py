import unittest

from sim.core import TopologySim
from sim.cli import CLIEngine


class TestACL(unittest.TestCase):
    def test_acl_blocks_icmp(self):
        sim = TopologySim()
        sim.add_device("R1", "router")
        sim.add_device("R2", "router")

        r1_if = sim.allocate_interface_name("R1")
        r2_if = sim.allocate_interface_name("R2")
        sim.connect("R1", r1_if, "R2", r2_if)

        cli = CLIEngine(sim)
        c1 = cli.new_context("R1")
        c2 = cli.new_context("R2")

        for ctx, ifn, ip in ((c1, r1_if, "10.0.0.1"), (c2, r2_if, "10.0.0.2")):
            cli.execute(ctx, "enable")
            cli.execute(ctx, "conf t")
            cli.execute(ctx, f"interface {ifn}")
            cli.execute(ctx, f"ip address {ip} 255.255.255.0")
            cli.execute(ctx, "no shutdown")
            cli.execute(ctx, "end")

        out_ok = cli.execute(c1, "ping 10.0.0.2").output
        self.assertIn("Success rate", out_ok)

        cli.execute(c1, "enable")
        cli.execute(c1, "conf t")
        cli.execute(c1, "ip access-list extended BLOCKICMP")
        cli.execute(c1, "deny icmp any any")
        cli.execute(c1, "permit ip any any")
        cli.execute(c1, "exit")
        cli.execute(c1, f"interface {r1_if}")
        cli.execute(c1, "ip access-group BLOCKICMP out")
        cli.execute(c1, "end")

        out_block = cli.execute(c1, "ping 10.0.0.2").output
        self.assertIn("prohibited", out_block.lower())

        show = cli.execute(c1, "show access-lists").output
        self.assertIn("BLOCKICMP", show)


if __name__ == "__main__":
    unittest.main()
