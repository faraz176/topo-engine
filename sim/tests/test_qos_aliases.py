import unittest

from sim.core import TopologySim
from sim.cli import CLIEngine


class TestQoSAliases(unittest.TestCase):
    def test_llq_alias_shortcuts(self):
        sim = TopologySim()
        sim.add_device("R1", "router")

        cli = CLIEngine(sim)
        ctx = cli.new_context("R1")

        cli.execute(ctx, "en")
        res = cli.execute(ctx, "conf t")
        self.assertEqual("", res.output)
        self.assertEqual("config", ctx.mode)

        res = cli.execute(ctx, "class ef-traffic")
        self.assertEqual("", res.output)
        self.assertEqual("config-cmap", ctx.mode)

        res = cli.execute(ctx, "match d ef")
        self.assertEqual("", res.output)

        cli.execute(ctx, "exit")
        self.assertEqual("config", ctx.mode)

        res = cli.execute(ctx, "policy qos-policy")
        self.assertEqual("", res.output)
        self.assertEqual("config-pmap", ctx.mode)

        res = cli.execute(ctx, "class ef-traffic")
        self.assertEqual("", res.output)
        self.assertEqual("config-pclass", ctx.mode)

        res = cli.execute(ctx, "pri 100")
        self.assertEqual("", res.output)
        res = cli.execute(ctx, "bw rem per 20")
        self.assertEqual("", res.output)

        cli.execute(ctx, "exit")  # back to policy-map
        cli.execute(ctx, "exit")  # back to config

        res = cli.execute(ctx, "int fa0/0")
        self.assertEqual("", res.output)
        self.assertEqual("config-if", ctx.mode)

        res = cli.execute(ctx, "serv-pol out qos-policy")
        self.assertEqual("", res.output)

        cli.execute(ctx, "end")

        res = cli.execute(ctx, "sh policy int Fa0/0")
        self.assertIn("Service-policy output: qos-policy", res.output)

    def test_access_list_alias(self):
        sim = TopologySim()
        sim.add_device("R1", "router")

        cli = CLIEngine(sim)
        ctx = cli.new_context("R1")

        cli.execute(ctx, "en")
        cli.execute(ctx, "conf t")

        res = cli.execute(ctx, "acc VOICE")
        self.assertEqual("", res.output)
        self.assertEqual("config-acl", ctx.mode)
        self.assertEqual("VOICE", ctx.current_acl)

        res = cli.execute(ctx, "permit icmp any any")
        self.assertEqual("", res.output)


if __name__ == "__main__":
    unittest.main()
