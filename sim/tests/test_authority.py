import unittest

from sim.core import TopologySim
from sim.cli import CLIEngine
from sim.authority import AuthorityModel


class TestAuthority(unittest.TestCase):
    def test_pdf_authority_gates_commands(self):
        # Only VLANs + trunks mentioned; no OSPF, no ACL, no EtherChannel.
        auth = AuthorityModel.from_text("Configure and verify VLANs and trunks")

        sim = TopologySim()
        sim.add_device("SW1", "switch")

        cli = CLIEngine(sim, authority=auth)
        c = cli.new_context("SW1")

        # Base CLI scaffolding always allowed.
        cli.execute(c, "enable")
        cli.execute(c, "conf t")

        # In-scope: vlan mode + show vlan.
        out = cli.execute(c, "vlan 10").output
        self.assertEqual(out, "")
        cli.execute(c, "name USERS")
        cli.execute(c, "end")
        out = cli.execute(c, "show vlan brief").output
        self.assertIn("VLAN", out)

        # Out-of-scope (not implied): OSPF
        out = cli.execute(c, "show ip ospf neighbor").output
        self.assertEqual(out, "% Command not supported in this simulator.")

        # Out-of-scope: EtherChannel summary
        out = cli.execute(c, "show etherchannel summary").output
        self.assertEqual(out, "% Command not supported in this simulator.")


class TestIosCompat(unittest.TestCase):
    def test_do_passthrough_and_show_abbrev(self):
        # Enable IPv4 verification commands in-scope.
        auth = AuthorityModel.from_text("IPv4 addressing and verify with show ip interface brief")

        sim = TopologySim()
        sim.add_device("R1", "router")
        ifn = sim.allocate_interface_name("R1")

        cli = CLIEngine(sim, authority=auth)
        c = cli.new_context("R1")
        cli.execute(c, "enable")
        cli.execute(c, "conf t")
        cli.execute(c, f"interface {ifn}")
        cli.execute(c, "ip address 10.0.0.1 255.255.255.0")
        cli.execute(c, "no shutdown")

        # Config mode: exec command should work via IOS 'do', including abbreviation.
        out = cli.execute(c, "do sh ip int brief").output
        self.assertIn("Interface", out)
        self.assertIn("10.0.0.1", out)

    def test_no_shut_and_interface_shortname(self):
        auth = AuthorityModel.from_text("IPv4 addressing and verify with show ip interface brief")

        sim = TopologySim()
        sim.add_device("R4", "router")
        gi0_0 = sim.allocate_interface_name("R4")  # Gi0/0

        cli = CLIEngine(sim, authority=auth)
        c = cli.new_context("R4")
        cli.execute(c, "en")
        cli.execute(c, "conf t")

        # IOS shorthand: int g0/0 should refer to Gi0/0 (not create a new 'g0/0' interface)
        cli.execute(c, "int g0/0")
        cli.execute(c, "ip address 192.168.1.1 255.255.255.0")

        # IOS shorthand: no shut -> no shutdown
        out = cli.execute(c, "no shut").output
        self.assertEqual(out, "")

        # Verify status is up on Gi0/0 and that we did not create a separate 'g0/0'
        out = cli.execute(c, "do sh ip int brief").output
        self.assertIn(gi0_0, out)
        self.assertNotIn("g0/0", out)

    def test_ambiguous_prefix_errors(self):
        # In interface config mode, "sh" could be show or shutdown; IOS reports ambiguity.
        auth = AuthorityModel.from_text("IPv4 addressing")

        sim = TopologySim()
        sim.add_device("R1", "router")
        ifn = sim.allocate_interface_name("R1")

        cli = CLIEngine(sim, authority=auth)
        c = cli.new_context("R1")
        cli.execute(c, "enable")
        cli.execute(c, "conf t")
        cli.execute(c, f"interface {ifn}")

        out = cli.execute(c, "sh").output
        self.assertEqual(out, "% Ambiguous command.")


if __name__ == "__main__":
    unittest.main()
