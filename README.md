# topo-engine an upgrade from topo-drawer

A lightweight, deterministic network simulator and topology-driven
configuration engine inspired by Cisco IOS behavior.

Designed for CCNA, CCNP, and CCIE-level study, validation, and deployment
workflows, with a focus on correctness, simplicity, and extensibility.

Still actively in production. Not ready for release


Project fixes (to apply)

- Apply shortcut `sh running-config` (should autocomplete)

- Adjust MCP to be more intelligent (we added hosts).  
  Have it generate hosts as well; currently it only has access to routers and switches.

- The MCP should be able to configure devices when asked.  
  Example: “Generate a simple OSPF topology and configure it.”  
  It should configure all devices, including hosts, with the necessary settings to run OSPF.

- Fails or works on macOS (friend’s computer)

