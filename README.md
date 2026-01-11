# topo-engine an upgrade from topo-drawer

A lightweight, deterministic network simulator and topology-driven
configuration engine inspired by Cisco IOS behavior.

Designed for CCNA, CCNP, and CCIE-level study, validation, and deployment
workflows, with a focus on correctness, simplicity, and extensibility.

Still actively in production. Not ready for release


Project fixes:

-Apply shortcut sh running-config (should autocomplete) 
-Adjust MCP to be more intelligent (we added hosts) (have it generate hosts as well because right now it only has access to 
routers and switches we want it to have access to hosts as well) 
-The MCP should be able to configure the devices when asked for example, if I say generate a simple OSPF topology and configure it 
it should be able to configure all devices including hosts with the necessary configurations to successfully run OSPF 
-fails or work on Mac (Friends computer) 
