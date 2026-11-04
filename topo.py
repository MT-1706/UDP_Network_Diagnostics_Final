#!/usr/bin/env python3
# This file creates the virtual network using Mininet. It defines three hosts,
# three OpenFlow switches and links between the switches. The triangle gives
# the controller more than one possible route between h1 and h2.
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
import json, os

META_FILE = '/tmp/sdn_topo_meta.json'   # read by the dashboard (link interfaces + base delays)

def delay_ms(params):
    # Convert Mininet's delay string (for example, "10ms") into a number.
    # The dashboard uses this value when displaying/estimating path delay.
    """'10ms' -> 10.0 (None/missing -> 0.0)"""
    try:
        return float(str(params.get('delay', '0ms')).replace('ms', ''))
    except ValueError:
        return 0.0

def write_meta(net):
    # Save the real interface names for every switch-to-switch link.
    # The dashboard later uses these names with the Linux "ip link" command
    # to simulate a link failure and then restore the link.
    """Save which interface belongs to which link, so the dashboard can fail
    links and inject loss/delay.  Never allowed to break the topology."""
    try:
        meta = []
        for l in net.links:
            a, b = l.intf1.node.name, l.intf2.node.name
            if a.startswith('s') and b.startswith('s'):          # switch-switch links only
                meta.append({'a': a, 'b': b, 'if_a': l.intf1.name, 'if_b': l.intf2.name,
                             'delay_ms': delay_ms(l.intf1.params)})
        with open(META_FILE, 'w') as f:
            json.dump(meta, f)
    except Exception as e:
        print('warning: could not write %s: %s' % (META_FILE, e))

def build():
    # Build the network but do not open the Mininet command-line yet.
    # Keeping construction in a function also lets automated tests reuse it.
    """Create and start the network (also used by automated tests)."""
    kw = {'datapath': os.environ['MN_DATAPATH']} if os.environ.get('MN_DATAPATH') else {}   # 'user' = no kernel module needed
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True)
    # Connect every switch to the Ryu controller listening on localhost:6653.
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')
    s1 = net.addSwitch('s1', protocols='OpenFlow13', **kw)
    s2 = net.addSwitch('s2', protocols='OpenFlow13', **kw)
    s3 = net.addSwitch('s3', protocols='OpenFlow13', **kw)
# Host-facing links: h1 is attached to s1, h3 to s2 and h2 to s3.
    # These IP addresses are the source/destination addresses used by probes.
    net.addLink(h1, s1)
    net.addLink(h3, s2)
    net.addLink(h2, s3)
    # Inter-switch links form a triangle, so there are two routes from s1 to s3:
    # direct s1-s3 (one hop but 30 ms) and s1-s2-s3 (two hops, 10 ms per link).
    # This lets the project compare hop-count routing with measured performance.
    net.addLink(s1, s2, delay='10ms')
    net.addLink(s2, s3, delay='10ms')
    # Redundant link -> a second path h1..h2 (s1-s3 direct: 1 hop but SLOWER,
    # 30 ms each way, versus s1-s2-s3: 2 hops, 10 ms + 10 ms).
    net.addLink(s1, s3, delay='30ms')

    net.start()
    write_meta(net)
    return net

def disable_offload(net):
    # Disable NIC checksum offloading on hosts. This is useful with the OVS
    # userspace datapath in VMs: otherwise UDP packets may have incomplete
    # checksums and appear as packet loss even when the path is connected.
    """Make hosts finish UDP/TCP checksums themselves.  With Open vSwitch's user-space
    datapath (VMs, WSL, containers without the kernel module) packets leave the host
    with an unfinished checksum and are silently dropped, so ping works but UDP probes
    get 100% loss.  Harmless with the kernel datapath."""
    for h in net.hosts:
        for intf in h.intfList():
            if intf.name != 'lo':
                h.cmd('ethtool -K %s tx off rx off 2>/dev/null' % intf.name)

def run():
     # Start the topology, hand control to the Mininet CLI, then stop it cleanly
    # when the user exits the CLI (for example by typing "exit").
    net = build()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
