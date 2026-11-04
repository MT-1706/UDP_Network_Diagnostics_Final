#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
import json, os

META_FILE = '/tmp/sdn_topo_meta.json'   # read by the dashboard (link interfaces + base delays)

def delay_ms(params):
    """'10ms' -> 10.0 (None/missing -> 0.0)"""
    try:
        return float(str(params.get('delay', '0ms')).replace('ms', ''))
    except ValueError:
        return 0.0

def write_meta(net):
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
    """Create and start the network (also used by automated tests)."""
    kw = {'datapath': os.environ['MN_DATAPATH']} if os.environ.get('MN_DATAPATH') else {}   # 'user' = no kernel module needed
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')
    s1 = net.addSwitch('s1', protocols='OpenFlow13', **kw)
    s2 = net.addSwitch('s2', protocols='OpenFlow13', **kw)
    s3 = net.addSwitch('s3', protocols='OpenFlow13', **kw)

    net.addLink(h1, s1)
    net.addLink(h3, s2)
    net.addLink(h2, s3)
    net.addLink(s1, s2, delay='10ms')
    net.addLink(s2, s3, delay='10ms')
    # Redundant link -> a second path h1..h2 (s1-s3 direct: 1 hop but SLOWER,
    # 30 ms each way, versus s1-s2-s3: 2 hops, 10 ms + 10 ms).
    net.addLink(s1, s3, delay='30ms')

    net.start()
    write_meta(net)
    return net

def disable_offload(net):
    """Make hosts finish UDP/TCP checksums themselves.  With Open vSwitch's user-space
    datapath (VMs, WSL, containers without the kernel module) packets leave the host
    with an unfinished checksum and are silently dropped, so ping works but UDP probes
    get 100% loss.  Harmless with the kernel datapath."""
    for h in net.hosts:
        for intf in h.intfList():
            if intf.name != 'lo':
                h.cmd('ethtool -K %s tx off rx off 2>/dev/null' % intf.name)

def run():
    net = build()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
