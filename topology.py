#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def Assignment5():
    net = Mininet( topo=None,
                   build=False)

    info( '*** Adding controller\n' )
    c0=net.addController('c0',
                      controller=RemoteController,
                      protocol='tcp',
                      port=6633)

    info( '*** Add switches\n')
    s5 = net.addSwitch('s5', cls=OVSKernelSwitch, listenPort=5, dpid='5')
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch, listenPort=5, dpid='3')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch, listenPort=5, dpid='1')
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch, listenPort=5, dpid='2')
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch, listenPort=5, dpid='4')



    info( '*** Add hosts\n')
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', cls=Host, ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    h4 = net.addHost('h4', cls=Host, ip='10.0.0.4/24', mac='00:00:00:00:00:04')
    h5 = net.addHost('h5', cls=Host, ip='10.0.0.5/24', mac='00:00:00:00:05:00')
    h6 = net.addHost('h6', cls=Host, ip='10.0.0.6/24', mac='00:00:00:00:06:00')
    h7 = net.addHost('h7', cls=Host, ip='10.0.0.7/24', mac='00:00:00:00:07:00')
    h8 = net.addHost('h8', cls=Host, ip='10.0.0.8/24', mac='00:00:00:00:08:00')

    info( '*** Add links\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s2)
    net.addLink(h4, s2)
    net.addLink(s1, s5)
    net.addLink(s2, s5)
    net.addLink(s5, s3)
    net.addLink(s5, s4)
    net.addLink(s3, h5)
    net.addLink(s3, h6)
    net.addLink(s4, h7)
    net.addLink(s4, h8)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s5').start([c0])
    net.get('s1').start([c0])
    net.get('s3').start([c0])
    net.get('s2').start([c0])
    net.get('s4').start([c0])


    '''
    Change MAC address for all interfaces of the switch to specif addresses
    '''
    info('*** Fixing mac addresses for other ports\n')
    s3.cmd("sudo ip link set down s3-eth1")
    s3.cmd("sudo ip link set dev s3-eth1 address 00:01:00:00:00:00")
    s3.cmd("sudo ip link set up s3-eth1")
    s4.cmd("sudo ip link set down s4-eth1")
    s4.cmd("sudo ip link set dev s4-eth1 address 00:02:00:00:00:00")
    s4.cmd("sudo ip link set up s4-eth1")


    info( '*** Adding Default Routes for all Hostst\n')
    '''
    Add Default routes so that all packets go out from a specific interface
    '''
    h1.cmd("ip route add default dev h1-eth0")
    h2.cmd("ip route add default dev h2-eth0")
    h3.cmd("ip route add default dev h3-eth0")
    h4.cmd("ip route add default dev h4-eth0")
    h5.cmd("ip route add default dev h5-eth0")
    h6.cmd("ip route add default dev h6-eth0")
    h7.cmd("ip route add default dev h7-eth0")
    h8.cmd("ip route add default dev h8-eth0")

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    Assignment5()
