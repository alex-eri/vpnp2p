modprobe tun
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o enp2s0 -j MASQUERADE


ip netns add testa
ip link add vethlocal type veth peer name vethremote
ip a a 192.168.123.1 peer 192.168.123.2 dev vethlocal
ip l s dev vethlocal up
ip link set vethremote netns testa
ip netns exec testa ip a a 192.168.123.2 peer 192.168.123.1 dev vethremote
ip netns exec testa ip l s dev vethremote up
ip netns exec testa ip r a default via 192.168.123.1
ip netns exec testa bash

gdbserver --multi 0.0.0.0:2345 ./vpnp2p

ip a a 10.0.0.1/24 dev tapp2p0

gdb ./vpnp2p

r

ip netns exec testa ip a a 10.0.0.2/24 dev tapp2p0
