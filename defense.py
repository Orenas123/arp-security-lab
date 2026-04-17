import flet as ft
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
import threading
import sys

# Global variables
arp_table: dict[str, str] = {}
router_ip: str = conf.route.route("0.0.0.0")[2]
router_mac = None
sniffing: bool = False
stop_sniffing: bool = False
log_box = None

# Log helper
def log(text: str):
    if log_box:
        log_box.value += text + "\n"
        log_box.update()

# Get MAC for a given IP
def get_mac(target_ip: str) -> str:
    packet: Packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip, op=1)
    ans, _ = srp(packet, timeout=2, inter=0.1, verbose=0)
    if not ans:
        raise ValueError(f"No answers received for {target_ip}")
    return ans[0][1].hwsrc

# Build ARP table for the network
def fill_arp_table() -> dict[str, str]:
    this_ip = conf.route.route("0.0.0.0")[1]
    network = this_ip.rsplit(".", 1)[0] + ".0/24"  # assumes /24
    packet: Packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network, op=1)
    answered, _ = srp(packet, timeout=1, verbose=0)
    temp_arp_table: dict[str, str] = {}
    for sent, received in answered:
        temp_arp_table[received.psrc] = received.hwsrc
    return temp_arp_table

# Restore ARP table for victim and router
def restore_arp(victim_ip, victim_mac):
    victim_packet = Ether(dst=victim_mac) / ARP(
        op=2, psrc=router_ip, hwsrc=router_mac, pdst=victim_ip, hwdst=victim_mac
    )
    router_packet = Ether(dst=router_mac) / ARP(
        op=2, psrc=victim_ip, hwsrc=victim_mac, pdst=router_ip, hwdst=router_mac
    )
    sendp(victim_packet, count=5, verbose=0)
    sendp(router_packet, count=5, verbose=0)
    log("[+] Successfully restored ARP table!")

# Process sniffed packets
def process(packet: Packet) -> None:
    global arp_table
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        try:
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            if ip in arp_table and arp_table[ip] != mac:
                log(f"[!] ARP spoofing detected for {ip}")
                log(f"REAL MAC: {arp_table[ip]}  FAKE MAC: {mac}")
                log("Restoring ARP Table...")
                restore_arp(ip, arp_table[ip])
        except IndexError:
            pass

# Sniffing thread
def sniff_thread():
    global stop_sniffing
    sniff(
        filter="arp and arp[6:2] == 2",
        store=False,
        prn=process,
        stop_filter=lambda pkt: stop_sniffing
    )

# Start detection
def start_detection(e):
    global arp_table, router_mac, sniffing
    if sniffing:
        log("Detection already running.")
        return
    sniffing = True
    log("Initializing ARP table...")
    arp_table = fill_arp_table()
    try:
        router_mac = get_mac(router_ip)
    except Exception as ex:
        log(f"Failed to resolve router MAC: {ex}")
        return
    log("Starting ARP monitoring")
    threading.Thread(target=sniff_thread, daemon=True).start()

# Handle window close
def on_close(e):
    global stop_sniffing
    stop_sniffing = True  # stop sniffing thread
    sys.exit()            # exit Python cleanly

# Main GUI
def main(page: ft.Page):
    global log_box
    page.title = "ARP Spoof Detection Tool"
    page.window_width = 600
    page.window_height = 500

    log_box = ft.TextField(multiline=True, expand=True, read_only=True)

    start_btn = ft.Button("Start Detection", on_click=start_detection)

    page.add(
        ft.Column([
            ft.Text("ARP Spoof Detection Tool", size=25),
            start_btn,
            log_box
        ])
    )

    page.on_close = on_close  # stop sniffing and exit on close

# Run Flet app
ft.run(main)