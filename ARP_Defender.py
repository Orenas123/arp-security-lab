"""
Project: ARP Spoofing Tool
Component: Defense
Description:
    Detects ARP spoofing attacks by monitoring network traffic.
    Maintains a baseline ARP table and automatically restores correct
    mappings if a mismatch is detected.
"""

# ========================
# Imports
# ========================
import flet as ft
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
import threading
import time
from queue import Queue

# ========================
# Global State
# ========================
arp_table: dict[str, str] = {}
log_queue = Queue()
action_queue = Queue()
last_alert_time = {}
ALERT_COOLDOWN = 2 # seconds
mac_to_ips = {}
router_ip: str = conf.route.route("0.0.0.0")[2]
router_mac = None
sniffing: bool = False
stop_sniffing: bool = False

# UI References
log_box = None
status_text = None
start_btn = None
stop_btn = None


# ========================
# Networking Utilities
# ========================
def log(text: str):
    if log_box and log_box.page:
        log_box.value += f"{text}\n"
        # We use the page reference directly from the control
        log_box.page.update()
    print(text) # Keep this so you can see it in the terminal too


def get_mac(target_ip: str) -> str:
    """Sends an ARP request to retrieve the MAC address of a specific IP."""
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip, op=1)
    ans, _ = srp(packet, timeout=2, inter=0.1, verbose=0)

    if not ans:
        raise ValueError(f"No answers received for {target_ip}")

    return ans[0][1].hwsrc

def arp_restore_worker():
    while True:
        victim_ip, victim_mac = action_queue.get()
        try:
            restore_arp(victim_ip, victim_mac)
        except Exception as e:
            log(f"[ERROR] Restore failed: {e}")

def fill_arp_table() -> dict[str, str]:
    """Scans the local network to build a baseline of IP-to-MAC mappings."""
    this_ip = conf.route.route("0.0.0.0")[1]
    network = this_ip.rsplit(".", 1)[0] + ".0/24"
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network, op=1)

    answered, _ = srp(packet, timeout=1, verbose=0)
    temp_arp_table: dict[str, str] = {}

    for _, received in answered:
        temp_arp_table[received.psrc] = received.hwsrc

    return temp_arp_table


def restore_arp(victim_ip: str, victim_mac: str):
    """Sends legitimate ARP replies to 're-teach' the network the correct MACs."""
    victim_packet = Ether(dst=victim_mac) / ARP(
        op=2, psrc=router_ip, hwsrc=router_mac, pdst=victim_ip, hwdst=victim_mac
    )
    router_packet = Ether(dst=router_mac) / ARP(
        op=2, psrc=victim_ip, hwsrc=victim_mac, pdst=router_ip, hwdst=router_mac
    )

    sendp(victim_packet, count=5, verbose=0)
    sendp(router_packet, count=5, verbose=0)
    log("[SYSTEM] ARP table restored.")


# ========================
# Packet Processing
# ========================
def process(packet: Packet):
    """Analyzes incoming ARP packets for inconsistencies against the baseline."""

    if packet.haslayer(ARP) and packet[ARP].op == 2:
        print(packet.summary())
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        if mac not in mac_to_ips:
            mac_to_ips[mac] = []

        if ip not in mac_to_ips[mac]:
            mac_to_ips[mac].append(ip)

            if len(mac_to_ips[mac]) > 1:
                log(f"[ALERT] MAC {mac} now claims multiple IPs!")

        now = time.time()

        if ip in arp_table and arp_table[ip] != mac:
            if ip not in last_alert_time or now - last_alert_time[ip] > ALERT_COOLDOWN:
                log(f"[ALERT] SPOOF DETECTED: {ip}")
                log(f" -> Expected: {arp_table[ip]} | Received: {mac}")
                action_queue.put((ip, arp_table[ip]))
                last_alert_time[ip] = now

        elif ip not in arp_table:
            log(f"[NEW] {ip} → {mac}")
            arp_table[ip] = mac
            return


def sniff_thread():
    """Background thread with error handling to keep sniffing alive."""
    global stop_sniffing
    while not stop_sniffing:
        try:
            sniff(
                filter="arp", # Simplified filter
                store=False,
                prn=process,
                stop_filter=lambda _: stop_sniffing,
                timeout=2 # Check stop_sniffing every 2 seconds
            )
        except Exception as e:
            log(f"[SYS ERROR] Sniffer socket reset: {e}")
            time.sleep(1) # Wait before restarting


# ========================
# UI Handlers
# ========================
def start_detection(e):
    """Initializes the baseline and starts the sniffing thread."""
    global arp_table, router_mac, sniffing, stop_sniffing
    if sniffing: return

    sniffing = True
    stop_sniffing = False

    # UI State Update
    start_btn.disabled = True
    stop_btn.disabled = False
    status_text.value = "STATUS: ACTIVE"
    status_text.color = ft.Colors.GREEN_ACCENT
    log("[*] Initializing baseline...")

    try:
        arp_table = fill_arp_table()

        threading.Thread(target=arp_restore_worker, daemon=True).start()

        mac_to_ips.clear()
        for ip, mac in arp_table.items():
            mac_to_ips.setdefault(mac, []).append(ip)

        router_mac = get_mac(router_ip)
        log(f"[*] Monitoring network: {router_ip}")
        threading.Thread(target=sniff_thread, daemon=True).start()
    except Exception as ex:
        log(f"[ERROR] {ex}")
        stop_detection(None)

    e.page.update()


def stop_detection(e):
    """Signals the sniffing thread to stop and resets UI buttons."""
    global sniffing, stop_sniffing
    sniffing = False
    stop_sniffing = True

    # UI State Update
    start_btn.disabled = False
    stop_btn.disabled = True
    status_text.value = "STATUS: STOPPED"
    status_text.color = ft.Colors.RED_ACCENT
    log("[!] Monitoring stopped.")

    if e: e.page.update()


# ========================
# Main App Layout
# ========================
def main(page: ft.Page):
    global log_box, status_text, start_btn, stop_btn, router_ip

    page.title = "Shield - ARP Guard"
    page.theme_mode = ft.ThemeMode.DARK
    page.window_width = 700
    page.window_height = 600

    # Retrieve router IP for display
    try:
        router_ip = conf.route.route("0.0.0.0")[2]
    except:
        router_ip = "Unknown"

    status_text = ft.Text(f"ROUTER: {router_ip} | STATUS: IDLE", color=ft.Colors.GREY_400)

    log_box = ft.TextField(
        multiline=True,
        expand=True,
        read_only=True,
        text_size=12,
        bgcolor="#1E1E1E",
    )

    # Modern Button Styling
    button_style = lambda color: ft.ButtonStyle(
        color=ft.Colors.WHITE,
        bgcolor={
            ft.ControlState.DISABLED: ft.Colors.GREY_900,
            ft.ControlState.DEFAULT: color,
        },
        overlay_color={
            ft.ControlState.HOVERED: ft.Colors.with_opacity(0.1, ft.Colors.WHITE),
            ft.ControlState.PRESSED: ft.Colors.with_opacity(0.2, ft.Colors.WHITE),
        },
        shape=ft.RoundedRectangleBorder(radius=8),
    )

    start_btn = ft.Button(
        content=ft.Text("Start Shield"),
        icon="security",
        style=button_style(ft.Colors.GREEN_800),
        on_click=start_detection,
    )

    stop_btn = ft.Button(
        content=ft.Text("Stop Shield"),
        icon="stop_circle",
        style=button_style(ft.Colors.RED_800),
        disabled=True,
        on_click=stop_detection,
    )

    page.add(
        ft.Column([
            ft.Text("ARP DEFENSE SYSTEM", size=24, weight="bold"),
            ft.Row([start_btn, stop_btn], alignment="center"),
            status_text,
            ft.Divider(),
            ft.Text("Live Logs:"),
            log_box
        ], expand=True)
    )

    """def process_log_queue():
        updated = False

        while not log_queue.empty():
            text = log_queue.get()
            log_box.value += f"{text}\n"
            updated = True

        if updated:
            page.update()

    def start_log_updater():
        def loop():
            while True:
                time.sleep(0.2)  # adjust for responsiveness vs CPU
                process_log_queue()

        threading.Thread(target=loop, daemon=True).start()

    start_log_updater()"""

    page.update()


# ========================
# Entry Point
# ========================
if __name__ == "__main__":
    ft.run(main)