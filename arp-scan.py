#!/usr/bin/env python3
import argparse
import json
import os
import time
import threading
import sys
from pathlib import Path
from scapy.all import ARP, Ether, srp, sr1, IP, ICMP, conf

try:
    import requests
except ImportError:
    requests = None

banner = r"""
+--------------------------------------------------+
|   .               .                              |
| .´  ·  .     .  ·  `.     Proof of Mood Scanner  |
| :  :  :  (¯)  :  :  :        v1.0                |
| `.  ·  ` /¯\ ´  ·  .´                            |
|   `     /¯¯¯\     ´                              |
+--------------------------------------------------+
"""

VENDOR_CACHE_PATH = Path.home() / ".cache" / "arp_scanner_vendors.json"
VENDOR_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
_vendor_cache = {}


def _load_cache():
    global _vendor_cache
    try:
        if VENDOR_CACHE_PATH.exists():
            with open(VENDOR_CACHE_PATH, "r") as f:
                _vendor_cache = json.load(f)
        else:
            _vendor_cache = {}
    except Exception:
        _vendor_cache = {}


def _save_cache():
    try:
        with open(VENDOR_CACHE_PATH, "w") as f:
            json.dump(_vendor_cache, f)
    except Exception:
        pass


def normalize_mac(mac: str) -> str:
    if not mac:
        return mac
    hexs = "".join([c for c in mac if c.isalnum()]).upper()
    if len(hexs) != 12:
        return mac.upper()
    return ":".join(hexs[i:i + 2] for i in range(0, 12, 2))


def get_vendor(mac: str) -> str:
    if not mac:
        return "Unknown Vendor"
    mac_norm = normalize_mac(mac)
    oui = mac_norm.upper()[0:8]
    if oui in _vendor_cache:
        return _vendor_cache[oui]

    if requests is None:
        _vendor_cache[oui] = "Unknown Vendor"
        _save_cache()
        return "Unknown Vendor"

    try:
        resp = requests.get(f"https://api.macvendors.com/{mac_norm}", timeout=5)
        if resp.status_code == 200 and resp.text:
            vendor = resp.text.strip()
        else:
            vendor = "Unknown Vendor"
    except Exception:
        vendor = "Unknown Vendor"

    _vendor_cache[oui] = vendor
    _save_cache()
    return vendor


def loading_animation(stop_event):
    dots = ["   ", " .  ", " .. ", " ..."]
    i = 0
    while not stop_event.is_set():
        sys.stdout.write(f"\r[*] Scanning{dots[i % len(dots)]}")
        sys.stdout.flush()
        time.sleep(0.4)
        i += 1
    sys.stdout.write("\r" + " " * 40 + "\r")
    sys.stdout.flush()


def scan(target, interface, do_vendor=False):
    try:
        print(banner)

        stop_event = threading.Event()
        loader = threading.Thread(target=loading_animation, args=(stop_event,))
        loader.start()

        arp = ARP(pdst=target)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=0, iface=interface)[0]

        clients = []
        for sent, received in result:
            client = {'ip': received.psrc, 'mac': received.hwsrc}
            reply = sr1(IP(dst=received.psrc) / ICMP(), timeout=1, verbose=0)
            if reply:
                try:
                    ttl = int(reply.ttl)
                    os_name = "Linux/Unix" if ttl <= 64 else "Windows"
                except Exception:
                    os_name = "Unknown"
                client['os'] = os_name
            else:
                client['os'] = "Unknown"

            if do_vendor:
                client['vendor'] = get_vendor(received.hwsrc)
            else:
                client['vendor'] = "N/A"

            clients.append(client)

        stop_event.set()
        loader.join()
        print("\r" + " " * 40, end="\r")
        print("[*] Scanning completed.\n")

        time.sleep(0.4)
        if do_vendor:
            print("\tIP" + " " * 15 + "MAC" + " " * 16 + "OS" + " " * 13 + "Vendor")
            print("\t---" + " " * 14 + "---" + " " * 16 + "---" + " " * 12 + "------")
            for c in clients:
                print("\t{:16} {:18} {:12} {}".format(
                    c['ip'], normalize_mac(c['mac']), c.get('os', 'Unknown'), c.get('vendor', 'Unknown')))
        else:
            print("\tIP" + " " * 16 + "MAC" + " " * 15 + "OS")
            print("\t---" + " " * 14 + "---" + " " * 16 + "---")
            for c in clients:
                print("\t{:16} {:18} {}".format(
                    c['ip'], normalize_mac(c['mac']), c.get('os', 'Unknown')))
        print()
    except PermissionError:
        stop_event.set()
        print("\n[!] Run as root (need raw socket privileges).")
    except KeyboardInterrupt:
        stop_event.set()
        print("\n[!] Interrupted by user.")
    except Exception as e:
        stop_event.set()
        print(f"\n[!] Error during scan: {e}")


def main():
    _load_cache()
    parser = argparse.ArgumentParser(description="Python ARP scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP address range (e.g., 192.168.1.0/24)")
    parser.add_argument("-i", "--iface", help="Interface to use (default: wlan0)")
    parser.add_argument("--vendor", action="store_true",
                        help="Lookup MAC vendor via api.macvendors.com (requires 'requests')")
    args = parser.parse_args()

    target = args.target
    interface = args.iface if args.iface else conf.iface
    do_vendor = args.vendor

    if do_vendor and requests is None:
        print("[!] Python 'requests' library not found. Vendor lookup disabled.")
        do_vendor = False

    scan(target, interface, do_vendor=do_vendor)


if __name__ == "__main__":
    main()

