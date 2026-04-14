from scapy.all import sniff, IP, UDP, TCP, BOOTP, DHCP, Ether, DNS
import time
import threading
import curses
import csv
import socket
import ipaddress
import requests
import json
import subprocess
import os

traffic_stats = {}
os_fingerprints = {}
protocol_flags = {}
seen_devices = {}
hostnames = {}
locations = {}
connected_hosts = {}
dest_hostnames = {}
scroll_offsets = {}
new_hosts_flag = {}
public_location = ""
allowlist = []
selected_index = 0
vendors = {}

def load_allowlist():
    global allowlist
    try:
        with open("allowlist.json") as f:
            allowlist = json.load(f)
    except:
        allowlist = []

def save_allowlist():
    with open("allowlist.json","w") as f:
        json.dump(allowlist,f,indent=2)

def load_vendor_cache():
    global vendors
    try:
        with open("vendor_cache.json") as f:
            vendors = json.load(f)
    except:
        vendors = {}

def save_vendor_cache():
    with open("vendor_cache.json","w") as f:
        json.dump(vendors,f)

def is_allowed(ip):
    return any(d["ip"] == ip for d in allowlist)

def shutdown_device(ip):
    device = next((d for d in allowlist if d["ip"] == ip), None)
    if not device:
        return
    if device["os"] == "linux":
        subprocess.Popen(["ssh", f"{device['user']}@{ip}", "sudo shutdown now"])
    elif device["os"] == "windows":
        subprocess.Popen(["shutdown", "/m", f"\\\\{ip}", "/s", "/t", "0"])

def add_visible_to_allowlist(keys):
    global allowlist
    for key in keys:
        ip, mac = key.split("-",1)
        if not any(d["ip"] == ip for d in allowlist):
            os_guess = os_fingerprints.get(mac,"linux")
            user = "pi" if os_guess == "linux" else "admin"
            allowlist.append({"ip": ip, "user": user, "os": os_guess if os_guess in ["linux","windows"] else "linux"})
    save_allowlist()

def get_public_location():
    global public_location
    try:
        r = requests.get("http://ip-api.com/json/", timeout=3).json()
        public_location = f"{r.get('city','')},{r.get('country','')}"
    except:
        public_location = ""

def guess_vendor_from_prefix(mac):
    prefix = mac.upper()[0:8]
    if prefix.startswith("DA:A1:19") or prefix.startswith("F2:"):
        return "Apple (Randomized)"
    if prefix.startswith("02:"):
        return "Randomized MAC"
    if prefix.startswith("00:1A:79") or prefix.startswith("3C:5A:B4"):
        return "Google"
    if prefix.startswith("B8:27:EB"):
        return "Raspberry Pi"
    return ""

def resolve_vendor(mac):
    if mac in vendors:
        return vendors[mac]
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        if r.status_code == 200 and r.text:
            vendors[mac] = r.text
        else:
            vendors[mac] = guess_vendor_from_prefix(mac)
    except:
        vendors[mac] = guess_vendor_from_prefix(mac)
    save_vendor_cache()
    return vendors[mac]

def classify_device(os_guess, traffic):
    if "android" in os_guess or "iphone" in os_guess:
        return "phone"
    if traffic.get("udp", 0) > traffic.get("tcp", 0) * 3:
        return "iot"
    if traffic.get("tcp", 0) > 300:
        return "laptop"
    return "unknown"

def resolve_hostname(ip):
    if ip in hostnames:
        return hostnames[ip]
    try:
        name = socket.gethostbyaddr(ip)[0]
    except:
        name = ""
    hostnames[ip] = name
    return name

def resolve_dest_hostname(ip):
    if ip in dest_hostnames:
        return dest_hostnames[ip]
    try:
        name = socket.gethostbyaddr(ip)[0]
    except:
        name = ""
    dest_hostnames[ip] = name
    return name

def resolve_location(ip):
    if ip in locations:
        return locations[ip]
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private:
            loc = "LAN"
        elif addr.is_loopback:
            loc = "LOOPBACK"
        elif addr.is_multicast:
            loc = "MULTICAST"
        else:
            loc = public_location or "PUBLIC"
    except:
        loc = ""
    locations[ip] = loc
    return loc

def dhcp_fingerprint(pkt):
    if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
        mac = pkt[BOOTP].chaddr[:6].hex(":")
        opts = pkt[DHCP].options
        param_req = None
        for o in opts:
            if o[0] == "param_req_list":
                param_req = tuple(o[1])
        os_guess = "unknown"
        if param_req:
            if param_req == (1,3,6,15,26,28,51,58,59):
                os_guess = "windows"
            elif param_req == (1,3,6,15,119,252):
                os_guess = "linux"
            elif 43 in param_req and 44 in param_req:
                os_guess = "android"
        os_fingerprints[mac] = os_guess
        ip = pkt[BOOTP].yiaddr
        if ip:
            seen_devices[f"{ip}-{mac}"] = {}

def ensure_device(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(Ether):
        ip = pkt[IP].src
        mac = pkt[Ether].src
        key = f"{ip}-{mac}"
        if key not in seen_devices:
            seen_devices[key] = {}
        if ip not in connected_hosts:
            connected_hosts[ip] = set()
        if ip not in scroll_offsets:
            scroll_offsets[ip] = 0
        if ip not in new_hosts_flag:
            new_hosts_flag[ip] = {}

def traffic_counter(pkt):
    if pkt.haslayer(IP):
        ip = pkt[IP].src
        if ip not in traffic_stats:
            traffic_stats[ip] = {"tcp":0,"udp":0,"bytes":0}
        if pkt.haslayer(TCP):
            traffic_stats[ip]["tcp"] += 1
        if pkt.haslayer(UDP):
            traffic_stats[ip]["udp"] += 1
        traffic_stats[ip]["bytes"] += len(pkt)
        dst_ip = pkt[IP].dst
        if ip in connected_hosts:
            hostname = resolve_dest_hostname(dst_ip)
            if hostname:
                if hostname not in connected_hosts[ip]:
                    new_hosts_flag[ip][hostname] = time.time()
                connected_hosts[ip].add(hostname)

def protocol_detection(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(UDP):
        ip = pkt[IP].src
        dport = pkt[UDP].dport
        if ip not in protocol_flags:
            protocol_flags[ip] = set()
        if dport == 443:
            protocol_flags[ip].add("QUIC")
        if dport in (853,443) and pkt.haslayer(DNS):
            protocol_flags[ip].add("DoH")

def packet_processor(pkt):
    try:
        ensure_device(pkt)
        dhcp_fingerprint(pkt)
        traffic_counter(pkt)
        protocol_detection(pkt)
    except:
        pass

def enrich_devices():
    while True:
        for key in list(seen_devices.keys()):
            ip, mac = key.split("-",1)
            traffic = traffic_stats.get(ip,{"tcp":0,"udp":0,"bytes":0})
            os_guess = os_fingerprints.get(mac,"unknown")
            device = classify_device(os_guess, traffic)
            proto = ",".join(protocol_flags.get(ip,[]))
            hostname = resolve_hostname(ip)
            location = resolve_location(ip)
            hosts = ",".join(list(connected_hosts.get(ip,set())))
            vendor = resolve_vendor(mac)
            seen_devices[key] = {
                "hostname": hostname,
                "vendor": vendor,
                "location": location,
                "device": device,
                "os": os_guess,
                "protocols": proto,
                "connected_hosts": hosts
            }
        time.sleep(2)

def confirm(stdscr, text):
    max_y, max_x = stdscr.getmaxyx()
    stdscr.addstr(max_y-2, 0, text.ljust(max_x-1), curses.A_REVERSE)
    stdscr.refresh()
    while True:
        k = stdscr.getch()
        if k in (ord("y"), ord("Y")):
            return True
        if k in (ord("n"), ord("N")):
            return False

def dashboard(stdscr):
    global selected_index
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_RED, -1)
    curses.init_pair(2, curses.COLOR_GREEN, -1)
    curses.init_pair(3, curses.COLOR_YELLOW, -1)
    curses.init_pair(4, curses.COLOR_CYAN, -1)
    stdscr.nodelay(True)
    scrolling_paused = False
    col_widths = [15, 20, 20, 15, 20, 12, 10, 6, 6, 10, 12]

    while True:
        stdscr.erase()
        max_y, max_x = stdscr.getmaxyx()

        stdscr.addstr(0, 0, f"Location: {public_location}".ljust(max_x-1), curses.color_pair(4) | curses.A_BOLD)

        headers = ["IP","Hostname","Vendor","Location","MAC","Auth","OS","TCP","UDP","Bytes","Protocols"]
        header_line = "|".join([h.ljust(w) for h, w in zip(headers, col_widths)])
        stdscr.addstr(2, 0, "|" + header_line[:max_x-2] + "|", curses.color_pair(1) | curses.A_BOLD)

        keys = list(seen_devices.keys())
        row = 3

        for i, key in enumerate(keys):
            if row >= max_y - 2:
                break

            ip, mac = key.split("-", 1)
            info = seen_devices[key]
            t = traffic_stats.get(ip, {"tcp":0,"udp":0,"bytes":0})

            auth = "AUTHORIZED" if is_allowed(ip) else "BLOCKED"

            if i == selected_index:
                line_color = curses.color_pair(4) | curses.A_REVERSE | curses.A_BOLD
            else:
                line_color = curses.color_pair(2)

            values = [
                ip.ljust(col_widths[0]),
                info.get("hostname","").ljust(col_widths[1]),
                info.get("vendor","").ljust(col_widths[2]),
                info.get("location","").ljust(col_widths[3]),
                mac.ljust(col_widths[4]),
                auth.ljust(col_widths[5]),
                info.get("os","").ljust(col_widths[6]),
                str(t["tcp"]).ljust(col_widths[7]),
                str(t["udp"]).ljust(col_widths[8]),
                str(t["bytes"]).ljust(col_widths[9]),
                info.get("protocols","").ljust(col_widths[10])
            ]

            line = "|" + "|".join(values)[:max_x-2] + "|"
            stdscr.addstr(row, 0, line, line_color)
            row += 1

        stdscr.refresh()

        try:
            k = stdscr.getch()
            if k == ord("q"):
                break
            elif k in (10, 13):
                if 0 <= selected_index < len(keys):
                    ip = keys[selected_index].split("-")[0]
                    if is_allowed(ip):
                        if confirm(stdscr, f"Shutdown {ip}? (y/n)"):
                            shutdown_device(ip)
            elif k == ord("a") or k == ord("A"):
                add_visible_to_allowlist(keys)
            elif k == curses.KEY_UP:
                selected_index = max(0, selected_index - 1)
            elif k == curses.KEY_DOWN:
                selected_index = min(len(keys) - 1, selected_index + 1)
            elif k == ord(" "):
                scrolling_paused = not scrolling_paused
        except:
            pass

        time.sleep(1)

load_allowlist()
load_vendor_cache()
threading.Thread(target=get_public_location, daemon=True).start()
threading.Thread(target=enrich_devices, daemon=True).start()
threading.Thread(target=lambda: sniff(prn=packet_processor, store=0), daemon=True).start()
curses.wrapper(dashboard)
