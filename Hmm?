from scapy.all import sniff, IP, UDP, TCP, BOOTP, DHCP, Ether, DNS
import time
import threading
import curses
import csv
import socket
import ipaddress

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
            loc = "PUBLIC"
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
            seen_devices[key] = {
                "hostname": hostname,
                "location": location,
                "device": device,
                "os": os_guess,
                "protocols": proto,
                "connected_hosts": hosts
            }
        time.sleep(2)

def export_csv():
    with open("network_details.csv","w",newline="") as f:
        w = csv.writer(f)
        w.writerow(["IP","Hostname","Location","MAC","Device","OS","TCP","UDP","Bytes","Protocols","Connected Hosts"])
        for key, info in seen_devices.items():
            ip, mac = key.split("-",1)
            t = traffic_stats.get(ip,{"tcp":0,"udp":0,"bytes":0})
            w.writerow([
                ip,
                info.get("hostname",""),
                info.get("location",""),
                mac,
                info.get("device",""),
                info.get("os",""),
                t["tcp"],
                t["udp"],
                t["bytes"],
                info.get("protocols",""),
                info.get("connected_hosts","")
            ])

def reset_data():
    traffic_stats.clear()
    os_fingerprints.clear()
    protocol_flags.clear()
    seen_devices.clear()
    hostnames.clear()
    locations.clear()
    connected_hosts.clear()
    dest_hostnames.clear()
    scroll_offsets.clear()
    new_hosts_flag.clear()

def dashboard(stdscr):
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_RED, -1)
    curses.init_pair(2, curses.COLOR_GREEN, -1)
    curses.init_pair(3, curses.COLOR_YELLOW, -1)
    curses.init_pair(4, curses.COLOR_CYAN, -1)
    stdscr.nodelay(True)
    scrolling_paused = False
    col_widths = [15, 20, 10, 20, 10, 10, 6, 6, 10, 12, 30]

    while True:
        stdscr.erase()
        max_y, max_x = stdscr.getmaxyx()
        if max_y < 5 or max_x < 90:
            stdscr.addstr(0, 0, "Window too small!", curses.color_pair(1))
            stdscr.refresh()
            time.sleep(1)
            continue

        stdscr.addstr(0, 0, "=" * (max_x - 1), curses.color_pair(1) | curses.A_BOLD)
        headers = ["IP","Hostname","Location","MAC","Device","OS","TCP","UDP","Bytes","Protocols","Connected Hosts"]
        header_line = "|".join([h.ljust(w) for h, w in zip(headers, col_widths)])
        stdscr.addstr(1, 0, "|" + header_line[:max_x-2] + "|", curses.color_pair(1) | curses.A_BOLD)
        stdscr.addstr(2, 0, "=" * (max_x - 1), curses.color_pair(1) | curses.A_BOLD)

        row = 3
        now = time.time()
        for key, info in seen_devices.items():
            if row >= max_y - 2:
                break
            ip, mac = key.split("-", 1)
            t = traffic_stats.get(ip, {"tcp":0,"udp":0,"bytes":0})

            hosts = info.get("connected_hosts","")
            scroll = scroll_offsets.get(ip,0)
            if not scrolling_paused:
                display_hosts = hosts[scroll:scroll + col_widths[-1]]
                scroll_offsets[ip] = (scroll + 1) % max(1, len(hosts))
            else:
                display_hosts = hosts[:col_widths[-1]]

            line_color = curses.color_pair(2) | curses.A_BOLD
            for h, ts in new_hosts_flag.get(ip, {}).items():
                if now - ts < 3:
                    line_color = curses.color_pair(3) | curses.A_BOLD
                    break

            values = [
                ip.ljust(col_widths[0]),
                info.get("hostname","").ljust(col_widths[1]),
                info.get("location","").ljust(col_widths[2]),
                mac.ljust(col_widths[3]),
                info.get("device","").ljust(col_widths[4]),
                info.get("os","").ljust(col_widths[5]),
                str(t["tcp"]).ljust(col_widths[6]),
                str(t["udp"]).ljust(col_widths[7]),
                str(t["bytes"]).ljust(col_widths[8]),
                info.get("protocols","").ljust(col_widths[9]),
                display_hosts.ljust(col_widths[10])
            ]
            line = "|" + "|".join(values)[:max_x-2] + "|"
            stdscr.addstr(row, 0, line, line_color)
            row += 1

        stdscr.addstr(max_y-1, 0, "=" * (max_x - 1), curses.color_pair(1) | curses.A_BOLD)
        stdscr.refresh()

        try:
            k = stdscr.getch()
            if k == ord("q"):
                break
            elif k == ord("r"):
                reset_data()
            elif k in (10, 13):
                export_csv()
            elif k == ord(" "):
                scrolling_paused = not scrolling_paused
        except:
            pass

        time.sleep(1)

threading.Thread(target=enrich_devices, daemon=True).start()
threading.Thread(target=lambda: sniff(prn=packet_processor, store=0), daemon=True).start()
curses.wrapper(dashboard)
