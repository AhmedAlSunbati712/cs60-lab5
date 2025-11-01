import curses
import threading
import time
from collections import deque
from scapy.all import *

HOST_MAC = None
LOCAL_MAC = None
iface = None
target_channel = None
clue = None
found_host = False
monitor_mode_script_path = "./set_monitor_mode.sh"

HISTORY_LEN = 10
UI_REFRESH = 0.5  # seconds
TREND_THRESHOLD_DB_PER_S = 0.5



# ====================== Part 1: Get host channel and MAC ==========================
def find_clue(pkt):
    """
    Description: Given a Wifi beacon packet from the AP, extract the clue from the info field of the vendor-specific
                 information element (ID == 221). Returns the clue if found. None otherwise.
    """
    if pkt.haslayer(Dot11Elt):
        elt = pkt.findlayer(Dot11Elt)
        while elt:
            if elt.ID == 221:
                clue = elt.info.decode()
                return clue
    return None
                
def packet_handler_detect_host(pkt):
    """
    Description: Given an incoming packet at the interface, check if it has a wifi information element.
                 If the information element is an ssid element, extract the ssid from the info field.
                 Check if the extracted ssid is CS60, if so, declare that we found the host, save its
                 mac address and extract the clue from the vendor-specific information element in the 
                 same packet.
    """
    global found_host, HOST_MAC
    if pkt.haslayer(Dot11Elt):
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:
                print(elt.info.decode(errors='ignore'))
            if elt.ID == 0 and elt.info.decode(errors='ignore') == "CS60":
                
                HOST_MAC = pkt[Dot11].addr2
                found_host = True
                print(f"[+] Found CS60 beacon from {HOST_MAC}")
                clue = find_clue(pkt)
                if clue: print(f"[+] Found clue in the packet: {clue}")
                else: prin("[!] Couldn't find the clue!")   
                return True
            elt = elt.payload.getlayer(Dot11Elt)
    return False

def discover_host(change_location_timeout=1, per_channel_timeout=2, inter_channel_delay=0.3):
    """
    Description: Sniffs on each channel of the interface for a few seconds. The packet handler filters for incoming packets
                 with SSID information element. If the ssid matches "CS60", it saves the mac address the packet was sent from
                 and declares that the host has been found. The packet handler (still in the same packet) recursivelyy looks for an
                 vendor-specific element, and extracts the clue from its info field.
    """
    global target_channel, found_host, HOST_MAC, iface, clue
    print("[*] Starting repeated channel scan for SSID 'CS60'...")
    try:
        while not found_host:
            for channel in range(1, 12):
                if found_host:
                    break
                subprocess.run([monitor_mode_script_path, iface, str(channel)],
                               check=True, capture_output=True, text=True)
                print(f"[*] Listening on channel {channel}...")
                sniff(iface=iface,
                      timeout=per_channel_timeout,
                      store=0,
                      stop_filter=packet_handler_detect_host)
                if found_host:
                    target_channel = channel
                    print(f"[+] Host found on channel {channel} with MAC {HOST_MAC}")
                    return target_channel, HOST_MAC, clue
                time.sleep(inter_channel_delay)
            print(f"[-] Sweep done. Wait {change_location_timeout}s before next sweep.")
            time.sleep(change_location_timeout)
    except KeyboardInterrupt:
        print("[!] Interrupted by user")
        return None, None


# =================== Part 2: GUI to track down where the AP is (Reused same gui from search and rescue from lab 4) ===================
host_info = {
    'samples': deque(maxlen=HISTORY_LEN),
    'last_seen': 0.0,
    'last_rssi': None,
    'avg': None,
}

def add_sample(rssi):
    global host_info
    t = time.time()
    host_info['last_seen'] = t
    if rssi is not None:
        host_info['samples'].append((t, float(rssi)))
        host_info['last_rssi'] = float(rssi)
        vals = [v for (_, v) in host_info['samples']]
        host_info['avg'] = sum(vals)/len(vals) if vals else None

def packet_handler(pkt):
    if not pkt.haslayer(Dot11):
        return
    if pkt[Dot11].addr2 != HOST_MAC:
        return
    rssi = pkt.getlayer(RadioTap).dBm_AntSignal
    add_sample(rssi)

def compute_slope(samples):
    if len(samples) < 2:
        return 0.0
    n = len(samples)
    xs = [s[0] for s in samples]
    ys = [s[1] for s in samples]
    x_mean = sum(xs)/n
    y_mean = sum(ys)/n
    num = sum((xs[i]-x_mean)*(ys[i]-y_mean) for i in range(n))
    den = sum((xs[i]-x_mean)**2 for i in range(n))
    return num/den if den != 0 else 0.0

def sniff_thread_func():
    sniff(iface=iface, prn=packet_handler)

def draw_ui(stdscr):
    curses.use_default_colors()
    stdscr.nodelay(True)
    stdscr.clear()
    last_refresh = 0

    while True:
        now = time.time()
        if now - last_refresh > UI_REFRESH:
            stdscr.erase()
            stdscr.addstr(0, 0, f"CS60 Host Monitor - iface: {iface}")
            stdscr.addstr(1, 0, "-"*50)
            last_rssi = host_info['last_rssi']
            avg = host_info['avg']
            slope = compute_slope(list(host_info['samples']))
            age = int(now - host_info['last_seen'])
            last_str = f"{last_rssi:.1f}" if last_rssi else "N/A"
            avg_str = f"{avg:.1f}" if avg else "N/A"
            trend = "→"
            if slope > TREND_THRESHOLD_DB_PER_S:
                trend = "▲"
            elif slope < -TREND_THRESHOLD_DB_PER_S:
                trend = "▼"
            stdscr.addstr(2, 0, f"MAC: {HOST_MAC}")
            stdscr.addstr(3, 0, f"Last RSSI: {last_str}, Avg: {avg_str}, Trend: {trend}, Age(s): {age}")
            stdscr.addstr(5, 0, "Press Ctrl-C to quit.")
            stdscr.refresh()
            last_refresh = now
        time.sleep(0.05)

# ==================== Part 3: Send layer two packet with id to the AP and get the flag =====================
def send_layer_two(payload):
    frame = RadioTap() / \
        Dot11(type=2, subtype=0, addr1=HOST_MAC, addr2=LOCAL_MAC, addr3=HOST_MAC) / \
            Raw(payload)
    sendp(frame, iface=iface, count=10, inter=0.1)

def get_flag(pkt):
    if not pkt.haslayer(Dot11) or pkt[Dot11].addr2 != HOST_MAC or pkt[Dot11].addr1 != LOCAL_HOST or not pkt.haslayer(Raw):
        return False
    flag = pkt[Raw].load.decode()
    print(f"[+] Flag received: {flag}")
    return True
    

def main():
    global iface
    iface = sys.argv[1]
    discover_host()
    # Launch sniff thread
    t = threading.Thread(target=sniff_thread_func, daemon=True)
    t.start()
    # Launch curses UI
    curses.wrapper(draw_ui)
    # Send id
    payload = b'f006w08'
    send_layer_two(payload)
    sniff(iface=iface, stop_filter=get_flag)

if __name__ == "__main__":
    main()
