"""
track_down_host.py        Ahmed Al Sunbati        Nov 3rd, 2025
Description: Captures packets from the access point; uses information from the RadioTap layer to locate the physical
             location of the AP. Uses similar logic from search and rescue of lab 4.
Usage: sudo python3 ./track_down_host.py <interface> <channel>
"""
import curses
import threading
from collections import deque
from scapy.all import *
import time

INTERFACE = None
CHANNEL = None
HOST_BSSID = "98:48:27:c2:a7:9a"
OUR_MAC = None
monitor_mode_script_path = "./set_monitor_mode.sh"

# Information for curses UI
HISTORY_LEN = 10
UI_REFRESH = 0.5 
TREND_THRESHOLD_DB_PER_S = 0.5
host_info = {
    'samples': deque(maxlen=HISTORY_LEN),
    'last_seen': 0.0,
    'last_rssi': None,
    'avg': None,
}

def add_sample(rssi):
    """
    Description: Given an rssi reading from the user, add it to the queue of sample readings that we have collected so far.
                 Calculate average of rssi readings, and reset the last_rssi reading.
    """
    global host_info
    t = time.time()
    host_info['last_seen'] = t
    if rssi is not None:
        host_info['samples'].append((t, float(rssi)))
        host_info['last_rssi'] = float(rssi)
        vals = [v for (_, v) in host_info['samples']]
        host_info['avg'] = sum(vals)/len(vals) if vals else None

def packet_handler(pkt):
    """
    Description: Capture packets coming from the host record the rssi signal.
    """
    global HOST_BSSID
    if not pkt.haslayer(Dot11):
        return
    if pkt[Dot11].addr2 != HOST_BSSID:
        return
    rssi = pkt.getlayer(RadioTap).dBm_AntSignal
    add_sample(rssi)

def sniff_thread_func():
    """
    Description: Sniffing thread execution function to detect packets coming from the AP.
    """
    global INTERFACE
    sniff(iface=INTERFACE, prn=packet_handler)

def compute_slope(samples):
    """
    Description: Uses regression to calculate whether we are seeing an increase or decrease of rssi in our sample
                 readings. Helpful to decie whether we are getting closer or further from the AP.
    """
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

def draw_ui(stdscr):
    """
    Description: Uses ncurses to display a graphical interface to help us locate the physical location of the AP.
    """
    def compute_slope(samples):
        """
        Description: Uses regression to calculate whether we are seeing an increase or decrease of rssi in our sample
                    readings. Helpful to decie whether we are getting closer or further from the AP.
        """
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
    global host_info, HOST_BSSID, INTERFACE, UI_REFRESH, TREND_THRESHOLD_DB_PER_S
    curses.use_default_colors()
    stdscr.nodelay(True)
    stdscr.clear()
    last_refresh = 0

    while True:
        now = time.time()
        if now - last_refresh > UI_REFRESH:
            stdscr.erase()
            stdscr.addstr(0, 0, f"CS60 Host Monitor - iface: {INTERFACE}")
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
            stdscr.addstr(2, 0, f"MAC: {HOST_BSSID}")
            stdscr.addstr(3, 0, f"Last RSSI: {last_str}, Avg: {avg_str}, Trend: {trend}, Age(s): {age}")
            stdscr.addstr(5, 0, "Press Ctrl-C to quit.")
            stdscr.refresh()
            last_refresh = now
        time.sleep(0.05)
        
def track_main():
    global INTERFACE, CHANNEL, OUR_MAC
    def parse_args():
        global INTERFACE, CHANNEL, OUR_MAC
        if len(sys.argv) != 3:
            print("Error: Usage sudo python3 ./track_down_host.py <interface> <channel>")
        INTERFACE = sys.argv[1]
        CHANNEL = sys.argv[2]
        OUR_MAC = get_if_hwaddr(INTERFACE)
    parse_args()
    
    print(f"- Putting the wifi dongle into monitor mode and listening on channel {CHANNEL}")
    subprocess.run([monitor_mode_script_path, INTERFACE, str(CHANNEL)],
                    check=True, capture_output=True, text=True)
    
    # Launch sniff thread
    t = threading.Thread(target=sniff_thread_func, daemon=True)
    t.start()
    # Launch curses UI
    curses.wrapper(draw_ui)

if __name__ == "__main__":
    track_main()