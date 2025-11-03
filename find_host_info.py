"""
find_host_info.py         Ahmed Al Sunbati         Nov 3rd, 2025
Description: Given the name of the dongle interface, this script scans all of the 11 channels in the 2.4GHz
             band to find the beacon frames transmitted by the AP. It targets frames with SSID == CS60, extracts
             sourcse BSSID, the channel it is transmitting on, and the clue in its vendor-specific element.
usage: sudo python3 ./find_host_info <interface>
"""
import time
from scapy.all import *
import sys

INTERFACE = None
HOST_CHANNEL = None
HOST_BSSID = None
OUR_MAC = None

monitor_mode_script_path = "./set_monitor_mode.sh"
found_host = False
clue = None

def find_clue(pkt):
    """
    Description: Given a Wifi beacon packet from the AP, extract the clue from the info field of the vendor-specific
                information element (ID == 221). Returns the clue if found. None otherwise.
    """
    global clue
    if pkt.haslayer(Dot11Elt):
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 221:
                clue = elt.info.decode()
                return clue
            elt = elt.payload.getlayer(Dot11Elt)
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
            if elt.ID == 0 and elt.info.decode(errors='ignore') == "CS60": # Only filter packet with SSID element and with ssid = CS60
                HOST_MAC = pkt[Dot11].addr2 # Save HOST mac address
                found_host = True
                print(f"- Found CS60 beacon from {HOST_MAC}")
                clue = find_clue(pkt)
                if clue: print(f"- Found clue in the packet")
                else: print("- Couldn't find the clue!")   
                return True
            elt = elt.payload.getlayer(Dot11Elt)
    return False

def discover_host(change_location_timeout=1, per_channel_timeout=4, inter_channel_delay=0.3):
    """
    Description: Sniffs on each channel of the interface for a few seconds. The packet handler filters for incoming packets
                with SSID information element. If the ssid matches "CS60", it saves the mac address the packet was sent from
                and declares that the host has been found. The packet handler (still in the same packet) recursivelyy looks for an
                vendor-specific element, and extracts the clue from its info field.
    """
    global target_channel, found_host, HOST_MAC, INTERFACE, clue
    print("- Starting channel scan for SSID 'CS60'...")
    try:
        while not found_host:
            for channel in range(1, 12):
                if found_host: # If we already found the host break
                    break
                
                subprocess.run([monitor_mode_script_path, INTERFACE, str(channel)],
                            check=True, capture_output=True, text=True) # Switch channels
                print(f"- Listening on channel {channel}...")
                
                sniff(iface=INTERFACE,
                    timeout=per_channel_timeout,
                    store=0,
                    stop_filter=packet_handler_detect_host) # Start sniffing until we find the host or until we timeout
                
                if found_host:
                    target_channel = channel # Save the channel we found the host on
                    return target_channel, HOST_MAC, clue
                time.sleep(inter_channel_delay)
            print(f"- Sweep done. Wait {change_location_timeout}s before next sweep.")
            time.sleep(change_location_timeout)
    except KeyboardInterrupt:
        print("Interrupted by user")
        return None, None


def discover_main():
    global INTERFACE, our_mac, HOST_CHANNEL, HOST_BSSID, clue
    if len(sys.argv) != 2:
        print("Error: usage is sudo python3 ./find_host_info.py <interface>")
        sys.exit(1)
    INTERFACE = sys.argv[1]
    our_mac = get_if_hwaddr(INTERFACE)
    HOST_CHANNEL, HOST_BSSID, clue = discover_host()
    print(f"- Found host on channel {HOST_CHANNEL}, with BSSID {HOST_BSSID}. Clue found in packet: {clue}")
    return HOST_CHANNEL, HOST_BSSID, clue

if __name__ == "__main__":
    discover_main()
    
    
