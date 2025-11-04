"""
find_flag.py          Ahmed Al Sunbati        Nov 3, 2025
Description: This script is used to find the flag from the AP. It sets the dongle to be on monitor mode on
             a specific channel, then sends a burst of packets with the encoded dartmouth ID and listens for replies.
             if captured a reply, it prints the flag.
usage: sudo python3 ./find_flag.py <interface> <channel> <dartmouth-id>
Citations: GeminiAI for refactoring code.
"""

import sys
import time
from scapy.all import *

INTERFACE = None
CHANNEL = None
DARTMOUTH_ID = None

target_bssid = "98:48:27:c2:a7:9a"
our_mac = None
monitor_mode_script_path = "./set_monitor_mode.sh"

received_flag = None

def parse_args():
    """
    Description: Parse arguments form command line
    """
    global INTERFACE, CHANNEL, DARTMOUTH_ID, our_mac
    if len(sys.argv) != 4:
        print("Error: Usage is sudo python3 ./find_flag.py <interface> <channel> <dartmouth-id>")
        sys.exit(1)
    INTERFACE = sys.argv[1]
    CHANNEL = sys.argv[2]
    DARTMOUTH_ID = sys.argv[3]
    our_mac = get_if_hwaddr(INTERFACE)


def find_flag(pkt):
    """
    Description: Packet handler for sniffing. Looks for the reply frame with our flag. Filters for management frames
                 carrying a Raw layer, coming from the target bssid.
    """
    global received_flag
    if (pkt.haslayer(Dot11) and
        pkt.type == 2 and
        pkt.addr2 == target_bssid and
        pkt.haslayer(Raw)):
        try:
            payload = pkt[Raw].load
            if payload != DARTMOUTH_ID.encode(): # Ignore it if it's not my ID
                flag = payload.decode()
                print(f"FLAG RECEIVED: {flag}\n")
                received_flag = flag
                return True
        except UnicodeDecodeError:
            print(f"Received unreadable payload from {pkt.addr2}")
    return False

def find_flag_main():
    global our_mac, target_bssid, received_flag, CHANNEL, DARTMOUTH_ID, INTERFACE
    parse_args()
    print(f"- Putting the wifi dongle into monitor mode and listening on channel {CHANNEL}")
    subprocess.run([monitor_mode_script_path, INTERFACE, str(CHANNEL)],
                    check=True, capture_output=True, text=True)
    
    print(f"- Using interface: {INTERFACE} (MAC: {our_mac})")
    print(f"- Payload to send: {DARTMOUTH_ID}")


    print("- Crafting and Sending Frame\n")
    
    packet = (
        RadioTap() /
        Dot11(type=2, addr1=target_bssid, addr2=our_mac, addr3=target_bssid) /
        LLC() /
        SNAP() /
        Raw(load=DARTMOUTH_ID.encode())
    )
    
    print("- Packet to send:")
    packet.show()

    # Sending burst of layer 2 packets
    print("Sending packet burst...")
    sendp(packet, iface=INTERFACE, count=20, inter=0.2, verbose=0)
    
    # Listening for replies back
    print("Packets sent. Listening for reply...")
    sniff(iface=INTERFACE, prn=find_flag, stop_filter=find_flag, timeout=20)
    
    print("Done")
    if received_flag:
        print(f"- Success! The flag is: {received_flag}")
    else:
        print("- Did not receive a flag!")
        print("- Try running the script again. Frames are sometimes dropped.")

if __name__ == "__main__":
    find_flag_main()
