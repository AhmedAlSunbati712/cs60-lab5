# CS60, Lab 5
- Felipe Pavanelli
- Ahmed Al Sunbati
## Lab1
1. First find the AP mac address, the channel its listening on, and the clue included in its vendor-specific element. To achieve this, run the `find_host_info.py` script with the following command: `sudo python3 ./find_host_info.py wlan0` or whatever the name of the your dongle interface is
2. Locate the physical location of the AP: The script `locate_host.py` helps figure out the direction you need to head in to find the AP (direction of increasing rssi reading). To run this script, run this command `sudo python3 ./track_down_host.py wlan0 <host-channel>`. Replace host-channel with whatever channel the host is sending packets on.
3. To get the code (the flag), we need to send a layer 2 frame with our ID to the AP. `find_flag.py` does that. To run this script, use the following command `sudo python3 ./find_flag.py wlan0 3 <dartmouth-id>`. 3 is the channel found in the clue from part 2. Replace with the appropirate interface and dartmouth id.