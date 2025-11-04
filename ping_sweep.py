#!/usr/bin/env python3

# Author: Felipe Pavanelli
# Date: 11/02/2025
# Class: CS60 - Computer Networks
# ping_sweep.py - Sends ICMP ping request to each address in a subnet mask and prints out all hosts that reply to pings

import ipaddress
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed


#===================PING ONE=========================#
# uses subprocess to run ping command once per given host
def ping_one(host: str, timeout_sec: int = 1) -> bool:
    try:
        # -c 1: one echo request, -W timeout in seconds
        r = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout_sec), host],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return r.returncode == 0
    except FileNotFoundError:
        print("Error: 'ping' command not found in this environment.", file=sys.stderr)
        sys.exit(2)

def next_power_of_two(n: int) -> int:
    if n <= 1:
        return 1
    return 1 << ((n - 1).bit_length())


#===================SUGGEST TIGHTER CIDR=========================#
#LLM usage: used ChatGPT generally throughout to understand and code subnet mask converstions from dotted to CIDR notation, as well as the math behind suggesting a minimal value to still scan all hosts
def suggest_tighter_cidr(base_net: ipaddress.IPv4Network, live_hosts):
    # If no live hosts, no meaningful tighter suggestion
    if not live_hosts:
        return None

    highest = max(ipaddress.ip_address(ip) for ip in live_hosts)
    if highest not in base_net:
        return None

    # Calculate how big a block (anchored at base_net.network_address) we need
    # to include up to 'highest' as a usable host.
    host_index = int(highest) - int(base_net.network_address)  # offset from base network address
    need = host_index + 2  # include network + broadcast in that smaller block
    if need < 4:
        need = 4  # minimum /30 to have usable hosts with traditional semantics

    # Smallest power-of-two block size that satisfies the need
    S = next_power_of_two(need)

    # Size of the base network in addresses
    base_size = base_net.num_addresses

    # Constrain to not exceed the base network
    if S > base_size:
        S = base_size

    # Compute suggested prefix: S = 2^(32 - p) => p = 32 - log2(S)
    p = 32 - (S.bit_length() - 1)

    # Ensure we never make it broader than the base (i.e., prefix must be >= base prefix)
    if p < base_net.prefixlen:
        p = base_net.prefixlen

    suggested = ipaddress.ip_network((base_net.network_address, p), strict=True)
    if suggested.prefixlen <= base_net.prefixlen:
        # No tighter network than the base
        return None

    return suggested

#===================MAIN=========================#
# Takes in subnet mask in CIDR notation. ex: 192.168.60.0/24 
# Prints out reachable host in network and suggest mininmal mask if it exists for faster lookup in the future
# LLM usage: used ChatGPT to code and debug 64 threads of parallel ping messages, as opposed to sequential pinging.
def main():
    if len(sys.argv) != 2:
        print("Usage: python3 ping_sweep.py <network_cidr>")
        print("Example: python3 ping_sweep.py 192.168.60.0/24")
        sys.exit(1)

    try:
        base_net = ipaddress.ip_network(sys.argv[1], strict=False)
        if base_net.version != 4:
            raise ValueError("Only IPv4 is supported.")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

    hosts = [str(h) for h in base_net.hosts()]
    live = []

    # parallel sweep. Coded by ChatGPT
    workers = 64
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(ping_one, h): h for h in hosts}
        for f in as_completed(futs):
            h = futs[f]
            try:
                ok = f.result()
            except Exception:
                ok = False
            if ok:
                live.append(h)

    live.sort(key=lambda s: tuple(int(x) for x in s.split(".")))
    for ip in live:
        print(ip)

    # Suggest a tighter CIDR (anchored at the same network address) if it reduces pings
    suggested = suggest_tighter_cidr(base_net, live)
    if suggested:
        orig_hosts = len(list(base_net.hosts()))
        sugg_hosts = len(list(suggested.hosts()))
        print(f"# Suggested minimal CIDR: {suggested.with_prefixlen} (mask {suggested.netmask}) "
              f"– scans {sugg_hosts} hosts vs {orig_hosts}")
    else:
        print(f"# No tighter mask than {base_net.with_prefixlen} improves the scan for the discovered hosts.")

if __name__ == "__main__":
    main()